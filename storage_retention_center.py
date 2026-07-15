import hashlib
import json
import os
import queue
import re
import secrets
import shutil
import threading
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk

import backup_verification_center as backup_center
import local_data_control_center as data_control
import recovery_drill_center as drill_center
import recovery_kit_builder as kit_builder
import usb_file_locker as locker
import vault_health_center


GUIDE_ENDPOINT = "/api/v1/retention-guide"
RECEIPT_HISTORY_PATH = locker.APP_DIR / "retention_receipts.jsonl"
MAX_TEMP_ENTRIES = 5000
MAX_METADATA_ENTRIES = 5000
MAX_HISTORY_RECORDS = 500
MAX_HISTORY_BYTES = 2 * 1024 * 1024
EXPIRED_SECONDS = locker.TEMP_DELETE_SECONDS
REPORT_SCHEMA_VERSION = 1
HEX_16_RE = re.compile(r"^[0-9a-f]{16}$")
HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,4}$")
SERVICE_MODES = frozenset({"normal", "maintenance", "limited", "degraded", "outage", "unknown"})
RECEIPT_LOCK = threading.RLock()
CLEANUP_LOCK = threading.RLock()

AREA_SPECS = (
    {
        "id": "temporary-unlocked-workspace",
        "label": "Temporary unlocked workspace",
        "purpose": "Hold short-lived working copies created by explicit local unlock-view actions.",
        "retention": "Automatic cleanup is attempted; entries older than ten minutes are eligible for explicit cleanup review.",
        "customer_action": "Close viewers, review the preview, then use typed-confirmation cleanup if needed.",
        "policy": "cleanup-eligible",
    },
    {
        "id": "audit-evidence",
        "label": "Audit evidence",
        "purpose": "Keep bounded privacy-safe action records and their local integrity key.",
        "retention": "Rotated by the audit subsystem to a bounded current file and backup set.",
        "customer_action": "Verify and export from Audit Log Viewer; do not delete from this center.",
        "policy": "preserve",
    },
    {
        "id": "recovery-history",
        "label": "Recovery and backup history",
        "purpose": "Keep fixed-ID Recovery Kit, Drill, and Backup Verification results.",
        "retention": "Bounded exact-schema histories remain until deliberately managed in their source centers.",
        "customer_action": "Verify integrity before replacing or restoring app data.",
        "policy": "preserve",
    },
    {
        "id": "privacy-baselines",
        "label": "Privacy receipts and baselines",
        "purpose": "Keep coarse Data Control, retention, and Vault Health evidence without file inventories.",
        "retention": "Remains local until deliberately replaced or cleared from the owning center.",
        "customer_action": "Investigate drift before replacing evidence.",
        "policy": "preserve",
    },
    {
        "id": "protected-local-records",
        "label": "Protected local records",
        "purpose": "Keep settings, protected license and owner controls, and the encrypted Personal Vault.",
        "retention": "Remains until the customer changes settings, removes local state, or restores app data.",
        "customer_action": "Use the owning app controls and protect app-data backups.",
        "policy": "preserve",
    },
    {
        "id": "update-rollback",
        "label": "Update and rollback records",
        "purpose": "Keep signed-update status and rollback app files needed after an installation.",
        "retention": "Managed by Update Center and updater boundaries.",
        "customer_action": "Use Update Center instead of deleting rollback data manually.",
        "policy": "source-center-only",
    },
    {
        "id": "owner-lab",
        "label": "Private owner-lab records",
        "purpose": "Keep tested candidate packages, private runtimes, preflight evidence, and release history.",
        "retention": "Bounded by Owner Update Lab runtime maintenance and owner release policy.",
        "customer_action": "Owner-only; never include it in customer packages or customer cleanup.",
        "policy": "owner-only",
    },
    {
        "id": "external-customer-data",
        "label": "External keys, locks, and backups",
        "purpose": "Represent customer-selected USB keys, locked containers, and backup destinations as an explicit no-scan boundary.",
        "retention": "Controlled by the customer outside VaultLink app data.",
        "customer_action": "Manage those locations directly and keep independent tested recovery copies.",
        "policy": "not-inventoried",
    },
)

CONTROL_CHECKS = (
    ("fixed-temp-boundary", "Boundary", "Exact temporary boundary", 12),
    ("no-reparse", "Boundary", "No link or junction traversal", 12),
    ("bounded-preview", "Boundary", "Bounded metadata preview", 8),
    ("expired-temp", "Retention", "Expired temporary workspace", 16),
    ("audit-integrity", "Evidence", "Audit history integrity", 12),
    ("recovery-integrity", "Evidence", "Recovery history integrity", 10),
    ("privacy-receipts", "Evidence", "Privacy receipt integrity", 8),
    ("rollback-boundary", "Boundary", "Rollback records stay in app data", 6),
    ("owner-lab-boundary", "Boundary", "Owner lab stays private", 6),
    ("external-no-scan", "Boundary", "External customer data is not scanned", 10),
)

CONTROL_MESSAGES = {
    "fixed-temp-boundary": ("The cleanup target is the exact VaultLink temporary workspace.", "The exact temporary workspace boundary could not be verified.", "Do not clean anything until the app-data boundary is repaired."),
    "no-reparse": ("The temporary preview found no link or junction boundary.", "A link, junction, or unsafe traversal boundary blocked cleanup.", "Review the temporary folder manually; this center will not follow the link."),
    "bounded-preview": ("The metadata-only preview completed within the 5,000-entry cap.", "The preview hit its fixed cap or a metadata error.", "Use the data-folder view and qualified help; cleanup remains blocked."),
    "expired-temp": ("No temporary entry is currently eligible for explicit cleanup.", "One or more temporary entries are old enough for explicit cleanup review.", "Close viewers, inspect the preview, and clean only after typed confirmation."),
    "audit-integrity": ("The bounded local audit history verified.", "The local audit history did not verify.", "Preserve it and investigate from Audit Log Viewer before changing records."),
    "recovery-integrity": ("Recovery Kit, Drill, and Backup Verification histories are absent or valid.", "One or more recovery histories did not verify.", "Preserve the affected history and review it in the source center."),
    "privacy-receipts": ("Data Control and retention receipt histories are absent or valid.", "A privacy receipt history did not verify.", "Preserve the history and do not append another receipt until reviewed."),
    "rollback-boundary": ("Update and rollback records remain inside known VaultLink app data.", "An update or rollback source left the known app-data boundary.", "Stop and review the updater boundary before continuing."),
    "owner-lab-boundary": ("Private Owner Update Lab records remain inside their owner-only app-data boundary.", "The private owner-lab boundary could not be verified.", "Do not distribute or clean owner-lab records until the boundary is repaired."),
    "external-no-scan": ("USB keys, locked containers, backups, Documents, and Downloads remain outside this center.", "The external no-scan boundary changed.", "Restore the fixed no-scan boundary before using retention tools."),
}

VALID_STATES = frozenset({"present", "empty", "not-configured", "not-inventoried"})
VALID_ACTIONS = frozenset({"review", "cleanup"})
VALID_RESULTS = frozenset({"ok", "attention", "blocked"})
RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "sequence",
        "time_utc",
        "event_id",
        "action",
        "result",
        "posture_score",
        "eligible_band",
        "removed_band",
        "bytes_band",
        "blocked",
        "previous_hash",
        "hash",
    }
)


def _linklike(path):
    path = Path(path)
    try:
        info = path.lstat()
        attributes = getattr(info, "st_file_attributes", 0)
        reparse = getattr(os.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return path.is_symlink() or bool(attributes & reparse)
    except OSError:
        return False


def _inside_app_dir(path):
    try:
        Path(path).resolve().relative_to(locker.APP_DIR.resolve())
        return True
    except (OSError, ValueError):
        return False


def _exact_temp_root():
    root = Path(locker.TEMP_DIR)
    expected = locker.APP_DIR.resolve() / "temp"
    if root.resolve() != expected or root.name.lower() != "temp":
        raise ValueError("The exact VaultLink temporary boundary could not be verified.")
    if _linklike(root):
        raise ValueError("The temporary workspace cannot be a link or junction.")
    return root


def _safe_utc_text(value=""):
    text = str(value or locker.utc_now_text()).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("UTC offset required")
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError):
        raise ValueError("Retention time must be a valid UTC timestamp.")


def _bounded_stats(paths):
    count = 0
    total_bytes = 0
    newest = None
    capped = False
    errors = False
    for source in paths:
        path = Path(source)
        if not _inside_app_dir(path) or _linklike(path):
            errors = True
            continue
        if not path.exists():
            continue
        if path.is_file():
            try:
                info = path.stat()
                count += 1
                total_bytes += max(0, int(info.st_size))
                newest = max(newest or info.st_mtime, info.st_mtime)
            except OSError:
                errors = True
            continue
        try:
            for root, directories, files in os.walk(path, followlinks=False):
                root_path = Path(root)
                safe_directories = []
                for name in directories:
                    child = root_path / name
                    if _linklike(child) or not _inside_app_dir(child):
                        errors = True
                    else:
                        safe_directories.append(name)
                directories[:] = safe_directories
                for name in files:
                    child = root_path / name
                    if _linklike(child) or not _inside_app_dir(child):
                        errors = True
                        continue
                    try:
                        info = child.stat()
                        count += 1
                        total_bytes += max(0, int(info.st_size))
                        newest = max(newest or info.st_mtime, info.st_mtime)
                    except OSError:
                        errors = True
                    if count >= MAX_METADATA_ENTRIES:
                        capped = True
                        break
                if capped:
                    break
        except OSError:
            errors = True
    return {"count": count, "bytes": total_bytes, "newest": newest, "capped": capped, "errors": errors}


def _inspect_temp_candidate(candidate, root, cutoff, budget):
    candidate = Path(candidate)
    root = Path(root)
    try:
        if candidate.parent.resolve() != root.resolve() or _linklike(candidate):
            return {"safe": False, "eligible": False, "entries": 0, "bytes": 0, "newest": None, "reason": "link-or-boundary"}
        info = candidate.stat()
    except OSError:
        return {"safe": False, "eligible": False, "entries": 0, "bytes": 0, "newest": None, "reason": "metadata-error"}
    entries = 1
    total_bytes = max(0, int(info.st_size)) if candidate.is_file() else 0
    newest = float(info.st_mtime)
    if candidate.is_dir():
        try:
            for walk_root, directories, files in os.walk(candidate, followlinks=False):
                walk_path = Path(walk_root)
                safe_directories = []
                for name in directories:
                    child = walk_path / name
                    if _linklike(child) or not _inside_app_dir(child):
                        return {"safe": False, "eligible": False, "entries": entries, "bytes": total_bytes, "newest": newest, "reason": "link-or-boundary"}
                    safe_directories.append(name)
                    child_info = child.stat()
                    entries += 1
                    newest = max(newest, float(child_info.st_mtime))
                    if entries > budget:
                        return {"safe": False, "eligible": False, "entries": entries, "bytes": total_bytes, "newest": newest, "reason": "cap"}
                directories[:] = safe_directories
                for name in files:
                    child = walk_path / name
                    if _linklike(child) or not _inside_app_dir(child):
                        return {"safe": False, "eligible": False, "entries": entries, "bytes": total_bytes, "newest": newest, "reason": "link-or-boundary"}
                    child_info = child.stat()
                    entries += 1
                    total_bytes += max(0, int(child_info.st_size))
                    newest = max(newest, float(child_info.st_mtime))
                    if entries > budget:
                        return {"safe": False, "eligible": False, "entries": entries, "bytes": total_bytes, "newest": newest, "reason": "cap"}
        except OSError:
            return {"safe": False, "eligible": False, "entries": entries, "bytes": total_bytes, "newest": newest, "reason": "metadata-error"}
    return {"safe": True, "eligible": newest <= cutoff, "entries": entries, "bytes": total_bytes, "newest": newest, "reason": ""}


def scan_temp_workspace(now=None):
    now_value = float(now if now is not None else time.time())
    cutoff = now_value - EXPIRED_SECONDS
    try:
        root = _exact_temp_root()
    except ValueError as exc:
        return {"boundary_valid": False, "blocked": True, "capped": False, "errors": True, "reason": str(exc), "total_entries": 0, "eligible_entries": 0, "eligible_candidates": 0, "total_bytes": 0, "eligible_bytes": 0, "newest": None, "candidate_paths": []}
    if not root.exists():
        return {"boundary_valid": True, "blocked": False, "capped": False, "errors": False, "reason": "", "total_entries": 0, "eligible_entries": 0, "eligible_candidates": 0, "total_bytes": 0, "eligible_bytes": 0, "newest": None, "candidate_paths": []}
    total_entries = 0
    eligible_entries = 0
    total_bytes = 0
    eligible_bytes = 0
    newest = None
    candidate_paths = []
    blocked = False
    capped = False
    errors = False
    try:
        candidates = list(root.iterdir())
    except OSError:
        candidates = []
        errors = True
        blocked = True
    for candidate in candidates:
        remaining = MAX_TEMP_ENTRIES - total_entries
        if remaining <= 0:
            capped = True
            blocked = True
            break
        result = _inspect_temp_candidate(candidate, root, cutoff, remaining)
        total_entries += result["entries"]
        total_bytes += result["bytes"]
        if result["newest"] is not None:
            newest = max(newest or result["newest"], result["newest"])
        if not result["safe"]:
            blocked = True
            errors = errors or result["reason"] == "metadata-error"
            capped = capped or result["reason"] == "cap"
            continue
        if result["eligible"]:
            eligible_entries += result["entries"]
            eligible_bytes += result["bytes"]
            candidate_paths.append(candidate)
    return {
        "boundary_valid": True,
        "blocked": blocked,
        "capped": capped,
        "errors": errors,
        "reason": "Preview blocked by a link, cap, or metadata error." if blocked else "",
        "total_entries": total_entries,
        "eligible_entries": eligible_entries,
        "eligible_candidates": len(candidate_paths),
        "total_bytes": total_bytes,
        "eligible_bytes": eligible_bytes,
        "newest": newest,
        "candidate_paths": candidate_paths,
    }


def cleanup_expired_temp(confirm_text, now=None):
    if str(confirm_text or "").strip() != "CLEAN TEMP":
        raise ValueError("Type CLEAN TEMP exactly to confirm temporary cleanup.")
    with CLEANUP_LOCK:
        now_value = float(now if now is not None else time.time())
        scan = scan_temp_workspace(now_value)
        if scan["blocked"] or not scan["boundary_valid"]:
            raise ValueError("Temporary cleanup is blocked by the safety preview.")
        root = _exact_temp_root()
        cutoff = now_value - EXPIRED_SECONDS
        removed_candidates = 0
        removed_entries = 0
        removed_bytes = 0
        for candidate in list(scan["candidate_paths"]):
            result = _inspect_temp_candidate(candidate, root, cutoff, MAX_TEMP_ENTRIES)
            if not result["safe"] or not result["eligible"]:
                raise ValueError("Temporary contents changed during cleanup review. Refresh and try again.")
            if candidate.is_dir():
                shutil.rmtree(candidate)
            else:
                candidate.unlink()
            removed_candidates += 1
            removed_entries += result["entries"]
            removed_bytes += result["bytes"]
        locker.log_event("retention_temp_cleanup", "expired_temp", "ok", f"removed_band={data_control.count_band(removed_entries)}")
        return {"removed_candidates": removed_candidates, "removed_entries": removed_entries, "removed_bytes": removed_bytes, "remaining": scan_temp_workspace(now_value)}


def _area_sources():
    return {
        "audit-evidence": [locker.LOG_FILE, locker.AUDIT_KEY_FILE] + [locker.audit_backup_path(index) for index in range(1, locker.MAX_AUDIT_BACKUPS + 1)],
        "recovery-history": [kit_builder.HISTORY_PATH, kit_builder.SETTINGS_PATH, backup_center.HISTORY_PATH, backup_center.SETTINGS_PATH, drill_center.HISTORY_PATH, drill_center.SETTINGS_PATH],
        "privacy-baselines": [data_control.RECEIPT_HISTORY_PATH, RECEIPT_HISTORY_PATH, vault_health_center.BASELINE_FILE],
        "protected-local-records": [locker.SETTINGS_FILE, locker.VAULT_FILE],
        "update-rollback": [locker.APP_DIR / "update_backups", locker.APP_DIR / "update-status.json"],
        "owner-lab": [locker.APP_DIR / "owner_update_lab"],
    }


def collect_area_rows(temp_scan, now=None):
    now_value = float(now if now is not None else time.time())
    rows = []
    sources = _area_sources()
    for spec in AREA_SPECS:
        if spec["id"] == "temporary-unlocked-workspace":
            stats = {"count": temp_scan["total_entries"], "bytes": temp_scan["total_bytes"], "newest": temp_scan["newest"], "capped": temp_scan["capped"], "errors": temp_scan["errors"] or temp_scan["blocked"]}
            state = "present" if stats["count"] else "empty"
        elif spec["id"] == "external-customer-data":
            stats = {"count": 0, "bytes": 0, "newest": None, "capped": False, "errors": False}
            state = "not-inventoried"
        else:
            stats = _bounded_stats(sources.get(spec["id"], []))
            state = "present" if stats["count"] else "not-configured"
        rows.append(
            {
                "id": spec["id"],
                "state": state,
                "count_band": data_control.count_band(stats["count"]),
                "size_band": data_control.size_band(stats["bytes"]),
                "age_band": data_control.age_band(stats["newest"], now_value) if stats["newest"] is not None else "none",
                "metadata_attention": bool(stats["capped"] or stats["errors"]),
            }
        )
    return rows


def collect_control_checks(temp_scan):
    try:
        audit_valid, _count, _message = locker.verify_audit_logs()
    except Exception:
        audit_valid = False
    recovery_results = []
    for loader in (kit_builder.load_snapshot_history, backup_center.load_checkpoint_history, drill_center.load_drill_history):
        try:
            _history, integrity = loader()
            recovery_results.append(bool(integrity.get("valid")))
        except Exception:
            recovery_results.append(False)
    try:
        _data_history, data_integrity = data_control.load_receipt_history()
        _retention_history, retention_integrity = load_receipt_history()
        privacy_valid = bool(data_integrity.get("valid")) and bool(retention_integrity.get("valid"))
    except Exception:
        privacy_valid = False
    rollback_sources = _area_sources()["update-rollback"]
    owner_sources = _area_sources()["owner-lab"]
    states = {
        "fixed-temp-boundary": bool(temp_scan["boundary_valid"]),
        "no-reparse": not temp_scan["blocked"],
        "bounded-preview": not temp_scan["capped"] and not temp_scan["errors"],
        "expired-temp": temp_scan["eligible_entries"] == 0,
        "audit-integrity": audit_valid,
        "recovery-integrity": all(recovery_results),
        "privacy-receipts": privacy_valid,
        "rollback-boundary": all(_inside_app_dir(path) and not _linklike(path) for path in rollback_sources),
        "owner-lab-boundary": all(_inside_app_dir(path) and not _linklike(path) for path in owner_sources),
        "external-no-scan": True,
    }
    return [{"id": identifier, "passed": states[identifier]} for identifier, _category, _title, _weight in CONTROL_CHECKS]


def safe_online_metadata(payload):
    source = payload if isinstance(payload, dict) else {}
    service = source.get("service_status") if isinstance(source.get("service_status"), dict) else {}
    release = source.get("signed_release") if isinstance(source.get("signed_release"), dict) else {}
    mode = str(service.get("mode") or "unknown").strip().lower()

    def version(value, fallback=""):
        text = str(value or "").strip()
        return text if VERSION_RE.fullmatch(text) else fallback

    return {
        "available": bool(source.get("ok")),
        "api_version": version(source.get("api_version"), "Unavailable"),
        "service_mode": mode if mode in SERVICE_MODES else "unknown",
        "signed_desktop_version": version(release.get("version")),
        "area_count": 8,
        "practice_count": 10,
        "accepts_inventory": False,
        "accepts_paths": False,
        "accepts_files": False,
        "accepts_progress": False,
    }


def build_retention_report(rows, checks, temp_scan, online_payload=None, history=None, integrity=None, generated_at_utc=""):
    row_map = {str(item.get("id")): item for item in rows or [] if isinstance(item, dict)}
    clean_rows = []
    for spec in AREA_SPECS:
        source = row_map.get(spec["id"], {})
        state = str(source.get("state", "not-configured"))
        count_value = str(source.get("count_band", "none"))
        size_value = str(source.get("size_band", "none"))
        age_value = str(source.get("age_band", "none"))
        clean_rows.append(
            {
                "id": spec["id"],
                "label": spec["label"],
                "purpose": spec["purpose"],
                "retention": spec["retention"],
                "customer_action": spec["customer_action"],
                "policy": spec["policy"],
                "state": state if state in VALID_STATES else "not-configured",
                "count_band": count_value if count_value in data_control.VALID_COUNT_BANDS else "none",
                "size_band": size_value if size_value in data_control.VALID_SIZE_BANDS else "none",
                "age_band": age_value if age_value in data_control.VALID_AGE_BANDS else "unknown",
                "metadata_attention": bool(source.get("metadata_attention")),
            }
        )
    check_map = {str(item.get("id")): item for item in checks or [] if isinstance(item, dict)}
    clean_checks = []
    for identifier, category, title, weight in CONTROL_CHECKS:
        passed = bool(check_map.get(identifier, {}).get("passed"))
        good_detail, bad_detail, action = CONTROL_MESSAGES[identifier]
        clean_checks.append({"id": identifier, "category": category, "title": title, "passed": passed, "state": "good" if passed else "attention", "weight": weight, "detail": good_detail if passed else bad_detail, "action": action})
    score = sum(item["weight"] for item in clean_checks if item["passed"])
    history = list(history or [])
    integrity = integrity if isinstance(integrity, dict) else {"valid": True}
    temp_public = {
        "total_band": data_control.count_band(int(temp_scan.get("total_entries", 0))),
        "eligible_band": data_control.count_band(int(temp_scan.get("eligible_entries", 0))),
        "total_size_band": data_control.size_band(int(temp_scan.get("total_bytes", 0))),
        "eligible_size_band": data_control.size_band(int(temp_scan.get("eligible_bytes", 0))),
        "blocked": bool(temp_scan.get("blocked")),
        "capped": bool(temp_scan.get("capped")),
        "metadata_errors": bool(temp_scan.get("errors")),
        "expiry_minutes": EXPIRED_SECONDS // 60,
    }
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": "VaultLink Storage and Retention Report",
        "generated_at_utc": _safe_utc_text(generated_at_utc),
        "areas": clean_rows,
        "area_count": len(clean_rows),
        "summary": {"present_count": sum(item["state"] == "present" for item in clean_rows), "preserve_count": sum(item["policy"] == "preserve" for item in clean_rows), "cleanup_area_count": sum(item["policy"] == "cleanup-eligible" for item in clean_rows), "external_boundary_count": sum(item["state"] == "not-inventoried" for item in clean_rows), "metadata_attention_count": sum(item["metadata_attention"] for item in clean_rows)},
        "posture": {"score": score, "maximum": 100, "label": "ready" if score >= 90 else "review" if score >= 70 else "attention", "passed": sum(item["passed"] for item in clean_checks), "total": len(clean_checks)},
        "checks": clean_checks,
        "temporary_workspace": temp_public,
        "online": safe_online_metadata(online_payload),
        "receipts": {"record_count": len(history), "integrity_valid": bool(integrity.get("valid")), "integrity_message": f"Verified {len(history)} hash-chained retention receipt(s)." if integrity.get("valid") else "Retention receipt history needs review before another receipt is saved."},
        "privacy_notice": "This report contains fixed area IDs, public descriptions, coarse count, size, and age bands, fixed control results, public service metadata, and receipt integrity only. It excludes names, contacts, license proof, keys, PINs, paths, filenames, file contents, screenshots, process lists, and free-form notes.",
        "cleanup_boundary": "Only expired direct children of the exact VaultLink temporary workspace can be removed after a fresh safety preview and typed confirmation.",
        "limitations": ["Temporary cleanup is best effort and is not a secure-erasure guarantee, especially on SSDs or synchronized storage.", "This center never deletes audit evidence, recovery history, privacy receipts, settings, licenses, owner controls, vault data, update rollback data, owner-lab data, keys, locked containers, or backups.", "A clean retention report is not forensic proof, legal advice, compliance certification, or a guarantee that every copy has been found."],
    }


def _canonical_receipt(record):
    payload = dict(record)
    payload.pop("hash", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def load_receipt_history(path=RECEIPT_HISTORY_PATH):
    path = Path(path)
    if not path.is_file():
        return [], {"valid": True, "message": "No retention receipts saved yet."}
    if _linklike(path):
        return [], {"valid": False, "message": "Retention receipt history cannot be a link or junction."}
    if path.stat().st_size > MAX_HISTORY_BYTES:
        return [], {"valid": False, "message": "Retention receipt history exceeds the fixed size limit."}
    records = []
    previous_hash = "0" * 64
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) > MAX_HISTORY_RECORDS:
            raise ValueError("Retention receipt history exceeds the fixed record limit.")
        for index, line in enumerate(lines, 1):
            record = json.loads(line)
            if not isinstance(record, dict) or set(record) != RECEIPT_FIELDS:
                raise ValueError(f"Receipt {index} does not match the fixed schema.")
            if record.get("schema_version") != 1 or record.get("sequence") != index or record.get("previous_hash") != previous_hash:
                raise ValueError(f"Receipt {index} broke the fixed sequence or hash chain.")
            if _safe_utc_text(record.get("time_utc")) != record.get("time_utc") or not HEX_16_RE.fullmatch(str(record.get("event_id", ""))):
                raise ValueError(f"Receipt {index} has invalid fixed identity fields.")
            if record.get("action") not in VALID_ACTIONS or record.get("result") not in VALID_RESULTS:
                raise ValueError(f"Receipt {index} has an invalid fixed action.")
            if not isinstance(record.get("posture_score"), int) or not 0 <= record["posture_score"] <= 100:
                raise ValueError(f"Receipt {index} has an invalid posture score.")
            if record.get("eligible_band") not in data_control.VALID_COUNT_BANDS or record.get("removed_band") not in data_control.VALID_COUNT_BANDS or record.get("bytes_band") not in data_control.VALID_SIZE_BANDS or not isinstance(record.get("blocked"), bool):
                raise ValueError(f"Receipt {index} has an invalid coarse value.")
            if not HEX_64_RE.fullmatch(str(record.get("previous_hash", ""))) or not HEX_64_RE.fullmatch(str(record.get("hash", ""))):
                raise ValueError(f"Receipt {index} has an invalid integrity field.")
            expected_hash = hashlib.sha256(_canonical_receipt(record)).hexdigest()
            if not secrets.compare_digest(str(record.get("hash", "")), expected_hash):
                raise ValueError(f"Receipt {index} failed its hash check.")
            records.append(record)
            previous_hash = expected_hash
    except Exception as exc:
        return records, {"valid": False, "message": str(exc)}
    return records, {"valid": True, "message": f"Verified {len(records)} hash-chained retention receipt(s)."}


def append_receipt(report, action="review", result="ok", removed_entries=0, removed_bytes=0, path=RECEIPT_HISTORY_PATH, time_utc=""):
    with RECEIPT_LOCK:
        path = Path(path)
        if _linklike(path):
            raise ValueError("Retention receipt history cannot be a link or junction.")
        history, integrity = load_receipt_history(path)
        if not integrity["valid"]:
            raise ValueError("Retention receipt integrity failed. Review it before saving another receipt.")
        action = str(action)
        result = str(result)
        if action not in VALID_ACTIONS or result not in VALID_RESULTS:
            raise ValueError("Retention receipt action is not allowed.")
        posture_score = int((report.get("posture") or {}).get("score", -1))
        temporary = report.get("temporary_workspace") if isinstance(report.get("temporary_workspace"), dict) else {}
        eligible_band = str(temporary.get("eligible_band", "none"))
        if not 0 <= posture_score <= 100 or eligible_band not in data_control.VALID_COUNT_BANDS:
            raise ValueError("Retention receipt contains an invalid fixed value.")
        record = {"schema_version": 1, "sequence": len(history) + 1, "time_utc": _safe_utc_text(time_utc), "event_id": secrets.token_hex(8), "action": action, "result": result, "posture_score": posture_score, "eligible_band": eligible_band, "removed_band": data_control.count_band(max(0, int(removed_entries))), "bytes_band": data_control.size_band(max(0, int(removed_bytes))), "blocked": bool(temporary.get("blocked")), "previous_hash": history[-1]["hash"] if history else "0" * 64}
        record["hash"] = hashlib.sha256(_canonical_receipt(record)).hexdigest()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return record


def collect_retention_report(online_payload=None, now=None):
    scan = scan_temp_workspace(now)
    rows = collect_area_rows(scan, now)
    checks = collect_control_checks(scan)
    history, integrity = load_receipt_history()
    return build_retention_report(rows, checks, scan, online_payload, history, integrity)


def collect_inputs():
    online = {}
    try:
        settings = locker.load_settings()
        state = locker.load_license_state(settings)
        server = locker.validated_license_server_url(state.get("server_url"))
        online = locker.license_api_get_json(server, GUIDE_ENDPOINT)
    except Exception:
        pass
    return collect_retention_report(online)


def record_cleanup_and_collect(cleanup_result):
    report = collect_inputs()
    append_receipt(
        report,
        "cleanup",
        "ok",
        cleanup_result["removed_entries"],
        cleanup_result["removed_bytes"],
    )
    history, integrity = load_receipt_history()
    report["receipts"] = {
        "record_count": len(history),
        "integrity_valid": bool(integrity.get("valid")),
        "integrity_message": integrity.get("message", "Retention receipt history needs review."),
    }
    return report


def safe_report_text(report):
    lines = ["VAULTLINK STORAGE AND RETENTION REPORT", "======================================", f"Generated UTC: {report['generated_at_utc']}", f"Areas: {report['area_count']} fixed", f"Posture: {report['posture']['score']}/100 ({report['posture']['label']})", f"Temporary workspace: {report['temporary_workspace']['total_band']} entries | eligible {report['temporary_workspace']['eligible_band']} | {report['temporary_workspace']['eligible_size_band']}", "", "RETENTION AREAS", "---------------"]
    for item in report["areas"]:
        lines.extend([f"{item['label']} | {item['state']} | {item['policy']}", f"  Storage: {item['count_band']} entries | {item['size_band']} | {item['age_band']}", f"  Retention: {item['retention']}", f"  Customer control: {item['customer_action']}"])
    lines.extend(["", "CONTROLS", "--------"])
    for item in report["checks"]:
        lines.extend([f"[{'PASS' if item['passed'] else 'REVIEW'}] {item['title']} ({item['weight']} points)", f"  {item['detail']}", f"  Action: {item['action']}"])
    lines.extend(["", "PRIVACY", "-------", report["privacy_notice"], report["cleanup_boundary"], "", "LIMITATIONS", "-----------"])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines)


def safe_summary(report):
    return "\n".join(["VaultLink Storage and Retention", f"Areas: {report['area_count']} fixed | cleanup targets: {report['summary']['cleanup_area_count']}", f"Posture: {report['posture']['score']}/100 | controls: {report['posture']['passed']}/{report['posture']['total']}", f"Temporary entries: {report['temporary_workspace']['total_band']} | eligible: {report['temporary_workspace']['eligible_band']} | eligible size: {report['temporary_workspace']['eligible_size_band']}", f"Receipt integrity: {'valid' if report['receipts']['integrity_valid'] else 'review'} | records: {report['receipts']['record_count']}", "No names, contacts, keys, PINs, paths, filenames, contents, screenshots, process lists, or notes are included.", "Temporary cleanup is best effort, not guaranteed secure erasure."])


class StorageRetentionCenter(tk.Tk):
    def __init__(self):
        super().__init__()
        if not locker.ensure_license_feature("storage-retention-center", parent=self):
            self.after(0, self.destroy)
            return
        self.title("VaultLink Storage & Retention Center")
        self.geometry("1240x920")
        self.minsize(1040, 760)
        self.configure(bg=locker.BG)
        self.results = queue.Queue()
        self.report = None
        self.working = False
        self.action_buttons = []
        self.status_var = tk.StringVar(value="Ready to preview fixed retention boundaries.")
        self.metric_vars = {name: tk.StringVar(value="--") for name in ("score", "areas", "temp", "eligible", "blocked", "receipts")}
        self.build_ui()
        self.after(80, self.refresh_report)

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=20)
        tk.Label(outer, text="Storage & Retention Center", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 25, "bold")).pack(anchor="w")
        tk.Label(outer, text="Preview eight fixed VaultLink storage areas and clean only expired temporary working copies after a fresh safety check and typed confirmation.", bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 10), wraplength=1120, justify="left").pack(anchor="w", pady=(4, 14))
        toolbar = tk.Frame(outer, bg=locker.BG)
        toolbar.pack(fill="x", pady=(0, 12))
        for text, command, bg, fg in (("REFRESH", self.refresh_report, locker.GREEN, locker.BLACK), ("CLEAN EXPIRED TEMP", self.clean_temp, locker.YELLOW, locker.BLACK), ("SAVE REVIEW RECEIPT", self.save_review_receipt, locker.BLUE, locker.BLACK), ("COPY SUMMARY", self.copy_summary, "#252936", locker.TEXT), ("EXPORT JSON", self.export_json, "#252936", locker.TEXT), ("EXPORT TEXT", self.export_text, "#252936", locker.TEXT)):
            button = tk.Button(toolbar, text=text, command=command, bg=bg, fg=fg, relief="flat", font=("Segoe UI", 8, "bold"))
            button.pack(side="left", padx=(0, 8), ipadx=9, ipady=7)
            self.action_buttons.append(button)
        public_button = tk.Button(toolbar, text="PUBLIC GUIDE", command=self.open_public_guide, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold"))
        public_button.pack(side="right", ipadx=9, ipady=7)
        data_button = tk.Button(toolbar, text="DATA CONTROL", command=self.open_data_control, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold"))
        data_button.pack(side="right", padx=(0, 8), ipadx=9, ipady=7)
        self.action_buttons.extend((public_button, data_button))
        metrics = tk.Frame(outer, bg=locker.PANEL)
        metrics.pack(fill="x", pady=(0, 14))
        for index, (key, label) in enumerate((("score", "POSTURE"), ("areas", "FIXED AREAS"), ("temp", "TEMP ENTRIES"), ("eligible", "ELIGIBLE"), ("blocked", "CLEANUP"), ("receipts", "RECEIPTS"))):
            cell = tk.Frame(metrics, bg=locker.PANEL)
            cell.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 1, 0))
            tk.Label(cell, text=label, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 7, "bold")).pack(anchor="w", padx=12, pady=(10, 2))
            tk.Label(cell, textvariable=self.metric_vars[key], bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 13, "bold"), wraplength=150, justify="left").pack(anchor="w", padx=12, pady=(0, 10))
            metrics.grid_columnconfigure(index, weight=1)
        body = tk.PanedWindow(outer, orient="horizontal", bg=locker.BG, sashwidth=6, bd=0)
        body.pack(fill="both", expand=True)
        left = tk.Frame(body, bg=locker.PANEL)
        right = tk.Frame(body, bg=locker.PANEL)
        body.add(left, minsize=610)
        body.add(right, minsize=420)
        tk.Label(left, text="FIXED RETENTION AREAS", bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=14, pady=(12, 8))
        columns = ("state", "area", "policy", "count", "size", "age")
        self.area_tree = ttk.Treeview(left, columns=columns, show="headings", height=10)
        for name, width in (("state", 90), ("area", 210), ("policy", 120), ("count", 80), ("size", 120), ("age", 100)):
            self.area_tree.heading(name, text=name.upper())
            self.area_tree.column(name, width=width, minwidth=60, stretch=name == "area")
        self.area_tree.pack(fill="x", padx=14)
        self.area_tree.bind("<<TreeviewSelect>>", self.show_selected_area)
        tk.Label(left, text="AREA DETAILS", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=14, pady=(12, 4))
        self.detail = scrolledtext.ScrolledText(left, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", wrap="word", font=("Consolas", 9), height=14, state="disabled")
        self.detail.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        tk.Label(right, text="RETENTION CONTROLS", bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=14, pady=(12, 8))
        self.check_tree = ttk.Treeview(right, columns=("state", "control", "points"), show="headings", height=11)
        for name, width in (("state", 80), ("control", 260), ("points", 70)):
            self.check_tree.heading(name, text=name.upper())
            self.check_tree.column(name, width=width, minwidth=55, stretch=name == "control")
        self.check_tree.pack(fill="x", padx=14)
        self.check_tree.bind("<<TreeviewSelect>>", self.show_selected_check)
        tk.Label(right, text="SAFETY BOUNDARY", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=14, pady=(14, 4))
        self.boundary = scrolledtext.ScrolledText(right, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", wrap="word", font=("Consolas", 9), height=13, state="disabled")
        self.boundary.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        tk.Label(outer, textvariable=self.status_var, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9), wraplength=1120, justify="left").pack(anchor="w", pady=(12, 0))

    def _set_text(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _run(self, operation, callback):
        if self.working:
            self.status_var.set("A retention operation is already running.")
            return
        self.working = True
        for button in self.action_buttons:
            button.configure(state="disabled")
        self.status_var.set("Working inside the fixed retention boundary...")
        def worker():
            try:
                value = operation()
                self.results.put((callback, value, None))
            except Exception as exc:
                self.results.put((callback, None, exc))
        threading.Thread(target=worker, daemon=True).start()
        self.after(80, self._poll)

    def _poll(self):
        try:
            callback, value, error = self.results.get_nowait()
        except queue.Empty:
            self.after(80, self._poll)
            return
        self.working = False
        for button in self.action_buttons:
            button.configure(state="normal")
        callback(value, error)

    def refresh_report(self):
        self._run(collect_inputs, self._finish_refresh)

    def _finish_refresh(self, report, error):
        if error:
            self.status_var.set("Retention preview failed without changing data.")
            messagebox.showerror("Retention preview failed", str(error), parent=self)
            return
        self.report = report
        self.area_tree.delete(*self.area_tree.get_children())
        for item in report["areas"]:
            self.area_tree.insert("", "end", iid=item["id"], values=(item["state"], item["label"], item["policy"], item["count_band"], item["size_band"], item["age_band"]))
        self.check_tree.delete(*self.check_tree.get_children())
        for item in report["checks"]:
            self.check_tree.insert("", "end", iid=item["id"], values=("PASS" if item["passed"] else "REVIEW", item["title"], item["weight"]))
        temp = report["temporary_workspace"]
        self.metric_vars["score"].set(f"{report['posture']['score']} / 100")
        self.metric_vars["areas"].set(str(report["area_count"]))
        self.metric_vars["temp"].set(temp["total_band"])
        self.metric_vars["eligible"].set(temp["eligible_band"])
        self.metric_vars["blocked"].set("BLOCKED" if temp["blocked"] else "READY")
        self.metric_vars["receipts"].set(str(report["receipts"]["record_count"]))
        self._set_text(self.boundary, report["cleanup_boundary"] + "\n\n" + report["privacy_notice"] + "\n\n" + "\n".join(f"- {item}" for item in report["limitations"]))
        self.status_var.set("Preview complete. No data changed. Cleanup is available only for expired temporary working copies." if temp["eligible_band"] == "none" else "Expired temporary items are available for explicit cleanup review. Close viewers before cleaning.")
        locker.log_event("retention_center_refresh", "fixed_preview", "ok")

    def show_selected_area(self, _event=None):
        if not self.report or not self.area_tree.selection():
            return
        identifier = self.area_tree.selection()[0]
        item = next((row for row in self.report["areas"] if row["id"] == identifier), None)
        if item:
            self._set_text(self.detail, "\n\n".join((item["label"], f"State: {item['state']} | policy: {item['policy']}", item["purpose"], "Retention: " + item["retention"], "Customer control: " + item["customer_action"], "Storage bands: " + item["count_band"] + " entries | " + item["size_band"] + " | " + item["age_band"])))

    def show_selected_check(self, _event=None):
        if not self.report or not self.check_tree.selection():
            return
        identifier = self.check_tree.selection()[0]
        item = next((row for row in self.report["checks"] if row["id"] == identifier), None)
        if item:
            self._set_text(self.boundary, f"{item['title']}\n\n{item['detail']}\n\nAction: {item['action']}\n\n{self.report['cleanup_boundary']}")

    def clean_temp(self):
        if not self.report:
            return
        temp = self.report["temporary_workspace"]
        if temp["blocked"]:
            messagebox.showwarning("Cleanup blocked", "The safety preview found a link, cap, or metadata error. No data will be removed.", parent=self)
            return
        if temp["eligible_band"] == "none":
            messagebox.showinfo("Nothing eligible", "No temporary entry is currently old enough for explicit cleanup.", parent=self)
            return
        if not messagebox.askyesno("Clean expired temporary copies?", "This removes only expired entries inside VaultLink's exact temporary workspace. Close any open viewers first. Keys, locked files, vault data, audit evidence, settings, backups, and other folders are excluded.\n\nContinue to typed confirmation?", parent=self):
            return
        text = simpledialog.askstring("Typed cleanup confirmation", "Type CLEAN TEMP exactly:", parent=self)
        if text != "CLEAN TEMP":
            self.status_var.set("Cleanup cancelled. Confirmation did not match.")
            return
        self._run(lambda: cleanup_expired_temp(text), self._finish_cleanup)

    def _finish_cleanup(self, result, error):
        if error:
            self.status_var.set("Cleanup stopped without leaving the fixed temporary boundary.")
            messagebox.showerror("Temporary cleanup stopped", str(error), parent=self)
            return
        self._run(
            lambda: record_cleanup_and_collect(result),
            lambda report, refresh_error: self._finish_cleanup_refresh(result, report, refresh_error),
        )

    def _finish_cleanup_refresh(self, result, report, error):
        if error:
            self.status_var.set("Temporary cleanup completed, but its receipt or refreshed preview needs review.")
            messagebox.showwarning("Cleanup receipt needs review", str(error), parent=self)
            return
        self._finish_refresh(report, None)
        self.status_var.set(f"Removed {data_control.count_band(result['removed_entries'])} expired temporary entries ({data_control.size_band(result['removed_bytes'])}). No other storage area was changed.")

    def save_review_receipt(self):
        if not self.report:
            return
        try:
            result = "attention" if self.report["temporary_workspace"]["eligible_band"] != "none" else "ok"
            append_receipt(self.report, "review", result)
            self.status_var.set("Saved a hash-chained fixed-schema retention review receipt locally.")
            locker.log_event("retention_receipt_save", "fixed_review", "ok")
            self.refresh_report()
        except Exception as exc:
            messagebox.showerror("Could not save receipt", str(exc), parent=self)

    def copy_summary(self):
        if self.report:
            self.clipboard_clear()
            self.clipboard_append(safe_summary(self.report))
            locker.log_event("retention_summary_copy", "privacy_safe", "ok")
            self.status_var.set("Copied the reviewed privacy-safe retention summary.")

    def export_json(self):
        if not self.report:
            return
        target = filedialog.asksaveasfilename(parent=self, title="Export Retention JSON", defaultextension=".json", initialfile="vaultlink-storage-retention.json", filetypes=(("JSON", "*.json"),))
        if target:
            Path(target).write_text(json.dumps(self.report, indent=2), encoding="utf-8")
            locker.log_event("retention_export_json", "privacy_safe", "ok")
            self.status_var.set("Exported reviewed retention JSON. Coarse category presence can still be sensitive.")

    def export_text(self):
        if not self.report:
            return
        target = filedialog.asksaveasfilename(parent=self, title="Export Retention Text", defaultextension=".txt", initialfile="vaultlink-storage-retention.txt", filetypes=(("Text", "*.txt"),))
        if target:
            Path(target).write_text(safe_report_text(self.report), encoding="utf-8")
            locker.log_event("retention_export_text", "privacy_safe", "ok")
            self.status_var.set("Exported reviewed privacy-safe retention text.")

    def open_data_control(self):
        try:
            locker.launch_companion_script("local_data_control_center.py")
            self.status_var.set("Opened Local Data Control Center.")
        except Exception as exc:
            messagebox.showerror("Could not open Data Control", str(exc), parent=self)

    def open_public_guide(self):
        try:
            settings = locker.load_settings()
            state = locker.load_license_state(settings)
            server = locker.validated_license_server_url(state.get("server_url"))
            webbrowser.open(server.rstrip("/") + "/retention", new=2)
            locker.log_event("retention_online_open", "public_workspace", "ok")
            self.status_var.set("Opened the public current-tab-only retention guide.")
        except Exception as exc:
            messagebox.showerror("Could not open Retention Guide", str(exc), parent=self)


if __name__ == "__main__":
    StorageRetentionCenter().mainloop()
