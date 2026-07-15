import base64
import hashlib
import json
import os
import queue
import re
import secrets
import threading
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

import backup_verification_center as backup_center
import recovery_drill_center as drill_center
import recovery_kit_builder as kit_builder
import usb_file_locker as locker
import vault_health_center


DATA_MAP_ENDPOINT = "/api/v1/data-map"
RECEIPT_HISTORY_PATH = locker.APP_DIR / "data_control_receipts.jsonl"
MAX_HISTORY_RECORDS = 500
MAX_HISTORY_BYTES = 2 * 1024 * 1024
MAX_INVENTORY_FILES = 5000
REPORT_SCHEMA_VERSION = 1
RECEIPT_LOCK = threading.RLock()
HEX_16_RE = re.compile(r"^[0-9a-f]{16}$")
HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,4}$")
SERVICE_MODES = frozenset({"normal", "maintenance", "limited", "degraded", "outage", "unknown"})

SCOPE_SPECS = (
    ("windows-user", "Windows user profile"),
    ("removable-media", "Removable media"),
    ("customer-selected", "Customer-selected storage"),
    ("explicit-api", "API after explicit action"),
    ("public-service", "Public service metadata"),
)

DATA_CLASS_SPECS = (
    {
        "id": "settings-preferences",
        "label": "Settings and preferences",
        "scope_id": "windows-user",
        "purpose": "Remember local UI choices, update preferences, recent key locations, and app behavior.",
        "protection": "Windows user permissions. Treat this shared settings container as private.",
        "retention": "Until settings are changed, reset, or restored from app data.",
        "customer_action": "Protect app-data backups like private records.",
        "mode": "settings",
    },
    {
        "id": "protected-license-state",
        "label": "Protected license state",
        "scope_id": "windows-user",
        "purpose": "Keep signed license, anonymous seat, rank, and service-sync state available locally.",
        "protection": "Windows DPAPI ciphertext inside the settings container.",
        "retention": "Until License Center removes it, local state is cleared, or app data is restored.",
        "customer_action": "Use License Center to remove or refresh this state.",
        "mode": "license",
    },
    {
        "id": "owner-access-controls",
        "label": "Owner and local-control access",
        "scope_id": "windows-user",
        "purpose": "Remember the owner USB policy and separate Local Control PIN verifier.",
        "protection": "Windows DPAPI plus a protected salted scrypt verifier; the PIN is never stored.",
        "retention": "Until the owner policy or Local Control PIN is changed or removed.",
        "customer_action": "Change these controls only from their local settings.",
        "mode": "owner-controls",
    },
    {
        "id": "audit-ledger",
        "label": "Audit ledger and integrity key",
        "scope_id": "windows-user",
        "purpose": "Record bounded actions, UTC times, results, anonymous IDs, and integrity fields.",
        "protection": "HMAC-SHA-256 chain with a DPAPI-protected local integrity key.",
        "retention": "Rotated to a bounded set of local audit files.",
        "customer_action": "Verify the chain and review any export before sharing.",
        "mode": "local-sources",
    },
    {
        "id": "personal-vault",
        "label": "Personal Vault",
        "scope_id": "windows-user",
        "purpose": "Store customer-entered private notes in a separate encrypted container.",
        "protection": "AES-256-GCM authenticated encryption derived from the master key and optional PIN.",
        "retention": "Until vault items or the encrypted vault container are removed.",
        "customer_action": "Back up the encrypted container and recovery material separately.",
        "mode": "local-sources",
    },
    {
        "id": "recovery-history",
        "label": "Recovery and backup history",
        "scope_id": "windows-user",
        "purpose": "Keep fixed-ID Recovery Kit, Recovery Drill, and Backup Verification results.",
        "protection": "Exact-schema tamper-evident hash chains and fixed local settings.",
        "retention": "Bounded histories remain until deliberately removed or restored.",
        "customer_action": "Verify integrity and export only reviewed fixed-ID summaries.",
        "mode": "local-sources",
    },
    {
        "id": "health-baselines",
        "label": "Health and readiness baselines",
        "scope_id": "windows-user",
        "purpose": "Compare aggregate health and data-control state without keeping a file inventory.",
        "protection": "Fixed aggregate schemas under the current Windows user.",
        "retention": "Until a baseline or privacy receipt is replaced or cleared.",
        "customer_action": "Investigate unexpected drift before replacing evidence.",
        "mode": "local-sources",
    },
    {
        "id": "temporary-workspace",
        "label": "Temporary unlocked workspace",
        "scope_id": "windows-user",
        "purpose": "Hold a short-lived working copy after an explicit local unlock-view action.",
        "protection": "Windows user permissions plus bounded cleanup attempts and visible deletion status.",
        "retention": "Designed for deletion after use or by the cleanup timer.",
        "customer_action": "Close files after use and confirm cleanup before leaving the PC.",
        "mode": "local-sources",
    },
    {
        "id": "app-backups",
        "label": "Customer-created app-data backups",
        "scope_id": "customer-selected",
        "purpose": "Preserve app data for recovery without including master-key files.",
        "protection": "Depends on the customer-selected destination.",
        "retention": "Controlled by the customer and reviewed backup policy.",
        "customer_action": "Keep independent protected copies and verify restore structure.",
        "mode": "external",
    },
    {
        "id": "update-owner-lab",
        "label": "Update, rollback, and owner-lab records",
        "scope_id": "windows-user",
        "purpose": "Keep update status, rollback app files, and private owner candidate evidence.",
        "protection": "Windows user permissions; signing secrets stay protected and outside customer packages.",
        "retention": "Rollback and private lab runtimes are bounded by local maintenance rules.",
        "customer_action": "Use Update Center or Owner Update Lab instead of mixing these files manually.",
        "mode": "local-sources",
    },
    {
        "id": "usb-master-key",
        "label": "USB master-key files",
        "scope_id": "removable-media",
        "purpose": "Provide secret material used to derive portable encryption keys.",
        "protection": "Customer-controlled removable storage and physical custody.",
        "retention": "Controlled by the key holder and recovery plan.",
        "customer_action": "Keep independent copies separate from locked data.",
        "mode": "external",
    },
    {
        "id": "locked-containers",
        "label": "Customer-selected locked containers",
        "scope_id": "customer-selected",
        "purpose": "Hold files or folders in portable authenticated encrypted containers.",
        "protection": "AES-256-GCM authenticated encryption using the master key and optional PIN.",
        "retention": "Controlled by the customer at the chosen location.",
        "customer_action": "Keep verified independent copies and preserve originals during recovery.",
        "mode": "external",
    },
    {
        "id": "explicit-api-records",
        "label": "Explicit API records",
        "scope_id": "explicit-api",
        "purpose": "Support licensing, anonymous seats, messages, support tickets, and approved audit exports.",
        "protection": "Signed tokens, encrypted private fields, admin headers, and scoped downloads.",
        "retention": "Depends on record type and configured server storage.",
        "customer_action": "Use the visible license, support, and audit controls for these records.",
        "mode": "api",
    },
    {
        "id": "public-service-metadata",
        "label": "Public service and release metadata",
        "scope_id": "public-service",
        "purpose": "Publish product, rank, service, privacy, security, and signed-release status.",
        "protection": "Public read-only responses with no customer record or license proof.",
        "retention": "Updated with service configuration and signed releases.",
        "customer_action": "Use public status, trust, privacy, and update pages to verify claims.",
        "mode": "public",
    },
)

CONTROL_CHECKS = (
    ("app-data-boundary", "Boundary", "Known app-data boundary", 10),
    ("allowlisted-inventory", "Boundary", "Allowlisted metadata inventory", 10),
    ("settings-structure", "Settings", "Settings container structure", 8),
    ("license-envelope", "Protection", "Protected license envelope", 8),
    ("owner-control-envelope", "Protection", "Protected owner controls", 8),
    ("audit-chain", "Evidence", "Audit chain integrity", 12),
    ("audit-key", "Protection", "Audit integrity key", 8),
    ("vault-format", "Protection", "Personal Vault authenticated format", 8),
    ("recovery-chains", "Evidence", "Recovery history integrity", 12),
    ("temporary-retention", "Retention", "Temporary workspace retention", 8),
    ("external-boundary", "Boundary", "External data stays outside inventory", 8),
)

CONTROL_MESSAGES = {
    "app-data-boundary": (
        "The known VaultLink app-data boundary is available to this Windows user.",
        "The known VaultLink app-data boundary is not fully available.",
        "Check Windows user permissions before relying on local state.",
    ),
    "allowlisted-inventory": (
        "Every metadata source remains inside the fixed VaultLink app-data allowlist.",
        "A metadata source left the fixed VaultLink app-data allowlist.",
        "Stop and review the Data Control source allowlist.",
    ),
    "settings-structure": (
        "The local settings container has a valid object structure.",
        "The local settings container could not be parsed safely.",
        "Preserve it, use a known-good backup, and avoid manual edits.",
    ),
    "license-envelope": (
        "The optional local license state is absent or uses the protected envelope.",
        "The optional local license state does not use the expected protected envelope.",
        "Preserve evidence, then remove and reactivate through License Center.",
    ),
    "owner-control-envelope": (
        "Optional owner controls are absent or use protected envelopes.",
        "An optional owner control does not use the expected protected envelope.",
        "Reconfigure the affected control locally without reusing a secret.",
    ),
    "audit-chain": (
        "The bounded local audit chain verified.",
        "The bounded local audit chain did not verify.",
        "Preserve the ledger and investigate the first failed anonymous event.",
    ),
    "audit-key": (
        "Audit records have the expected local integrity-key boundary.",
        "Audit records exist without a usable local integrity-key file.",
        "Preserve the ledger and restore the matching app-data backup.",
    ),
    "vault-format": (
        "The optional Personal Vault is absent or uses the authenticated format marker.",
        "The optional Personal Vault does not use the expected format marker.",
        "Preserve the original and test only a copied container.",
    ),
    "recovery-chains": (
        "The fixed Recovery Kit, Backup Verification, and Recovery Drill histories are absent or valid.",
        "One or more fixed recovery histories failed integrity review.",
        "Preserve the affected history and do not append new results until reviewed.",
    ),
    "temporary-retention": (
        "No temporary item was found beyond the expected cleanup window.",
        "At least one temporary item is older than the expected cleanup window.",
        "Close open working copies and use the explicit cleanup control.",
    ),
    "external-boundary": (
        "USB keys, customer backups, and locked-container locations stay outside this inventory.",
        "The fixed no-search boundary is not active.",
        "Restore the fixed no-search boundary before using this center.",
    ),
}

VALID_STATES = frozenset({"present", "not-configured", "not-inventoried", "api-boundary", "public"})
VALID_COUNT_BANDS = frozenset({"none", "one", "2-10", "11-100", "101-1000", "1000+"})
VALID_SIZE_BANDS = frozenset({"none", "under-64-kib", "64-kib-to-1-mib", "1-to-10-mib", "10-to-100-mib", "100-mib-plus"})
VALID_AGE_BANDS = frozenset({"none", "today", "2-7-days", "8-30-days", "31-90-days", "over-90-days", "unknown"})
RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "sequence",
        "time_utc",
        "event_id",
        "posture_score",
        "class_count",
        "present_class_count",
        "class_states",
        "passed_check_ids",
        "previous_hash",
        "hash",
    }
)


def _scope_label(identifier):
    return dict(SCOPE_SPECS).get(identifier, identifier)


def _class_sources():
    return {
        "settings-preferences": [locker.SETTINGS_FILE],
        "protected-license-state": [locker.SETTINGS_FILE],
        "owner-access-controls": [locker.SETTINGS_FILE],
        "audit-ledger": [locker.LOG_FILE, locker.AUDIT_KEY_FILE] + [locker.audit_backup_path(index) for index in range(1, locker.MAX_AUDIT_BACKUPS + 1)],
        "personal-vault": [locker.VAULT_FILE],
        "recovery-history": [
            kit_builder.HISTORY_PATH,
            kit_builder.SETTINGS_PATH,
            backup_center.HISTORY_PATH,
            backup_center.SETTINGS_PATH,
            drill_center.HISTORY_PATH,
            drill_center.SETTINGS_PATH,
        ],
        "health-baselines": [vault_health_center.BASELINE_FILE, RECEIPT_HISTORY_PATH],
        "temporary-workspace": [locker.TEMP_DIR],
        "app-backups": [],
        "update-owner-lab": [
            locker.APP_DIR / "update-status.json",
            locker.APP_DIR / "update_backups",
            locker.APP_DIR / "restore_backups",
            locker.APP_DIR / "owner_update_lab",
        ],
        "usb-master-key": [],
        "locked-containers": [],
        "explicit-api-records": [],
        "public-service-metadata": [],
    }


def _inside_app_dir(path):
    root = locker.APP_DIR.resolve()
    resolved = Path(path).resolve(strict=False)
    return resolved == root or root in resolved.parents


def _linklike(path):
    try:
        return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())
    except OSError:
        return True


def _add_stat(path, seen, totals):
    try:
        if _linklike(path) or not path.is_file():
            return
        resolved = path.resolve()
        if resolved in seen or not _inside_app_dir(resolved):
            return
        seen.add(resolved)
        info = path.stat()
        totals["count"] += 1
        totals["bytes"] += max(0, int(info.st_size))
        totals["newest"] = max(totals["newest"], float(info.st_mtime))
    except OSError:
        totals["errors"] += 1


def bounded_source_stats(paths):
    seen = set()
    totals = {"count": 0, "bytes": 0, "newest": 0.0, "capped": False, "errors": 0}
    for raw_path in paths:
        path = Path(raw_path)
        if not _inside_app_dir(path):
            totals["errors"] += 1
            continue
        if _linklike(path):
            totals["errors"] += 1
            continue
        if path.is_file():
            _add_stat(path, seen, totals)
            continue
        if not path.is_dir():
            continue
        try:
            for root, directories, files in os.walk(path, followlinks=False):
                root_path = Path(root)
                directories[:] = [
                    name
                    for name in directories
                    if not _linklike(root_path / name) and _inside_app_dir(root_path / name)
                ]
                for name in files:
                    if totals["count"] >= MAX_INVENTORY_FILES:
                        totals["capped"] = True
                        break
                    _add_stat(root_path / name, seen, totals)
                if totals["capped"]:
                    break
        except OSError:
            totals["errors"] += 1
    return totals


def count_band(value):
    value = max(0, int(value or 0))
    if value == 0:
        return "none"
    if value == 1:
        return "one"
    if value <= 10:
        return "2-10"
    if value <= 100:
        return "11-100"
    if value <= 1000:
        return "101-1000"
    return "1000+"


def size_band(value):
    value = max(0, int(value or 0))
    if value == 0:
        return "none"
    if value < 64 * 1024:
        return "under-64-kib"
    if value < 1024 * 1024:
        return "64-kib-to-1-mib"
    if value < 10 * 1024 * 1024:
        return "1-to-10-mib"
    if value < 100 * 1024 * 1024:
        return "10-to-100-mib"
    return "100-mib-plus"


def age_band(timestamp, now=None):
    if not timestamp:
        return "none"
    now_value = float(now if now is not None else time.time())
    try:
        days = max(0.0, (now_value - float(timestamp)) / 86400.0)
    except (TypeError, ValueError):
        return "unknown"
    if days < 1:
        return "today"
    if days <= 7:
        return "2-7-days"
    if days <= 30:
        return "8-30-days"
    if days <= 90:
        return "31-90-days"
    return "over-90-days"


def _encoded_blob(value):
    if not isinstance(value, str) or len(value) < 16:
        return False
    try:
        return len(base64.b64decode(value.encode("ascii"), validate=True)) >= 16
    except Exception:
        return False


def _load_raw_settings():
    if not locker.SETTINGS_FILE.is_file():
        return {}, True
    try:
        payload = json.loads(locker.SETTINGS_FILE.read_text(encoding="utf-8"))
        return (payload, True) if isinstance(payload, dict) else ({}, False)
    except Exception:
        return {}, False


def collect_class_rows(settings, now=None):
    source_map = _class_sources()
    rows = []
    for spec in DATA_CLASS_SPECS:
        mode = spec["mode"]
        stats = bounded_source_stats(source_map[spec["id"]]) if source_map[spec["id"]] else {"count": 0, "bytes": 0, "newest": 0.0, "capped": False, "errors": 0}
        configured = stats["count"] > 0
        if mode == "license":
            configured = bool(settings.get("license_state"))
        elif mode == "owner-controls":
            configured = bool(settings.get("owner_usb_policy") or settings.get("local_control_pin_verifier"))
        if mode in {"settings", "license", "owner-controls", "local-sources"}:
            state = "present" if configured else "not-configured"
        elif mode == "external":
            state = "not-inventoried"
        elif mode == "api":
            state = "api-boundary"
        else:
            state = "public"
        rows.append(
            {
                "id": spec["id"],
                "label": spec["label"],
                "scope_id": spec["scope_id"],
                "scope_label": _scope_label(spec["scope_id"]),
                "purpose": spec["purpose"],
                "protection": spec["protection"],
                "retention": spec["retention"],
                "customer_action": spec["customer_action"],
                "state": state,
                "count_band": count_band(stats["count"] if configured else 0),
                "size_band": size_band(stats["bytes"] if configured else 0),
                "age_band": age_band(stats["newest"], now) if configured else "none",
                "inventory_capped": bool(stats["capped"]),
                "metadata_errors": bool(stats["errors"]),
            }
        )
    return rows


def _check(identifier, category, title, passed, weight, good_detail, bad_detail, action):
    return {
        "id": identifier,
        "category": category,
        "title": title,
        "passed": bool(passed),
        "state": "good" if passed else "attention",
        "weight": int(weight),
        "detail": good_detail if passed else bad_detail,
        "action": action,
    }


def collect_control_checks(settings, settings_valid, now=None):
    now_value = float(now if now is not None else time.time())
    source_map = _class_sources()
    allowed_sources = [path for paths in source_map.values() for path in paths]
    boundary_ok = locker.APP_DIR.is_dir() and os.access(locker.APP_DIR, os.R_OK | os.W_OK)
    allowlist_ok = all(_inside_app_dir(path) and not _linklike(Path(path)) for path in allowed_sources)
    license_value = settings.get("license_state")
    license_ok = not license_value or _encoded_blob(license_value)
    owner_values = [settings.get("owner_usb_policy"), settings.get("local_control_pin_verifier")]
    owner_ok = all(not value or _encoded_blob(value) for value in owner_values)
    try:
        audit_valid, audit_count, _audit_message = locker.verify_audit_logs()
    except Exception:
        audit_valid, audit_count = False, 0
    audit_files_present = any(path.is_file() for path in [locker.LOG_FILE] + [locker.audit_backup_path(index) for index in range(1, locker.MAX_AUDIT_BACKUPS + 1)])
    audit_key_ok = not audit_files_present or (locker.AUDIT_KEY_FILE.is_file() and locker.AUDIT_KEY_FILE.stat().st_size >= 16)
    try:
        if locker.VAULT_FILE.is_file():
            with locker.VAULT_FILE.open("rb") as handle:
                vault_ok = handle.read(len(locker.VAULT_MAGIC)) == locker.VAULT_MAGIC
        else:
            vault_ok = True
    except OSError:
        vault_ok = False
    chain_results = []
    for loader in (kit_builder.load_snapshot_history, backup_center.load_checkpoint_history, drill_center.load_drill_history):
        try:
            _records, integrity = loader()
            chain_results.append(bool(integrity.get("valid")))
        except Exception:
            chain_results.append(False)
    histories_ok = all(chain_results)
    stale_temp = False
    if locker.TEMP_DIR.is_dir():
        try:
            for root, directories, files in os.walk(locker.TEMP_DIR, followlinks=False):
                root_path = Path(root)
                directories[:] = [
                    name
                    for name in directories
                    if not _linklike(root_path / name) and _inside_app_dir(root_path / name)
                ]
                for name in files:
                    path = root_path / name
                    if _linklike(path) or not _inside_app_dir(path):
                        continue
                    try:
                        if now_value - path.stat().st_mtime > locker.TEMP_DELETE_SECONDS:
                            stale_temp = True
                            break
                    except OSError:
                        stale_temp = True
                        break
                if stale_temp:
                    break
        except OSError:
            stale_temp = True
    checks = [
        _check("app-data-boundary", "Boundary", "Known app-data boundary", boundary_ok, 10, "VaultLink app data is readable and writable for this Windows user.", "The VaultLink app-data boundary is not fully available.", "Check Windows user permissions before relying on local state."),
        _check("allowlisted-inventory", "Boundary", "Allowlisted metadata inventory", allowlist_ok, 10, "Every inventoried source is an exact known location inside VaultLink app data.", "One or more inventory sources left the approved app-data boundary.", "Stop and review the Data Control source allowlist."),
        _check("settings-structure", "Settings", "Settings container structure", settings_valid, 8, "The local settings container has a valid object structure.", "The local settings container could not be parsed safely.", "Preserve it, use a known-good backup, and avoid manual edits."),
        _check("license-envelope", "Protection", "Protected license envelope", license_ok, 8, "The optional local license state is absent or stored as a protected binary envelope.", "The local license envelope is not in the expected protected form.", "Remove and reactivate through License Center after preserving evidence."),
        _check("owner-control-envelope", "Protection", "Protected owner controls", owner_ok, 8, "Optional owner and Local Control records are absent or protected binary envelopes.", "An owner-control record is not in the expected protected form.", "Reconfigure the affected control locally without reusing a secret."),
        _check("audit-chain", "Evidence", "Audit chain integrity", audit_valid, 12, f"The local audit chain verified across {int(audit_count)} bounded event(s).", "The local audit chain did not verify.", "Preserve the ledger and investigate the first failed anonymous event."),
        _check("audit-key", "Protection", "Audit integrity key", audit_key_ok, 8, "Audit records have the expected protected local integrity-key boundary.", "Audit records exist without a usable protected integrity-key file.", "Preserve the ledger and restore the matching app-data backup."),
        _check("vault-format", "Protection", "Personal Vault authenticated format", vault_ok, 8, "The optional Personal Vault is absent or begins with the supported authenticated format marker.", "The Personal Vault container does not have the expected format marker.", "Preserve the original and test only a copied container."),
        _check("recovery-chains", "Evidence", "Recovery history integrity", histories_ok, 12, "Recovery Kit, Backup Verification, and Recovery Drill histories are absent or valid.", "One or more fixed recovery histories failed integrity review.", "Preserve the affected history and do not append new results until reviewed."),
        _check("temporary-retention", "Retention", "Temporary workspace retention", not stale_temp, 8, "No temporary item was found beyond the expected cleanup window.", "At least one temporary item is older than the cleanup window.", "Close open working copies and use the explicit cleanup control."),
        _check("external-boundary", "Boundary", "External data stays outside inventory", True, 8, "USB keys, customer backups, and locked-container locations are not searched by this center.", "External inventory boundary changed.", "Restore the fixed no-search boundary before using this center."),
    ]
    return checks


def safe_online_metadata(payload):
    source = payload if isinstance(payload, dict) else {}
    service = source.get("service_status") if isinstance(source.get("service_status"), dict) else {}
    release = source.get("signed_release") if isinstance(source.get("signed_release"), dict) else {}

    def safe_version(value, fallback=""):
        text = str(value or "").strip()
        return text if VERSION_RE.fullmatch(text) else fallback

    mode = str(service.get("mode") or "unknown").strip().lower()

    return {
        "available": bool(source.get("ok")),
        "api_version": safe_version(source.get("api_version"), "Unavailable"),
        "service_mode": mode if mode in SERVICE_MODES else "unknown",
        "signed_desktop_version": safe_version(release.get("version")),
        "class_count": 14,
        "scope_count": 5,
        "accepts_inventory": False,
        "accepts_paths": False,
        "accepts_files": False,
        "accepts_progress": False,
    }


def safe_utc_text(value=""):
    text = str(value or locker.utc_now_text()).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("UTC offset required")
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError):
        raise ValueError("Data Control time must be a valid UTC timestamp.")


def build_data_control_report(rows, checks, online_payload=None, history=None, integrity=None, generated_at_utc=""):
    expected_ids = [item["id"] for item in DATA_CLASS_SPECS]
    row_map = {str(item.get("id")): item for item in rows or [] if isinstance(item, dict)}
    clean_rows = []
    for spec in DATA_CLASS_SPECS:
        source = row_map.get(spec["id"], {})
        state = str(source.get("state", "not-configured"))
        count_value = str(source.get("count_band", "none"))
        size_value = str(source.get("size_band", "none"))
        age_value = str(source.get("age_band", "none"))
        clean_rows.append(
            {
                "id": spec["id"],
                "label": spec["label"],
                "scope_id": spec["scope_id"],
                "scope_label": _scope_label(spec["scope_id"]),
                "purpose": spec["purpose"],
                "protection": spec["protection"],
                "retention": spec["retention"],
                "customer_action": spec["customer_action"],
                "state": state if state in VALID_STATES else "not-configured",
                "count_band": count_value if count_value in VALID_COUNT_BANDS else "none",
                "size_band": size_value if size_value in VALID_SIZE_BANDS else "none",
                "age_band": age_value if age_value in VALID_AGE_BANDS else "unknown",
                "inventory_capped": bool(source.get("inventory_capped")),
                "metadata_errors": bool(source.get("metadata_errors")),
            }
        )
    check_map = {str(item.get("id")): item for item in checks or [] if isinstance(item, dict)}
    clean_checks = []
    for identifier, category, title, weight in CONTROL_CHECKS:
        source = check_map.get(identifier, {})
        passed = bool(source.get("passed"))
        good_detail, bad_detail, action = CONTROL_MESSAGES[identifier]
        clean_checks.append(
            {
                "id": identifier,
                "category": category,
                "title": title,
                "passed": passed,
                "state": "good" if passed else "attention",
                "weight": weight,
                "detail": good_detail if passed else bad_detail,
                "action": action,
            }
        )
    score = sum(item["weight"] for item in clean_checks if item["passed"])
    history = list(history or [])
    integrity = integrity if isinstance(integrity, dict) else {"valid": True, "message": "No receipts saved yet."}
    present_count = sum(item["state"] == "present" for item in clean_rows)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": "VaultLink Local Data Control Report",
        "generated_at_utc": safe_utc_text(generated_at_utc),
        "data_classes": clean_rows,
        "class_count": len(expected_ids),
        "scope_count": len(SCOPE_SPECS),
        "summary": {
            "present_class_count": present_count,
            "not_configured_count": sum(item["state"] == "not-configured" for item in clean_rows),
            "external_boundary_count": sum(item["state"] == "not-inventoried" for item in clean_rows),
            "api_boundary_count": sum(item["state"] == "api-boundary" for item in clean_rows),
            "public_class_count": sum(item["state"] == "public" for item in clean_rows),
            "metadata_attention_count": sum(bool(item["metadata_errors"]) for item in clean_rows),
        },
        "posture": {
            "score": score,
            "maximum": 100,
            "label": "ready" if score >= 90 else "review" if score >= 70 else "attention",
            "passed": sum(item["passed"] for item in clean_checks),
            "total": len(clean_checks),
        },
        "checks": clean_checks,
        "online": safe_online_metadata(online_payload),
        "receipts": {
            "record_count": len(history),
            "integrity_valid": bool(integrity.get("valid")),
            "integrity_message": (
                f"Verified {len(history)} hash-chained Data Control receipt(s)."
                if integrity.get("valid")
                else "Receipt history needs review before another receipt is saved."
            ),
        },
        "privacy_notice": (
            "This report contains fixed class IDs, public descriptions, presence states, coarse count/size/age bands, "
            "fixed check results, public service metadata, and receipt integrity only. It excludes names, contacts, "
            "license proof, receipts, keys, PINs, paths, filenames, file contents, screenshots, process lists, and free-form notes."
        ),
        "sharing_warning": "Category presence can still be sensitive. Review this local export before sharing it.",
        "limitations": [
            "The map reads metadata only from exact known VaultLink app-data sources and never scans arbitrary customer folders.",
            "It cannot prove that every backup, USB key, locked container, or server record is complete or recoverable.",
            "It is not forensic discovery, legal advice, compliance certification, or a replacement for independent review.",
        ],
    }


def _canonical_receipt(record):
    payload = dict(record)
    payload.pop("hash", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def load_receipt_history(path=RECEIPT_HISTORY_PATH):
    path = Path(path)
    if not path.is_file():
        return [], {"valid": True, "message": "No Data Control receipts saved yet."}
    if _linklike(path):
        return [], {"valid": False, "message": "Receipt history cannot be a link or junction."}
    if path.stat().st_size > MAX_HISTORY_BYTES:
        return [], {"valid": False, "message": "Receipt history exceeds the fixed size limit."}
    records = []
    previous_hash = "0" * 64
    expected_ids = {item["id"] for item in DATA_CLASS_SPECS}
    expected_checks = {item[0] for item in CONTROL_CHECKS}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) > MAX_HISTORY_RECORDS:
            raise ValueError("Receipt history exceeds the fixed record limit.")
        for index, line in enumerate(lines, 1):
            record = json.loads(line)
            if not isinstance(record, dict) or set(record) != RECEIPT_FIELDS:
                raise ValueError(f"Receipt {index} does not match the fixed schema.")
            if record.get("schema_version") != 1:
                raise ValueError(f"Receipt {index} has an unsupported schema version.")
            if record["sequence"] != index or record["previous_hash"] != previous_hash:
                raise ValueError(f"Receipt {index} broke the hash chain.")
            if safe_utc_text(record.get("time_utc")) != record.get("time_utc"):
                raise ValueError(f"Receipt {index} has an invalid UTC time.")
            if not HEX_16_RE.fullmatch(str(record.get("event_id", ""))):
                raise ValueError(f"Receipt {index} has an invalid anonymous event ID.")
            if not HEX_64_RE.fullmatch(str(record.get("previous_hash", ""))) or not HEX_64_RE.fullmatch(str(record.get("hash", ""))):
                raise ValueError(f"Receipt {index} has an invalid integrity field.")
            if not isinstance(record.get("posture_score"), int) or not 0 <= record["posture_score"] <= 100:
                raise ValueError(f"Receipt {index} has an invalid posture score.")
            if record.get("class_count") != len(DATA_CLASS_SPECS) or not isinstance(record.get("present_class_count"), int) or not 0 <= record["present_class_count"] <= len(DATA_CLASS_SPECS):
                raise ValueError(f"Receipt {index} has invalid class totals.")
            states = record.get("class_states")
            if not isinstance(states, list) or {item.get("id") for item in states if isinstance(item, dict)} != expected_ids:
                raise ValueError(f"Receipt {index} does not contain the fixed data classes.")
            for item in states:
                if set(item) != {"id", "state", "count_band", "size_band", "age_band"}:
                    raise ValueError(f"Receipt {index} contains an unexpected class field.")
                if item["state"] not in VALID_STATES or item["count_band"] not in VALID_COUNT_BANDS or item["size_band"] not in VALID_SIZE_BANDS or item["age_band"] not in VALID_AGE_BANDS:
                    raise ValueError(f"Receipt {index} contains an invalid fixed value.")
            passed = record.get("passed_check_ids")
            if not isinstance(passed, list) or len(passed) != len(set(passed)) or not set(passed).issubset(expected_checks):
                raise ValueError(f"Receipt {index} contains an invalid check ID.")
            expected_hash = hashlib.sha256(_canonical_receipt(record)).hexdigest()
            if not secrets.compare_digest(str(record.get("hash", "")), expected_hash):
                raise ValueError(f"Receipt {index} failed its hash check.")
            records.append(record)
            previous_hash = expected_hash
    except Exception as exc:
        return records, {"valid": False, "message": str(exc)}
    return records, {"valid": True, "message": f"Verified {len(records)} hash-chained Data Control receipt(s)."}


def append_receipt(report, path=RECEIPT_HISTORY_PATH, time_utc=""):
    with RECEIPT_LOCK:
        return _append_receipt_locked(report, path, time_utc)


def _append_receipt_locked(report, path=RECEIPT_HISTORY_PATH, time_utc=""):
    path = Path(path)
    if _linklike(path):
        raise ValueError("Data Control receipt history cannot be a link or junction.")
    history, integrity = load_receipt_history(path)
    if not integrity["valid"]:
        raise ValueError("Data Control receipt integrity failed. Review it before saving another receipt.")
    rows = list(report.get("data_classes") or [])
    checks = list(report.get("checks") or [])
    expected_ids = {item["id"] for item in DATA_CLASS_SPECS}
    expected_checks = {item[0] for item in CONTROL_CHECKS}
    if len(rows) != len(expected_ids) or {item.get("id") for item in rows if isinstance(item, dict)} != expected_ids:
        raise ValueError("The Data Control receipt does not contain the fixed data classes.")
    for item in rows:
        if (
            item.get("state") not in VALID_STATES
            or item.get("count_band") not in VALID_COUNT_BANDS
            or item.get("size_band") not in VALID_SIZE_BANDS
            or item.get("age_band") not in VALID_AGE_BANDS
        ):
            raise ValueError("The Data Control receipt contains an invalid fixed class value.")
    if any(not isinstance(item, dict) or item.get("id") not in expected_checks for item in checks):
        raise ValueError("The Data Control receipt contains an invalid control check.")
    passed_check_ids = sorted({item["id"] for item in checks if item.get("passed")})
    weights = {identifier: weight for identifier, _category, _title, weight in CONTROL_CHECKS}
    posture_score = sum(weights[identifier] for identifier in passed_check_ids)
    record = {
        "schema_version": 1,
        "sequence": len(history) + 1,
        "time_utc": safe_utc_text(time_utc),
        "event_id": secrets.token_hex(8),
        "posture_score": posture_score,
        "class_count": len(expected_ids),
        "present_class_count": sum(item.get("state") == "present" for item in rows),
        "class_states": [
            {
                "id": item["id"],
                "state": item["state"],
                "count_band": item["count_band"],
                "size_band": item["size_band"],
                "age_band": item["age_band"],
            }
            for item in sorted(rows, key=lambda value: value["id"])
        ],
        "passed_check_ids": passed_check_ids,
        "previous_hash": history[-1]["hash"] if history else "0" * 64,
    }
    if not 0 <= record["posture_score"] <= 100 or record["class_count"] != len(DATA_CLASS_SPECS):
        raise ValueError("The Data Control receipt contains an invalid fixed value.")
    record["hash"] = hashlib.sha256(_canonical_receipt(record)).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return record


def collect_data_control_report(online_payload=None, now=None):
    settings, settings_valid = _load_raw_settings()
    rows = collect_class_rows(settings, now)
    checks = collect_control_checks(settings, settings_valid, now)
    history, integrity = load_receipt_history()
    return build_data_control_report(rows, checks, online_payload, history, integrity)


def collect_inputs():
    online = {}
    try:
        settings = locker.load_settings()
        state = locker.load_license_state(settings)
        server = locker.validated_license_server_url(state.get("server_url"))
        online = locker.license_api_get_json(server, DATA_MAP_ENDPOINT)
    except Exception:
        pass
    return collect_data_control_report(online)


def safe_report_text(report):
    lines = [
        "VAULTLINK LOCAL DATA CONTROL REPORT",
        "===================================",
        f"Generated UTC: {report['generated_at_utc']}",
        f"Data classes: {report['class_count']} across {report['scope_count']} fixed scopes",
        f"Posture: {report['posture']['score']}/100 ({report['posture']['label']})",
        f"Controls passed: {report['posture']['passed']}/{report['posture']['total']}",
        f"Receipt history: {report['receipts']['record_count']} | integrity: {'valid' if report['receipts']['integrity_valid'] else 'review'}",
        "",
        "DATA MAP",
        "--------",
    ]
    for item in report["data_classes"]:
        lines.extend(
            [
                f"{item['label']} | {item['scope_label']} | {item['state']}",
                f"  Storage: {item['count_band']} objects | {item['size_band']} | {item['age_band']}",
                f"  Purpose: {item['purpose']}",
                f"  Protection: {item['protection']}",
                f"  Retention: {item['retention']}",
                f"  Customer control: {item['customer_action']}",
            ]
        )
    lines.extend(["", "CONTROLS", "--------"])
    for item in report["checks"]:
        lines.extend([f"[{'PASS' if item['passed'] else 'REVIEW'}] {item['title']} ({item['weight']} points)", f"  {item['detail']}", f"  Action: {item['action']}"])
    lines.extend(["", "PRIVACY", "-------", report["privacy_notice"], report["sharing_warning"], "", "LIMITATIONS", "-----------"])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines)


def safe_summary(report):
    return "\n".join(
        [
            "VaultLink Local Data Control",
            f"Data classes: {report['class_count']} across {report['scope_count']} fixed scopes",
            f"Present local classes: {report['summary']['present_class_count']} | external no-search boundaries: {report['summary']['external_boundary_count']}",
            f"Posture: {report['posture']['score']}/100 | controls: {report['posture']['passed']}/{report['posture']['total']}",
            f"Receipt integrity: {'valid' if report['receipts']['integrity_valid'] else 'review'} | records: {report['receipts']['record_count']}",
            "No names, contacts, license proof, keys, PINs, paths, filenames, contents, screenshots, process lists, or notes are included.",
            "Review category presence before sharing this summary.",
        ]
    )


class LocalDataControlCenter(tk.Tk):
    def __init__(self):
        super().__init__()
        if not locker.ensure_license_feature("data-control-center", parent=self):
            self.after(0, self.destroy)
            return
        self.title("VaultLink Local Data Control Center")
        self.geometry("1240x920")
        self.minsize(1040, 760)
        self.configure(bg=locker.BG)
        self.results = queue.Queue()
        self.report = None
        self.scope_var = tk.StringVar(value="All scopes")
        self.state_var = tk.StringVar(value="All states")
        self.status_var = tk.StringVar(value="Ready to inspect fixed VaultLink data boundaries.")
        self.metric_vars = {name: tk.StringVar(value="--") for name in ("score", "classes", "present", "external", "receipts", "api")}
        self._build_ui()
        self.after(120, self.refresh_data)
        self.after(150, self.poll_results)

    def _build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=22, pady=18)
        tk.Label(outer, text="Local Data Control Center", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 25, "bold")).pack(anchor="w")
        tk.Label(outer, text="Review fixed storage boundaries, coarse local metadata, protection controls, retention, and privacy receipts without scanning customer folders.", bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 10), wraplength=1120, justify="left").pack(anchor="w", pady=(4, 14))

        toolbar = tk.Frame(outer, bg=locker.BG)
        toolbar.pack(fill="x", pady=(0, 12))
        actions = (
            ("REFRESH", self.refresh_data, locker.GREEN, locker.BLACK),
            ("SAVE RECEIPT", self.save_receipt, locker.YELLOW, locker.BLACK),
            ("COPY SUMMARY", self.copy_summary, "#27313d", locker.TEXT),
            ("EXPORT JSON", self.export_json, locker.BLUE, locker.BLACK),
            ("EXPORT TEXT", self.export_text, "#27313d", locker.TEXT),
            ("OPEN DATA FOLDER", self.open_data_folder, "#27313d", locker.TEXT),
            ("PUBLIC DATA MAP", self.open_public_map, "#27313d", locker.TEXT),
        )
        for index, (label, command, bg, fg) in enumerate(actions):
            tk.Button(toolbar, text=label, command=command, bg=bg, fg=fg, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(0 if index == 0 else 8, 0), ipadx=8, ipady=7)
        tk.Button(toolbar, text="CLOSE", command=self.destroy, bg="#27313d", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="right", ipadx=10, ipady=7)

        filters = tk.Frame(outer, bg=locker.PANEL, padx=12, pady=10, highlightbackground="#343b49", highlightthickness=1)
        filters.pack(fill="x", pady=(0, 12))
        tk.Label(filters, text="SCOPE", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        scope_values = ["All scopes"] + [label for _identifier, label in SCOPE_SPECS]
        scope_box = ttk.Combobox(filters, textvariable=self.scope_var, values=scope_values, state="readonly", width=28)
        scope_box.pack(side="left", padx=(8, 18))
        scope_box.bind("<<ComboboxSelected>>", lambda _event: self.populate())
        tk.Label(filters, text="STATE", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        state_values = ["All states", "Present", "Not configured", "Not inventoried", "API boundary", "Public"]
        state_box = ttk.Combobox(filters, textvariable=self.state_var, values=state_values, state="readonly", width=22)
        state_box.pack(side="left", padx=(8, 0))
        state_box.bind("<<ComboboxSelected>>", lambda _event: self.populate())

        metrics = tk.Frame(outer, bg=locker.BG)
        metrics.pack(fill="x", pady=(0, 12))
        for index, (key, label) in enumerate((("score", "POSTURE"), ("classes", "DATA CLASSES"), ("present", "PRESENT LOCAL"), ("external", "NO-SEARCH BOUNDARIES"), ("receipts", "RECEIPTS"), ("api", "API"))):
            cell = tk.Frame(metrics, bg=locker.PANEL, highlightbackground="#343b49", highlightthickness=1)
            cell.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 5, 0))
            tk.Label(cell, text=label, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 7, "bold")).pack(anchor="w", padx=10, pady=(8, 2))
            tk.Label(cell, textvariable=self.metric_vars[key], bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=10, pady=(0, 8))
            metrics.grid_columnconfigure(index, weight=1)

        style = ttk.Style(self)
        style.configure("DataControl.Treeview", background=locker.PANEL, fieldbackground=locker.PANEL, foreground=locker.TEXT, rowheight=28)
        style.configure("DataControl.Treeview.Heading", background="#27313d", foreground=locker.TEXT, font=("Segoe UI", 8, "bold"))

        split = tk.PanedWindow(outer, orient="horizontal", bg=locker.BG, sashwidth=6, relief="flat")
        split.pack(fill="both", expand=True)
        left = tk.Frame(split, bg=locker.BG)
        right = tk.Frame(split, bg=locker.BG)
        split.add(left, minsize=650, stretch="always")
        split.add(right, minsize=330, stretch="always")

        columns = ("state", "label", "scope", "size", "objects", "age")
        self.tree = ttk.Treeview(left, columns=columns, show="headings", style="DataControl.Treeview", height=15)
        widths = {"state": 110, "label": 210, "scope": 165, "size": 105, "objects": 90, "age": 100}
        for column in columns:
            self.tree.heading(column, text=column.upper())
            self.tree.column(column, width=widths[column], minwidth=70, stretch=column in {"label", "scope"})
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.show_selected)

        tk.Label(right, text="SELECTED DATA CLASS", bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
        self.detail = scrolledtext.ScrolledText(right, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", wrap="word", font=("Consolas", 9), height=18, state="disabled")
        self.detail.pack(fill="both", expand=True, pady=(6, 0))

        tk.Label(outer, text="PROTECTION CONTROLS", bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(12, 5))
        check_columns = ("state", "control", "points", "detail")
        self.check_tree = ttk.Treeview(outer, columns=check_columns, show="headings", style="DataControl.Treeview", height=6)
        for column, width in (("state", 90), ("control", 240), ("points", 70), ("detail", 720)):
            self.check_tree.heading(column, text=column.upper())
            self.check_tree.column(column, width=width, minwidth=60, stretch=column == "detail")
        self.check_tree.pack(fill="x")
        tk.Label(outer, textvariable=self.status_var, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9), wraplength=1120, justify="left").pack(anchor="w", pady=(10, 0))

    def refresh_data(self):
        self.status_var.set("Reading allowlisted VaultLink metadata and verifying fixed protection controls...")
        threading.Thread(target=self._collect_worker, name="VaultLink-DataControl", daemon=True).start()

    def _collect_worker(self):
        try:
            self.results.put(("report", collect_inputs()))
        except Exception as exc:
            self.results.put(("error", str(exc)))

    def poll_results(self):
        try:
            while True:
                kind, payload = self.results.get_nowait()
                if kind == "report":
                    self.report = payload
                    self.populate()
                    locker.log_event("data_control_center_refresh", "fixed_metadata", "ok")
                    self.status_var.set("Data map refreshed. External keys, backups, and locked-container locations were not searched.")
                else:
                    self.status_var.set(f"Data Control refresh failed: {payload}")
        except queue.Empty:
            pass
        self.after(150, self.poll_results)

    def _filtered_rows(self):
        if not self.report:
            return []
        selected_scope = self.scope_var.get()
        selected_state = self.state_var.get().lower().replace(" ", "-")
        rows = list(self.report["data_classes"])
        if selected_scope != "All scopes":
            rows = [item for item in rows if item["scope_label"] == selected_scope]
        if self.state_var.get() != "All states":
            rows = [item for item in rows if item["state"] == selected_state]
        return rows

    def populate(self):
        if not self.report:
            return
        for item in self.tree.get_children():
            self.tree.delete(item)
        for row in self._filtered_rows():
            self.tree.insert("", "end", iid=row["id"], values=(row["state"], row["label"], row["scope_label"], row["size_band"], row["count_band"], row["age_band"]))
        for item in self.check_tree.get_children():
            self.check_tree.delete(item)
        for check in self.report["checks"]:
            self.check_tree.insert("", "end", values=("PASS" if check["passed"] else "REVIEW", check["title"], check["weight"], check["detail"]))
        summary = self.report["summary"]
        posture = self.report["posture"]
        self.metric_vars["score"].set(f"{posture['score']} / 100")
        self.metric_vars["classes"].set(str(self.report["class_count"]))
        self.metric_vars["present"].set(str(summary["present_class_count"]))
        self.metric_vars["external"].set(str(summary["external_boundary_count"]))
        self.metric_vars["receipts"].set(str(self.report["receipts"]["record_count"]))
        self.metric_vars["api"].set(self.report["online"]["api_version"])
        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children[0])
            self.tree.focus(children[0])
            self.show_selected()
        else:
            self._set_detail("No fixed data classes match the selected filters.")

    def _set_detail(self, text):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    def show_selected(self, _event=None):
        if not self.report or not self.tree.selection():
            return
        identifier = self.tree.selection()[0]
        row = next((item for item in self.report["data_classes"] if item["id"] == identifier), None)
        if not row:
            return
        self._set_detail(
            "\n".join(
                [
                    row["label"],
                    "=" * len(row["label"]),
                    f"State: {row['state']}",
                    f"Scope: {row['scope_label']}",
                    f"Objects: {row['count_band']} | Size: {row['size_band']} | Age: {row['age_band']}",
                    "",
                    "PURPOSE",
                    row["purpose"],
                    "",
                    "PROTECTION",
                    row["protection"],
                    "",
                    "RETENTION",
                    row["retention"],
                    "",
                    "CUSTOMER CONTROL",
                    row["customer_action"],
                    "",
                    "This view contains no path, filename, key, PIN, receipt, content, or free-form note.",
                ]
            )
        )

    def save_receipt(self):
        if not self.report:
            return
        try:
            append_receipt(self.report)
            locker.log_event("data_control_receipt_save", "fixed_snapshot", "ok")
            self.status_var.set("Saved a hash-chained fixed-schema Data Control receipt locally.")
            self.refresh_data()
        except Exception as exc:
            messagebox.showerror("Could not save receipt", str(exc), parent=self)

    def copy_summary(self):
        if not self.report:
            return
        self.clipboard_clear()
        self.clipboard_append(safe_summary(self.report))
        locker.log_event("data_control_summary_copy", "privacy_safe", "ok")
        self.status_var.set("Copied the reviewed privacy-safe summary.")

    def export_json(self):
        if not self.report:
            return
        destination = filedialog.asksaveasfilename(parent=self, title="Export Local Data Control JSON", defaultextension=".json", initialfile="vaultlink-local-data-control.json", filetypes=(("JSON", "*.json"),))
        if not destination:
            return
        Path(destination).write_text(json.dumps(self.report, indent=2), encoding="utf-8")
        locker.log_event("data_control_export_json", "privacy_safe", "ok")
        self.status_var.set("Exported reviewed Data Control JSON. Category presence can still be sensitive.")

    def export_text(self):
        if not self.report:
            return
        destination = filedialog.asksaveasfilename(parent=self, title="Export Local Data Control Text", defaultextension=".txt", initialfile="vaultlink-local-data-control.txt", filetypes=(("Text", "*.txt"),))
        if not destination:
            return
        Path(destination).write_text(safe_report_text(self.report), encoding="utf-8")
        locker.log_event("data_control_export_text", "privacy_safe", "ok")
        self.status_var.set("Exported reviewed Data Control text. Category presence can still be sensitive.")

    def open_data_folder(self):
        os.startfile(locker.APP_DIR)
        locker.log_event("data_control_folder_open", "local_app_data", "ok")
        self.status_var.set("Opened the local VaultLink app-data folder.")

    def open_public_map(self):
        try:
            settings = locker.load_settings()
            state = locker.load_license_state(settings)
            server = locker.validated_license_server_url(state.get("server_url"))
            webbrowser.open(server.rstrip("/") + "/data-control", new=2)
            locker.log_event("data_control_online_open", "public_workspace", "ok")
            self.status_var.set("Opened the public fixed data map.")
        except Exception as exc:
            messagebox.showerror("Could not open public Data Control", str(exc), parent=self)


if __name__ == "__main__":
    LocalDataControlCenter().mainloop()
