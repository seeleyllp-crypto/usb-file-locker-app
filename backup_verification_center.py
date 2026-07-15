import hashlib
import json
import os
import queue
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

import diagnostics_center as diagnostics
import trust_recovery_center as trust
import usb_file_locker as locker


REPORT_SCHEMA_VERSION = 1
CENTER_ENDPOINT = "/api/v1/backup-verification"
HISTORY_PATH = locker.APP_DIR / "backup_verification_history.jsonl"
SETTINGS_PATH = locker.APP_DIR / "backup_verification_settings.json"
MAX_HISTORY_RECORDS = 500
MAX_HISTORY_BYTES = 2 * 1024 * 1024
ALLOWED_INTERVAL_DAYS = (7, 14, 30, 60, 90)
COPY_TARGETS = (1, 2, 3, 4, 5)

RESTORE_OBJECTIVES = (
    {"id": "15-minutes", "label": "Critical access in 15 minutes", "minutes": 15},
    {"id": "1-hour", "label": "Critical access in 1 hour", "minutes": 60},
    {"id": "4-hours", "label": "Working recovery in 4 hours", "minutes": 240},
    {"id": "1-day", "label": "Working recovery in 1 day", "minutes": 1440},
    {"id": "3-days", "label": "Full recovery in 3 days", "minutes": 4320},
)

PLAN_SPECS = (
    ("master-key-copies", "Keys", "Master-key copy verification", "independent master-key copies without exposing key bytes"),
    ("optional-pin-custody", "Keys", "Optional-PIN custody plan", "exact optional-PIN recovery without recording the PIN"),
    ("locked-file-copies", "Locked Data", "Locked-file backup sets", "encrypted-container copies while originals remain unchanged"),
    ("app-data-backup", "App Data", "VaultLink app-data backup", "settings, audit records, and personal-vault data without key files"),
    ("audit-evidence", "App Data", "Audit evidence continuity", "verified privacy-safe audit evidence and offline copies"),
    ("signed-app-rollback", "Application", "Signed app and rollback copies", "verified transparent app files and rollback copies"),
    ("new-device-recovery", "Devices", "New-device recovery order", "a replacement PC using signed software and disposable validation"),
    ("lost-device-continuity", "Devices", "Lost-device continuity", "account, license-seat, key, app-data, and encrypted-copy recovery"),
    ("family-handoff", "People", "Trusted-family handoff", "a trusted adult who can follow the restore order"),
    ("small-office-continuity", "Business", "Small-office continuity pack", "a synthetic office recovery with no client data"),
    ("ransomware-safe-backups", "Security", "Ransomware-safe backup decisions", "tabletop isolation and preservation without malware or file changes"),
    ("full-restore-rehearsal", "Recovery", "Full disposable restore rehearsal", "signed software, app data, key custody, and copied test data"),
)

PLAN_STAGES = (
    ("inventory", "Inventory the required pieces", "Count the required recovery pieces without listing paths, filenames, secrets, or contents.", "The recovery scope is understood."),
    ("separate", "Separate failure domains", "Keep the only copies away from the same PC and separate unlocking material from encrypted data.", "One lost location cannot remove every recovery part."),
    ("verify", "Verify the backup structure", "Use the appropriate read-only VaultLink check and record only a coarse pass or attention state.", "The selected backup type has a recognized structure."),
    ("test", "Run a disposable recovery test", "Use non-private copied test data and never delete or overwrite the original during verification.", "A safe copied recovery path completes."),
    ("schedule", "Schedule the next checkpoint", "Choose a fixed review interval and save only the approved coarse checkpoint fields.", "The backup plan has a next review date."),
)

READINESS_CHECKS = (
    ("defender-protection", "Security", "Microsoft Defender protection", 10),
    ("defender-signatures", "Security", "Defender signatures current", 5),
    ("audit-chain", "Evidence", "Local audit integrity", 10),
    ("owner-usb-policy", "Keys", "Owner USB policy", 10),
    ("selected-key", "Keys", "Selected USB key available", 15),
    ("recovery-test", "Recovery", "Disposable recovery test recorded", 10),
    ("app-data-backup", "Backup", "App-data backup verified", 10),
    ("signed-release", "Application", "Verified signed release", 10),
    ("app-data-access", "Storage", "App-data access", 5),
    ("free-space", "Storage", "Working disk space", 5),
    ("settings-read", "Application", "Settings readable", 5),
    ("cryptography-package", "Application", "Encryption dependency", 5),
)


def local_backup_plans():
    plans = []
    for plan_id, category, title, focus in PLAN_SPECS:
        steps = []
        for stage_id, stage_title, action, expected in PLAN_STAGES:
            steps.append(
                {
                    "id": f"{plan_id}-{stage_id}",
                    "title": stage_title,
                    "action": f"For {focus}, {action[0].lower() + action[1:]}",
                    "expected": expected,
                }
            )
        plans.append(
            {
                "id": plan_id,
                "category": category,
                "title": title,
                "summary": f"Prepare {focus}.",
                "steps": steps,
                "success": f"The {title.lower()} was reviewed with disposable data and no private details were recorded.",
            }
        )
    return plans


LOCAL_PLANS = local_backup_plans()
VALID_PLAN_IDS = frozenset(item["id"] for item in LOCAL_PLANS)
VALID_OBJECTIVE_IDS = frozenset(item["id"] for item in RESTORE_OBJECTIVES)
VALID_CHECK_IDS = frozenset(item[0] for item in READINESS_CHECKS)
CHECKPOINT_FIELDS = frozenset(
    {
        "schema_version",
        "sequence",
        "time_utc",
        "event_id",
        "plan_id",
        "result",
        "completed_count",
        "total_steps",
        "readiness_score",
        "ready_check_ids",
        "objective_id",
        "copy_target",
        "previous_hash",
        "hash",
    }
)


def _fallback_guide(message="Online backup verification catalog unavailable."):
    return {
        "ok": False,
        "backup_verification_schema_version": 1,
        "api_version": "Unavailable",
        "service_status": {"mode": "unknown", "message": message, "updated_at_utc": ""},
        "signed_release": {"ready": False, "version": "", "minimum_supported_version": ""},
        "plans": json.loads(json.dumps(LOCAL_PLANS)),
        "restore_objectives": json.loads(json.dumps(RESTORE_OBJECTIVES)),
        "privacy_boundaries": [
            "The public API serves only fixed plans and never receives customer progress, local check results, backup paths, or history.",
            "Desktop checkpoints store only fixed IDs, coarse totals, readiness scores, objective, copy target, timestamps, and hash-chain fields.",
            "No key, PIN, receipt, identity, path, filename, screenshot, process list, file content, or free-form note is stored or uploaded.",
        ],
        "limitations": [
            "A recognized backup folder and passing checkpoint cannot guarantee that every future restore will succeed.",
            "Ransomware planning is tabletop guidance only; never run malware, destructive scripts, or file-encryption simulations.",
            "Use Microsoft Defender and qualified recovery help for active compromise, damaged storage, identity exposure, or important business data.",
        ],
        "server_time_utc": "",
        "accepts_free_text": False,
        "accepts_files": False,
        "accepts_progress": False,
        "customer_records_included": False,
    }


def safe_backup_guide(payload):
    source = payload if isinstance(payload, dict) else {}
    fallback = _fallback_guide()
    if not source.get("ok"):
        return fallback

    def clean(value, default="", limit=320):
        return trust.safe_online_text(value, default, limit)

    def clean_list(values, default):
        if not isinstance(values, (list, tuple)):
            return list(default)
        cleaned = [clean(value) for value in values[:20]]
        return [value for value in cleaned if value] or list(default)

    plans = []
    raw_plans = source.get("plans")
    if isinstance(raw_plans, (list, tuple)):
        for raw in raw_plans[:16]:
            if not isinstance(raw, dict):
                continue
            steps = []
            for step in raw.get("steps", [])[:8] if isinstance(raw.get("steps"), (list, tuple)) else []:
                if not isinstance(step, dict):
                    continue
                steps.append(
                    {
                        "id": clean(step.get("id"), "step", 90),
                        "title": clean(step.get("title"), "Backup step", 160),
                        "action": clean(step.get("action"), "Review this fixed step locally."),
                        "expected": clean(step.get("expected"), "Record whether the fixed step is complete."),
                    }
                )
            if steps:
                plans.append(
                    {
                        "id": clean(raw.get("id"), "other", 90),
                        "category": clean(raw.get("category"), "Other", 80),
                        "title": clean(raw.get("title"), "Backup plan", 160),
                        "summary": clean(raw.get("summary"), "Use the fixed backup-verification steps."),
                        "steps": steps,
                        "success": clean(raw.get("success"), "The fixed backup steps were reviewed."),
                    }
                )
    if not plans:
        plans = fallback["plans"]

    objectives = []
    for item in source.get("restore_objectives", [])[:8] if isinstance(source.get("restore_objectives"), (list, tuple)) else []:
        if not isinstance(item, dict):
            continue
        identifier = clean(item.get("id"), "", 40)
        if identifier not in VALID_OBJECTIVE_IDS:
            continue
        objectives.append(
            {
                "id": identifier,
                "label": clean(item.get("label"), "Restore objective", 120),
                "minutes": int(item.get("minutes", 0)),
            }
        )
    if len(objectives) != len(RESTORE_OBJECTIVES):
        objectives = fallback["restore_objectives"]

    service = source.get("service_status") if isinstance(source.get("service_status"), dict) else {}
    release = source.get("signed_release") if isinstance(source.get("signed_release"), dict) else {}
    return {
        "ok": True,
        "backup_verification_schema_version": 1,
        "api_version": clean(source.get("api_version"), "Unknown", 80),
        "service_status": {
            "mode": clean(service.get("mode"), "unknown", 40),
            "message": clean(service.get("message"), "No public service message."),
            "updated_at_utc": clean(service.get("updated_at_utc"), "", 40),
        },
        "signed_release": {
            "ready": bool(release.get("ready")),
            "version": clean(release.get("version"), "", 40),
            "minimum_supported_version": clean(release.get("minimum_supported_version"), "", 40),
        },
        "plans": plans,
        "restore_objectives": objectives,
        "privacy_boundaries": clean_list(source.get("privacy_boundaries"), fallback["privacy_boundaries"]),
        "limitations": clean_list(source.get("limitations"), fallback["limitations"]),
        "server_time_utc": clean(source.get("server_time_utc"), "", 40),
        "accepts_free_text": False,
        "accepts_files": False,
        "accepts_progress": False,
        "customer_records_included": False,
    }


def _canonical_record(record):
    payload = dict(record)
    payload.pop("hash", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _is_lower_hex(value, length):
    text = str(value or "")
    return len(text) == length and all(character in "0123456789abcdef" for character in text)


def _validate_checkpoint_record(record, sequence, previous_hash):
    if not isinstance(record, dict) or set(record) != CHECKPOINT_FIELDS or record.get("schema_version") != 1:
        raise ValueError(f"Backup checkpoint {sequence} has an invalid fixed schema.")
    if type(record.get("sequence")) is not int or record["sequence"] != sequence:
        raise ValueError(f"Backup checkpoint {sequence} has an invalid sequence.")
    if record.get("previous_hash") != previous_hash or not _is_lower_hex(record.get("previous_hash"), 64):
        raise ValueError(f"Backup checkpoint {sequence} broke the hash chain.")
    if not _is_lower_hex(record.get("hash"), 64) or not _is_lower_hex(record.get("event_id"), 16):
        raise ValueError(f"Backup checkpoint {sequence} has an invalid fixed identifier.")
    time_utc = str(record.get("time_utc") or "")
    if len(time_utc) > 40 or locker.parse_utc_text(time_utc) is None:
        raise ValueError(f"Backup checkpoint {sequence} has an invalid timestamp.")
    if record.get("plan_id") not in VALID_PLAN_IDS or record.get("objective_id") not in VALID_OBJECTIVE_IDS:
        raise ValueError(f"Backup checkpoint {sequence} contains an unknown fixed value.")
    completed_count = record.get("completed_count")
    total_steps = record.get("total_steps")
    readiness_score = record.get("readiness_score")
    copy_target = record.get("copy_target")
    if any(type(value) is not int for value in (completed_count, total_steps, readiness_score, copy_target)):
        raise ValueError(f"Backup checkpoint {sequence} has an invalid numeric value.")
    if not 0 < total_steps <= 8 or not 0 <= completed_count <= total_steps or not 0 <= readiness_score <= 100:
        raise ValueError(f"Backup checkpoint {sequence} has an out-of-range fixed value.")
    expected_result = "complete" if completed_count == total_steps else "partial"
    if record.get("result") != expected_result:
        raise ValueError(f"Backup checkpoint {sequence} has an invalid result.")
    ready_ids = record.get("ready_check_ids")
    if (
        not isinstance(ready_ids, list)
        or any(not isinstance(value, str) for value in ready_ids)
        or ready_ids != sorted(set(ready_ids))
        or not set(ready_ids).issubset(VALID_CHECK_IDS)
    ):
        raise ValueError(f"Backup checkpoint {sequence} has invalid fixed check states.")
    if copy_target not in COPY_TARGETS:
        raise ValueError(f"Backup checkpoint {sequence} has an invalid copy target.")


def load_checkpoint_history(path=HISTORY_PATH):
    path = Path(path)
    if not path.is_file():
        return [], {"valid": True, "message": "No backup verification checkpoints have been saved yet."}
    try:
        if path.stat().st_size > MAX_HISTORY_BYTES:
            raise ValueError("Backup checkpoint history is larger than the safety limit.")
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) > MAX_HISTORY_RECORDS:
            raise ValueError("Backup checkpoint history exceeds the 500-record safety limit.")
        previous_hash = "0" * 64
        records = []
        for sequence, line in enumerate(lines, 1):
            record = json.loads(line)
            _validate_checkpoint_record(record, sequence, previous_hash)
            expected = hashlib.sha256(_canonical_record(record)).hexdigest()
            if not secrets.compare_digest(str(record.get("hash", "")), expected):
                raise ValueError(f"Backup checkpoint {sequence} failed its hash check.")
            records.append(record)
            previous_hash = expected
        return records, {"valid": True, "message": f"Verified {len(records)} hash-chained backup checkpoint(s)."}
    except Exception as exc:
        return [], {"valid": False, "message": str(exc)[:300]}


def append_checkpoint(plan_id, completed_count, total_steps, readiness_score, ready_check_ids, objective_id, copy_target, path=HISTORY_PATH, time_utc=""):
    plan_id = str(plan_id or "")
    objective_id = str(objective_id or "")
    completed_count = int(completed_count)
    total_steps = int(total_steps)
    readiness_score = int(readiness_score)
    copy_target = int(copy_target)
    ready_ids = sorted(set(str(value) for value in (ready_check_ids or [])))
    if plan_id not in VALID_PLAN_IDS or objective_id not in VALID_OBJECTIVE_IDS:
        raise ValueError("Choose a fixed backup plan and restore objective before saving.")
    if not 0 < total_steps <= 8 or not 0 <= completed_count <= total_steps:
        raise ValueError("Backup step totals are outside the allowed range.")
    if not 0 <= readiness_score <= 100 or not set(ready_ids).issubset(VALID_CHECK_IDS):
        raise ValueError("The backup readiness checkpoint contains an invalid fixed value.")
    if copy_target not in COPY_TARGETS:
        raise ValueError("Choose a copy target from one through five.")
    path = Path(path)
    records, integrity = load_checkpoint_history(path)
    if not integrity["valid"]:
        raise ValueError("Backup checkpoint integrity failed. Preserve the file and review it before adding records.")
    if len(records) >= MAX_HISTORY_RECORDS:
        raise ValueError("Backup checkpoint history reached its 500-record safety limit. Export and archive it first.")
    record = {
        "schema_version": 1,
        "sequence": len(records) + 1,
        "time_utc": time_utc or locker.utc_now_text(),
        "event_id": secrets.token_hex(8),
        "plan_id": plan_id,
        "result": "complete" if completed_count == total_steps else "partial",
        "completed_count": completed_count,
        "total_steps": total_steps,
        "readiness_score": readiness_score,
        "ready_check_ids": ready_ids,
        "objective_id": objective_id,
        "copy_target": copy_target,
        "previous_hash": records[-1]["hash"] if records else "0" * 64,
    }
    record["hash"] = hashlib.sha256(_canonical_record(record)).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    return record


def load_center_settings(path=SETTINGS_PATH):
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except Exception:
        raw = {}
    try:
        interval = int(raw.get("interval_days", 30))
        copy_target = int(raw.get("copy_target", 2))
    except (TypeError, ValueError):
        interval, copy_target = 30, 2
    objective_id = str(raw.get("objective_id", "4-hours"))
    return {
        "interval_days": interval if interval in ALLOWED_INTERVAL_DAYS else 30,
        "copy_target": copy_target if copy_target in COPY_TARGETS else 2,
        "objective_id": objective_id if objective_id in VALID_OBJECTIVE_IDS else "4-hours",
    }


def save_center_settings(interval_days, objective_id, copy_target, path=SETTINGS_PATH):
    interval_days = int(interval_days)
    copy_target = int(copy_target)
    objective_id = str(objective_id or "")
    if interval_days not in ALLOWED_INTERVAL_DAYS or copy_target not in COPY_TARGETS or objective_id not in VALID_OBJECTIVE_IDS:
        raise ValueError("Choose only the fixed interval, restore objective, and copy-target values.")
    payload = {"schema_version": 1, "interval_days": interval_days, "objective_id": objective_id, "copy_target": copy_target}
    locker.write_text_atomic(Path(path), json.dumps(payload, indent=2))
    return payload


def _next_due(records, interval_days):
    if not records:
        return "Not scheduled until the first saved checkpoint"
    latest = locker.parse_utc_text(records[-1].get("time_utc"))
    if not latest:
        return "Unknown"
    return (latest + timedelta(days=int(interval_days))).strftime("%Y-%m-%dT%H:%M:%SZ")


def _comparison(records):
    if len(records) < 2:
        return {"available": False, "score_delta": 0, "gained_check_ids": [], "lost_check_ids": []}
    previous, current = records[-2], records[-1]
    old_ids = set(previous.get("ready_check_ids", []))
    new_ids = set(current.get("ready_check_ids", []))
    return {
        "available": True,
        "score_delta": int(current.get("readiness_score", 0)) - int(previous.get("readiness_score", 0)),
        "gained_check_ids": sorted(new_ids - old_ids),
        "lost_check_ids": sorted(old_ids - new_ids),
    }


def build_backup_report(diagnostic_report, online_guide, selected_plan_id="", completed_step_ids=None, history=None, integrity=None, settings=None, session_backup_verified=False, verified_file_count=0, generated_at_utc=""):
    diagnostic_report = diagnostic_report if isinstance(diagnostic_report, dict) else {}
    guide = safe_backup_guide(online_guide)
    settings = dict(settings or load_center_settings())
    check_map = {str(item.get("id")): item for item in diagnostic_report.get("checks", []) if isinstance(item, dict) and item.get("id")}
    checks = []
    for identifier, category, title, weight in READINESS_CHECKS:
        source = check_map.get(identifier, {})
        passed = bool(source.get("passed"))
        detail = source.get("detail")
        action = source.get("action")
        if identifier == "app-data-backup" and session_backup_verified:
            passed = True
            detail = f"A selected backup folder was recognized in this session with {max(0, int(verified_file_count))} restorable file(s)."
            action = "Keep at least one independent protected copy and verify it again on schedule."
        checks.append(
            {
                "id": identifier,
                "category": category,
                "title": title,
                "state": "ready" if passed else "attention",
                "passed": passed,
                "weight": weight,
                "detail": trust.safe_online_text(detail, "This readiness result is unavailable.", 320),
                "action": trust.safe_online_text(action, "Run Diagnostics Center and review the failed fixed check.", 320),
            }
        )
    score = sum(item["weight"] for item in checks if item["passed"])
    label = "ready" if score >= 90 else "prepared" if score >= 70 else "attention" if score >= 50 else "action"
    plans = guide["plans"]
    selected = next((item for item in plans if item["id"] == selected_plan_id), plans[0])
    valid_steps = {item["id"] for item in selected["steps"]}
    completed = sorted(valid_steps.intersection(str(value) for value in (completed_step_ids or [])))
    history = list(history or [])
    integrity = integrity if isinstance(integrity, dict) else {"valid": True, "message": "No history loaded."}
    recent = []
    for item in history[-25:]:
        if not isinstance(item, dict) or item.get("plan_id") not in VALID_PLAN_IDS:
            continue
        recent.append(
            {
                "sequence": int(item.get("sequence", 0)),
                "time_utc": str(item.get("time_utc", ""))[:40],
                "event_id": str(item.get("event_id", ""))[:32],
                "plan_id": str(item.get("plan_id", ""))[:90],
                "result": str(item.get("result", ""))[:20],
                "completed_count": int(item.get("completed_count", 0)),
                "total_steps": int(item.get("total_steps", 0)),
                "readiness_score": int(item.get("readiness_score", 0)),
                "ready_check_ids": sorted(set(item.get("ready_check_ids", []))).copy(),
                "objective_id": str(item.get("objective_id", ""))[:40],
                "copy_target": int(item.get("copy_target", 0)),
                "previous_hash": str(item.get("previous_hash", ""))[:64],
                "hash": str(item.get("hash", ""))[:64],
            }
        )
    objective_id = settings.get("objective_id") if settings.get("objective_id") in VALID_OBJECTIVE_IDS else "4-hours"
    objective = next(item for item in RESTORE_OBJECTIVES if item["id"] == objective_id)
    copy_target = int(settings.get("copy_target", 2))
    interval = int(settings.get("interval_days", 30))
    generated = generated_at_utc or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": "VaultLink Privacy-Safe Backup Verification Report",
        "generated_at_utc": generated,
        "desktop_version": locker.DESKTOP_APP_VERSION,
        "runtime": "owner_lab" if locker.LAB_MODE else "customer",
        "readiness": {
            "value": score,
            "maximum": 100,
            "label": label,
            "passed": sum(item["passed"] for item in checks),
            "total": len(checks),
            "attention": sum(not item["passed"] for item in checks),
            "ready_check_ids": [item["id"] for item in checks if item["passed"]],
        },
        "checks": checks,
        "selected_plan": {
            "id": selected["id"],
            "category": selected["category"],
            "title": selected["title"],
            "summary": selected["summary"],
            "steps": selected["steps"],
            "success": selected["success"],
            "completed_step_ids": completed,
            "completed_count": len(completed),
            "total_steps": len(selected["steps"]),
        },
        "restore_target": {"objective_id": objective["id"], "label": objective["label"], "minutes": objective["minutes"], "copy_target": copy_target},
        "session_backup_verification": {"verified": bool(session_backup_verified), "restorable_file_count": max(0, int(verified_file_count))},
        "history": {
            "integrity_valid": bool(integrity.get("valid")),
            "integrity_message": str(integrity.get("message") or "History status unavailable.")[:300],
            "record_count": len(history),
            "interval_days": interval,
            "next_due_utc": _next_due(history, interval),
            "comparison": _comparison(history),
            "recent_records": recent,
        },
        "online_catalog": {
            "available": bool(guide.get("ok")),
            "api_version": guide.get("api_version", "Unavailable"),
            "service_mode": guide.get("service_status", {}).get("mode", "unknown"),
            "signed_release_ready": bool(guide.get("signed_release", {}).get("ready")),
            "signed_release_version": guide.get("signed_release", {}).get("version", ""),
            "plan_count": len(plans),
            "step_count": sum(len(item["steps"]) for item in plans),
        },
        "privacy_notice": (
            "This report excludes license keys, receipts, identities, machine identity, passwords, PINs, USB secrets, "
            "backup paths, filenames, screenshots, process lists, private file contents, and free-form notes. Checkpoints stay local."
        ),
        "limitations": list(guide.get("limitations") or _fallback_guide()["limitations"]),
    }


def collect_backup_inputs():
    diagnostic_report = diagnostics.collect_diagnostics_report()
    guide = _fallback_guide()
    try:
        app_settings = locker.load_settings()
        state = locker.load_license_state(app_settings)
        server = locker.validated_license_server_url(state.get("server_url"))
        guide = safe_backup_guide(locker.license_api_get_json(server, CENTER_ENDPOINT))
    except Exception:
        pass
    history, integrity = load_checkpoint_history()
    return diagnostic_report, guide, history, integrity, load_center_settings()


def safe_backup_text(report):
    readiness = report["readiness"]
    plan = report["selected_plan"]
    history = report["history"]
    target = report["restore_target"]
    comparison = history["comparison"]
    completed = set(plan["completed_step_ids"])
    lines = [
        f"BACKUP READINESS     {readiness['value']} / {readiness['maximum']}  {readiness['label'].upper()}",
        f"READINESS CHECKS     {readiness['passed']} / {readiness['total']} PASSED",
        f"BACKUP PLAN          {plan['title']}",
        f"PLAN PROGRESS        {plan['completed_count']} / {plan['total_steps']}",
        f"RESTORE OBJECTIVE    {target['label']}",
        f"COPY TARGET          {target['copy_target']}",
        f"LOCAL CHECKPOINTS    {history['record_count']} | {'VALID' if history['integrity_valid'] else 'CHECK'}",
        f"NEXT DUE             {history['next_due_utc']}",
        f"GENERATED            {report['generated_at_utc']}",
        "",
    ]
    if comparison["available"]:
        lines.extend(
            [
                "CHECKPOINT COMPARISON",
                "---------------------",
                f"Score change: {comparison['score_delta']:+d}",
                f"Checks gained: {', '.join(comparison['gained_check_ids']) or 'none'}",
                f"Checks lost: {', '.join(comparison['lost_check_ids']) or 'none'}",
                "",
            ]
        )
    lines.extend(["READINESS", "---------"])
    for item in report["checks"]:
        lines.extend([f"[{item['state'].upper():9}] {item['category']} | {item['title']} ({item['weight']} points)", f"  {item['detail']}"])
        if not item["passed"]:
            lines.append(f"  NEXT: {item['action']}")
        lines.append("")
    lines.extend(["RESTORE ORDER", "-------------", plan["summary"], ""])
    for index, step in enumerate(plan["steps"], 1):
        marker = "X" if step["id"] in completed else " "
        lines.extend([f"[{marker}] STEP {index}: {step['title']}", f"    {step['action']}", f"    EXPECTED: {step['expected']}", ""])
    lines.extend([f"SUCCESS: {plan['success']}", "", "PRIVACY", "-------", report["privacy_notice"], "", "LIMITATIONS", "-----------"])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines)


def safe_backup_summary(report):
    readiness = report["readiness"]
    plan = report["selected_plan"]
    history = report["history"]
    target = report["restore_target"]
    return "\n".join(
        [
            f"VaultLink backup readiness: {readiness['value']}/100 ({readiness['label']})",
            f"Fixed checks: {readiness['passed']}/{readiness['total']} ready",
            f"Plan: {plan['title']} ({plan['completed_count']}/{plan['total_steps']} steps)",
            f"Restore objective: {target['label']} | copy target: {target['copy_target']}",
            f"Local checkpoints: {history['record_count']} | integrity: {'valid' if history['integrity_valid'] else 'review'}",
            f"Next checkpoint: {history['next_due_utc']}",
            "No keys, PINs, paths, filenames, file contents, identity, receipts, or free-form notes are included.",
        ]
    )


class BackupVerificationCenter(tk.Tk):
    def __init__(self):
        super().__init__()
        if not locker.ensure_license_feature("backup-verification-center", parent=self):
            self.after(0, self.destroy)
            return
        self.title("VaultLink Backup Verification Center")
        self.geometry("1180x900")
        self.minsize(1040, 790)
        self.configure(bg=locker.BG)
        self.results = queue.Queue()
        self.diagnostic_report = {}
        self.guide = _fallback_guide()
        self.history = []
        self.integrity = {"valid": True, "message": "No history loaded."}
        self.settings = load_center_settings()
        self.report = None
        self.completed_by_plan = {}
        self.session_backup_verified = False
        self.verified_file_count = 0
        self.status_var = tk.StringVar(value="Ready to verify backup readiness.")
        self.metric_vars = {name: tk.StringVar(value="--") for name in ("readiness", "checks", "catalog", "progress", "history", "due")}
        self.category_var = tk.StringVar(value="ALL")
        self.plan_var = tk.StringVar(value=LOCAL_PLANS[0]["title"])
        self.objective_var = tk.StringVar(value=next(item["label"] for item in RESTORE_OBJECTIVES if item["id"] == self.settings["objective_id"]))
        self.copy_var = tk.StringVar(value=str(self.settings["copy_target"]))
        self.interval_var = tk.StringVar(value=f"{self.settings['interval_days']} days")
        self.title_to_id = {item["title"]: item["id"] for item in LOCAL_PLANS}
        self._build_ui()
        self.after(120, self.refresh_data)
        self.after(150, self.poll_results)

    def _build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=20)
        tk.Label(outer, text="Backup Verification Center", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 25, "bold")).pack(anchor="w")
        tk.Label(outer, text="Verify recognized backups, compare coarse checkpoints, and follow a fixed restore order without collecting private file details.", bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 10), wraplength=1080, justify="left").pack(anchor="w", pady=(3, 12))

        actions = tk.Frame(outer, bg=locker.BG)
        actions.pack(fill="x", pady=(0, 10))
        for text, command, color, foreground in (
            ("REFRESH", self.refresh_data, "#252936", locker.TEXT),
            ("VERIFY BACKUP FOLDER", self.verify_backup_folder, locker.GREEN, locker.BLACK),
            ("CREATE APP-DATA BACKUP", self.create_app_data_backup, locker.YELLOW, locker.BLACK),
            ("SAVE CHECKPOINT", self.save_checkpoint, locker.BLUE, locker.BLACK),
            ("EXPORT REPORT", self.export_report, "#252936", locker.TEXT),
            ("EXPORT HISTORY", self.export_history, "#252936", locker.TEXT),
            ("COPY SUMMARY", self.copy_summary, "#252936", locker.TEXT),
            ("WINDOWS SECURITY", self.open_windows_security, "#252936", locker.TEXT),
        ):
            tk.Button(actions, text=text, command=command, bg=color, fg=foreground, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(0, 7), ipadx=8, ipady=7)

        metrics = tk.Frame(outer, bg=locker.PANEL)
        metrics.pack(fill="x", pady=(0, 10))
        for column, (name, label) in enumerate((("readiness", "READINESS"), ("checks", "FIXED CHECKS"), ("catalog", "PLANS / STEPS"), ("progress", "PLAN PROGRESS"), ("history", "CHECKPOINTS"), ("due", "NEXT DUE"))):
            metrics.grid_columnconfigure(column, weight=1, uniform="metric")
            cell = tk.Frame(metrics, bg=locker.PANEL)
            cell.grid(row=0, column=column, sticky="nsew", padx=12, pady=11)
            tk.Label(cell, text=label, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 7, "bold")).pack(anchor="w")
            tk.Label(cell, textvariable=self.metric_vars[name], bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 10, "bold"), wraplength=160, justify="left").pack(anchor="w", pady=(3, 0))

        controls = tk.Frame(outer, bg=locker.PANEL)
        controls.pack(fill="x", pady=(0, 10), padx=0)
        categories = ("ALL",) + tuple(sorted({item["category"] for item in LOCAL_PLANS}))
        self._combo(controls, "CATEGORY", self.category_var, categories, 0, 13).bind("<<ComboboxSelected>>", self.change_category)
        self.plan_box = self._combo(controls, "BACKUP PLAN", self.plan_var, tuple(self.title_to_id), 1, 31)
        self.plan_box.bind("<<ComboboxSelected>>", self.change_plan)
        objective_labels = tuple(item["label"] for item in RESTORE_OBJECTIVES)
        self._combo(controls, "RESTORE OBJECTIVE", self.objective_var, objective_labels, 2, 27).bind("<<ComboboxSelected>>", self.change_settings)
        self._combo(controls, "COPY TARGET", self.copy_var, tuple(str(value) for value in COPY_TARGETS), 3, 9).bind("<<ComboboxSelected>>", self.change_settings)
        self._combo(controls, "REVIEW INTERVAL", self.interval_var, tuple(f"{value} days" for value in ALLOWED_INTERVAL_DAYS), 4, 13).bind("<<ComboboxSelected>>", self.change_settings)

        progress = tk.Frame(outer, bg=locker.BG)
        progress.pack(fill="x", pady=(0, 9))
        for text, command in (("MARK NEXT", self.mark_next), ("MARK ALL", self.mark_all), ("RESET PLAN", self.reset_plan), ("OPEN DIAGNOSTICS", self.open_diagnostics), ("OPEN RECOVERY DRILLS", self.open_recovery_drills)):
            tk.Button(progress, text=text, command=command, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(0, 7), ipadx=10, ipady=6)

        self.output = scrolledtext.ScrolledText(outer, wrap="word", bg="#0b0d12", fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Consolas", 9), padx=14, pady=12)
        self.output.pack(fill="both", expand=True)
        self.output.configure(state="disabled")
        tk.Label(outer, textvariable=self.status_var, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(9, 0))

    def _combo(self, parent, label, variable, values, column, width):
        box_frame = tk.Frame(parent, bg=locker.PANEL)
        box_frame.grid(row=0, column=column, sticky="ew", padx=10, pady=10)
        parent.grid_columnconfigure(column, weight=1 if column in (1, 2) else 0)
        tk.Label(box_frame, text=label, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 7, "bold")).pack(anchor="w")
        box = ttk.Combobox(box_frame, textvariable=variable, values=values, state="readonly", width=width)
        box.pack(fill="x", pady=(4, 0))
        return box

    def refresh_data(self):
        self.status_var.set("Refreshing local checks, fixed plans, checkpoints, and schedule...")
        threading.Thread(target=self._refresh_worker, daemon=True).start()

    def _refresh_worker(self):
        try:
            self.results.put(("refresh", collect_backup_inputs()))
        except Exception as exc:
            self.results.put(("error", str(exc)))

    def poll_results(self):
        try:
            while True:
                kind, payload = self.results.get_nowait()
                if kind == "refresh":
                    self.diagnostic_report, self.guide, self.history, self.integrity, self.settings = payload
                    self._sync_catalog()
                    self._render_report()
                    self.status_var.set("Backup readiness refreshed. No backup path or file content was collected.")
                else:
                    self.status_var.set("Could not refresh backup readiness.")
                    messagebox.showerror("Backup verification failed", payload, parent=self)
        except queue.Empty:
            pass
        if self.winfo_exists():
            self.after(150, self.poll_results)

    def _sync_catalog(self):
        plans = self.guide.get("plans") or LOCAL_PLANS
        self.title_to_id = {item["title"]: item["id"] for item in plans}
        current_id = self.selected_plan_id()
        self.category_var.set(self.category_var.get() if self.category_var.get() in {"ALL", *[item["category"] for item in plans]} else "ALL")
        self._refresh_plan_choices(current_id)

    def _refresh_plan_choices(self, preferred_id=""):
        plans = self.guide.get("plans") or LOCAL_PLANS
        category = self.category_var.get()
        filtered = [item for item in plans if category == "ALL" or item["category"] == category]
        if not filtered:
            filtered = plans
        values = tuple(item["title"] for item in filtered)
        self.plan_box.configure(values=values)
        selected = next((item for item in filtered if item["id"] == preferred_id), filtered[0])
        self.plan_var.set(selected["title"])

    def selected_plan_id(self):
        return self.title_to_id.get(self.plan_var.get(), LOCAL_PLANS[0]["id"])

    def completed_steps(self):
        return self.completed_by_plan.setdefault(self.selected_plan_id(), set())

    def _current_settings(self):
        objective_label = self.objective_var.get()
        objective = next((item for item in RESTORE_OBJECTIVES if item["label"] == objective_label), RESTORE_OBJECTIVES[2])
        return {
            "objective_id": objective["id"],
            "copy_target": int(self.copy_var.get()),
            "interval_days": int(self.interval_var.get().split()[0]),
        }

    def _render_report(self):
        self.report = build_backup_report(
            self.diagnostic_report,
            self.guide,
            self.selected_plan_id(),
            self.completed_steps(),
            self.history,
            self.integrity,
            self._current_settings(),
            self.session_backup_verified,
            self.verified_file_count,
        )
        readiness = self.report["readiness"]
        plan = self.report["selected_plan"]
        history = self.report["history"]
        self.metric_vars["readiness"].set(f"{readiness['value']} / 100 | {readiness['label'].upper()}")
        self.metric_vars["checks"].set(f"{readiness['passed']} / {readiness['total']} READY")
        self.metric_vars["catalog"].set(f"{self.report['online_catalog']['plan_count']} / {self.report['online_catalog']['step_count']}")
        self.metric_vars["progress"].set(f"{plan['completed_count']} / {plan['total_steps']}")
        self.metric_vars["history"].set(f"{history['record_count']} | {'VALID' if history['integrity_valid'] else 'CHECK'}")
        self.metric_vars["due"].set(history["next_due_utc"])
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", safe_backup_text(self.report))
        self.output.configure(state="disabled")

    def change_category(self, _event=None):
        self._refresh_plan_choices()
        self._render_report()

    def change_plan(self, _event=None):
        self._render_report()

    def change_settings(self, _event=None):
        try:
            self.settings = save_center_settings(**self._current_settings())
            self._render_report()
            self.status_var.set("Saved the fixed local backup target and review schedule.")
        except Exception as exc:
            messagebox.showerror("Could not save backup settings", str(exc), parent=self)

    def mark_next(self):
        if not self.report:
            return
        step = next((item for item in self.report["selected_plan"]["steps"] if item["id"] not in self.completed_steps()), None)
        if step:
            self.completed_steps().add(step["id"])
        self._render_report()

    def mark_all(self):
        if self.report:
            self.completed_steps().update(item["id"] for item in self.report["selected_plan"]["steps"])
            self._render_report()

    def reset_plan(self):
        self.completed_steps().clear()
        self._render_report()

    def verify_backup_folder(self):
        selected = filedialog.askdirectory(parent=self, title="Choose an app-data backup folder to verify")
        if not selected:
            self.status_var.set("Backup-folder verification canceled.")
            return
        try:
            candidates = locker.app_data_backup_candidates(selected)
            self.session_backup_verified = True
            self.verified_file_count = len(candidates)
            locker.log_event("backup_folder_verify", "customer_selected_backup", "ok", f"restorable_files={len(candidates)}")
            self._render_report()
            self.status_var.set(f"Recognized {len(candidates)} restorable app-data file(s). The selected path was not retained.")
            messagebox.showinfo("Backup recognized", f"Recognized {len(candidates)} restorable app-data file(s).\n\nThe folder path is not stored in this report or checkpoint history.", parent=self)
        except Exception as exc:
            locker.log_event("backup_folder_verify", "customer_selected_backup", "failed")
            self.status_var.set("The selected folder was not recognized as a restorable app-data backup.")
            messagebox.showerror("Backup not recognized", str(exc), parent=self)

    def create_app_data_backup(self):
        destination = filedialog.askdirectory(parent=self, title="Choose protected destination for app-data backup")
        if not destination:
            self.status_var.set("App-data backup canceled.")
            return
        try:
            backup_dir, copied, _summary = locker.export_app_data_backup(destination)
            locker.log_event("backup_app_data", "customer_selected_destination", "ok", f"files={len(copied)}")
            self.session_backup_verified = True
            self.verified_file_count = len(copied)
            self._render_report()
            self.status_var.set(f"Created and recognized an app-data backup with {len(copied)} file(s).")
            messagebox.showinfo("App data backed up", f"Saved backup folder:\n{backup_dir}\n\nCopied {len(copied)} file(s). The path is not included in reports or checkpoints.", parent=self)
        except Exception as exc:
            locker.log_event("backup_app_data", "customer_selected_destination", "failed")
            self.status_var.set("Could not create the app-data backup.")
            messagebox.showerror("Backup failed", str(exc), parent=self)

    def save_checkpoint(self):
        if not self.report:
            return
        try:
            plan = self.report["selected_plan"]
            target = self.report["restore_target"]
            readiness = self.report["readiness"]
            append_checkpoint(
                plan["id"],
                plan["completed_count"],
                plan["total_steps"],
                readiness["value"],
                readiness["ready_check_ids"],
                target["objective_id"],
                target["copy_target"],
            )
            self.history, self.integrity = load_checkpoint_history()
            locker.log_event("backup_checkpoint_save", "coarse_local_checkpoint", "ok")
            self._render_report()
            self.status_var.set("Saved a privacy-safe hash-chained backup checkpoint.")
        except Exception as exc:
            locker.log_event("backup_checkpoint_save", "coarse_local_checkpoint", "failed")
            messagebox.showerror("Could not save checkpoint", str(exc), parent=self)

    def export_report(self):
        if not self.report:
            return
        path = filedialog.asksaveasfilename(parent=self, title="Export privacy-safe backup report", defaultextension=".json", filetypes=[("JSON report", "*.json")], initialfile="vaultlink-backup-verification-report.json")
        if not path:
            return
        locker.write_text_atomic(Path(path), json.dumps(self.report, indent=2))
        locker.log_event("backup_verification_export", "safe_report", "ok")
        self.status_var.set("Exported the reviewed privacy-safe backup report.")

    def export_history(self):
        records, integrity = load_checkpoint_history()
        if not integrity["valid"]:
            messagebox.showerror("History integrity failed", integrity["message"], parent=self)
            return
        path = filedialog.asksaveasfilename(parent=self, title="Export privacy-safe backup checkpoint history", defaultextension=".json", filetypes=[("JSON history", "*.json")], initialfile="vaultlink-backup-checkpoint-history.json")
        if not path:
            return
        payload = {"schema_version": 1, "report_type": "VaultLink Privacy-Safe Backup Checkpoint History", "generated_at_utc": locker.utc_now_text(), "integrity": integrity, "records": records, "privacy_notice": self.report["privacy_notice"] if self.report else _fallback_guide()["privacy_boundaries"][1]}
        locker.write_text_atomic(Path(path), json.dumps(payload, indent=2))
        locker.log_event("backup_history_export", "safe_history", "ok")
        self.status_var.set("Exported the verified privacy-safe checkpoint history.")

    def copy_summary(self):
        if not self.report:
            return
        self.clipboard_clear()
        self.clipboard_append(safe_backup_summary(self.report))
        locker.log_event("backup_summary_copy", "safe_summary", "ok")
        self.status_var.set("Copied the privacy-safe backup summary.")

    def open_windows_security(self):
        try:
            if os.name != "nt" or not hasattr(os, "startfile"):
                raise OSError("Windows Security is available only on Windows.")
            os.startfile("windowsdefender:")
            self.status_var.set("Opened Windows Security. VaultLink does not read or control that window.")
        except Exception as exc:
            messagebox.showerror("Could not open Windows Security", str(exc), parent=self)

    def open_diagnostics(self):
        try:
            locker.launch_companion_script("diagnostics_center.py")
            self.status_var.set("Opened Diagnostics Center.")
        except Exception as exc:
            messagebox.showerror("Could not open Diagnostics Center", str(exc), parent=self)

    def open_recovery_drills(self):
        try:
            locker.launch_companion_script("recovery_drill_center.py")
            self.status_var.set("Opened Recovery Drill Center.")
        except Exception as exc:
            messagebox.showerror("Could not open Recovery Drill Center", str(exc), parent=self)


if __name__ == "__main__":
    BackupVerificationCenter().mainloop()
