import hashlib
import json
import os
import queue
import secrets
import threading
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

import usb_file_locker as locker


REPORT_SCHEMA_VERSION = 2
GUIDE_ENDPOINT = "/api/v1/maintenance-guide"
HISTORY_PATH = locker.APP_DIR / "security_maintenance_history.jsonl"
SNAPSHOT_PATH = locker.APP_DIR / "security_maintenance_snapshots.jsonl"
MAX_HISTORY_RECORDS = 500
MAX_HISTORY_BYTES = 2 * 1024 * 1024
MAX_SNAPSHOT_RECORDS = 200
MAX_SNAPSHOT_BYTES = 1024 * 1024
ALLOWED_CADENCE_DAYS = (7, 14, 30, 60, 90)
VALID_STATES = frozenset({"completed", "reopened"})
VALID_SOURCES = frozenset({"manual", "routine"})
DISPLAY_STATES = ("all", "current", "due-soon", "overdue", "not-started")
PLANNING_WINDOWS = (
    ("all", "All scheduled", None),
    ("attention", "Attention now", 0),
    ("next-7", "Next 7 days", 7),
    ("next-30", "Next 30 days", 30),
    ("next-90", "Next 90 days", 90),
)
SCHEDULE_SCORE_WEIGHTS = {
    "current": 100,
    "due-soon": 65,
    "overdue": 15,
    "not-started": 0,
}
HISTORY_LOCK = threading.RLock()
SNAPSHOT_LOCK = threading.RLock()
HISTORY_FIELDS = frozenset(
    {
        "schema_version",
        "sequence",
        "time_utc",
        "event_id",
        "task_id",
        "cadence_days",
        "state",
        "source",
        "previous_hash",
        "hash",
    }
)
SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "sequence",
        "time_utc",
        "event_id",
        "schedule_score",
        "current_count",
        "due_soon_count",
        "overdue_count",
        "not_started_count",
        "scheduled_task_count",
        "history_record_count",
        "previous_hash",
        "hash",
    }
)

CATEGORY_ROWS = (
    ("windows-security", "Windows Security", "Keep Microsoft Defender and Windows servicing current through visible Windows controls."),
    ("signed-software", "Signed Software", "Review the transparent VaultLink folder, dependencies, signed release, and retired copies."),
    ("key-custody", "Key Custody", "Test existing keys with disposable data and keep recovery material separated."),
    ("locked-data", "Locked Data", "Practice safe lock and unlock handling while preserving encrypted originals and copies."),
    ("app-data-backup", "App Data Backup", "Create, verify, separate, and understand recovery copies of VaultLink app data."),
    ("recovery-practice", "Recovery Practice", "Rehearse fixed recovery steps before a real device loss, outage, or replacement."),
    ("audit-privacy", "Audit & Privacy", "Verify bounded evidence and review what VaultLink keeps, exports, and cleans."),
    ("license-service", "License & Service", "Review license status, anonymous seats, public service health, and support routes."),
)

TASK_ROWS = (
    ("defender-protection", "windows-security", "Review Defender protection", "Open Windows Security and review Virus & threat protection without disabling any protection.", "Windows reports active protection or gives a visible action that can be reviewed.", 7),
    ("defender-intelligence", "windows-security", "Update Defender intelligence", "Use Windows Security protection updates to check for current Microsoft security intelligence.", "The latest available Defender intelligence check finishes normally.", 7),
    ("defender-quick-scan", "windows-security", "Run a Defender quick scan", "Start a Microsoft Defender quick scan and review its exact detection result.", "The scan completes; any detection is handled through Windows Security instead of VaultLink.", 14),
    ("windows-update", "windows-security", "Review Windows Update", "Check Windows Update, review pending updates, and restart only when normal work is protected.", "Windows reports its current update state and no required restart is forgotten.", 30),
    ("vaultlink-version", "signed-software", "Check the signed VaultLink version", "Open Update Center and compare the installed version with the latest signed release.", "The installed version and signed release status are understood before installing anything.", 14),
    ("signed-package-check", "signed-software", "Verify release signature and hash", "Review the Ed25519 manifest result and SHA-256 package result in Update Center.", "Both integrity checks pass or the update stays uninstalled.", 30),
    ("app-folder-completeness", "signed-software", "Review the transparent app folder", "Confirm the normal app folder still contains its launchers, Python files, dependency setup, and documentation.", "The app uses a complete transparent folder rather than an unknown single-file build.", 30),
    ("retired-copy-review", "signed-software", "Review retired app copies", "Identify obsolete VaultLink app folders only after the current signed copy and rollback path are known good.", "Old app copies are not mistaken for the active release, and no app data or keys are removed.", 60),
    ("primary-key-test", "key-custody", "Test the primary key", "Use the existing primary key in a disposable non-private lock and unlock round trip.", "The intended key reads correctly without exposing its secret or changing important data.", 30),
    ("backup-key-compare", "key-custody", "Compare the backup key", "Use the local key comparison tool to compare the existing backup with the primary key.", "The approved backup matches locally; neither key is uploaded or replaced.", 60),
    ("key-storage-separation", "key-custody", "Review key and data separation", "Confirm the backup key is stored away from the PC, primary USB, PIN, and locked-data backup.", "Loss of one location does not expose or destroy every recovery component.", 30),
    ("owner-usb-review", "key-custody", "Review owner USB policy", "Verify the registered owner USB locally and confirm its protected backup remains available.", "Owner controls recognize the intended removable USB without creating a replacement key.", 30),
    ("disposable-roundtrip", "locked-data", "Run a disposable lock round trip", "Lock and unlock a new non-private test item using the intended key and optional PIN workflow.", "The recovered disposable content matches the original and the real locked files remain unchanged.", 30),
    ("locked-copy-health", "locked-data", "Check an encrypted backup copy", "Run read-only Vault Health checks on a copied non-private .locked test container.", "The copied container structure is readable without decrypting or modifying important originals.", 60),
    ("encrypted-copy-count", "locked-data", "Review independent encrypted copies", "Count recovery sets without recording filenames or paths in VaultLink.", "At least two intended recovery locations are understood and kept separate from keys.", 30),
    ("temporary-output-review", "locked-data", "Review temporary unlocked output", "Close unlocked viewers and inspect the bounded Storage & Retention preview.", "Expired VaultLink temporary copies are understood before any typed-confirmation cleanup.", 7),
    ("appdata-backup-create", "app-data-backup", "Create an app-data backup", "Use Back Up App Data and choose protected storage separate from the live PC.", "A transparent recovery copy of approved VaultLink app data is created.", 30),
    ("appdata-backup-verify", "app-data-backup", "Verify an app-data backup", "Use Backup Verification Center on a recognized app-data backup folder.", "The backup structure and expected files verify without importing keys or personal documents.", 30),
    ("appdata-backup-separate", "app-data-backup", "Review backup separation", "Confirm the app-data backup is not the same physical device as the live data and primary key.", "A PC or single-drive failure does not remove every app-data recovery copy.", 30),
    ("restore-order-review", "app-data-backup", "Review the restore order", "Review the fixed restore objective and safety-snapshot order without replacing live app data.", "The restore sequence is understood before an emergency.", 60),
    ("recovery-kit-review", "recovery-practice", "Review the Recovery Kit", "Open Recovery Kit Builder and review the selected fixed profile and first-hour runbook.", "The next recovery steps are understood without storing identity, contacts, or secrets.", 30),
    ("recovery-drill-run", "recovery-practice", "Complete a recovery drill", "Use a fixed tabletop or disposable-data drill appropriate for the current setup.", "The drill finishes without live malware, destructive simulation, or production data.", 30),
    ("replacement-pc-readiness", "recovery-practice", "Review replacement-PC readiness", "Review the signed app, existing key, app-data backup, and disposable test sequence for a replacement PC.", "A replacement plan exists without creating a universal recovery key.", 90),
    ("trusted-helper-handoff", "recovery-practice", "Review trusted-helper handoff", "Explain the fixed recovery order and stop conditions to an authorized trusted adult using disposable data.", "The helper understands preservation, privacy, and when qualified help is required.", 90),
    ("audit-chain-verify", "audit-privacy", "Verify the audit chain", "Open Audit Log Viewer and run its full local integrity verification.", "The bounded hash chain verifies or the original evidence is preserved for review.", 14),
    ("audit-export-review", "audit-privacy", "Review a privacy-safe audit export", "Export only through Audit Log Viewer and inspect the fields before sharing.", "The reviewed export contains no key, PIN, password, file content, client name, or full path.", 30),
    ("data-control-review", "audit-privacy", "Review the local data map", "Open Local Data Control Center and review its fixed classes, controls, and receipt integrity.", "VaultLink data boundaries are understood without arbitrary folder scanning.", 30),
    ("retention-review", "audit-privacy", "Review storage retention", "Open Storage & Retention Center and review preservation and cleanup boundaries.", "Protected records remain outside cleanup and ordinary deletion is not mistaken for secure erasure.", 30),
    ("license-status-refresh", "license-service", "Refresh license status", "Open Customer Workspace or License Center and refresh the saved license status.", "Plan, status, and signed-update access are current without displaying the license key.", 14),
    ("anonymous-seat-review", "license-service", "Review anonymous device seats", "Review active anonymous seats and remove only a device that is intentionally retired or lost.", "Intended devices retain access and unknown or retired seats are investigated.", 30),
    ("service-status-review", "license-service", "Review public service status", "Open the public status page before treating an online failure as a local key problem.", "Service mode and signed-release availability are understood without sending license data.", 14),
    ("support-channel-review", "license-service", "Review the official support route", "Confirm the visible Bug Center and privacy-safe diagnostic export workflow.", "Support evidence can be sent without keys, PINs, receipts, private files, or unnecessary identity.", 90),
)

LOCAL_CATEGORIES = [
    {"id": identifier, "title": title, "summary": summary}
    for identifier, title, summary in CATEGORY_ROWS
]
LOCAL_TASKS = [
    {
        "id": identifier,
        "category_id": category_id,
        "title": title,
        "action": action,
        "expected": expected,
        "cadence_days": cadence_days,
    }
    for identifier, category_id, title, action, expected, cadence_days in TASK_ROWS
]
TASK_BY_ID = {item["id"]: item for item in LOCAL_TASKS}
CATEGORY_BY_ID = {item["id"]: item for item in LOCAL_CATEGORIES}

ROUTINE_ROWS = (
    (
        "weekly-security",
        "Weekly security",
        "The shortest recurring check for Windows protection, temporary output, service status, and evidence integrity.",
        ("defender-protection", "defender-intelligence", "temporary-output-review", "audit-chain-verify", "service-status-review"),
    ),
    (
        "monthly-core",
        "Monthly core",
        "A practical monthly pass across updates, keys, locking, backups, recovery, privacy, and licensing.",
        ("windows-update", "vaultlink-version", "primary-key-test", "disposable-roundtrip", "appdata-backup-create", "recovery-kit-review", "data-control-review", "license-status-refresh"),
    ),
    (
        "key-custody",
        "Key custody",
        "Review the primary key, backup match, physical separation, owner policy, and disposable recovery.",
        ("primary-key-test", "backup-key-compare", "key-storage-separation", "owner-usb-review", "disposable-roundtrip"),
    ),
    (
        "backup-recovery",
        "Backup & recovery",
        "Review encrypted copies, app-data recovery, fixed runbooks, drills, and replacement readiness.",
        ("locked-copy-health", "encrypted-copy-count", "appdata-backup-create", "appdata-backup-verify", "appdata-backup-separate", "restore-order-review", "recovery-kit-review", "recovery-drill-run", "replacement-pc-readiness"),
    ),
    (
        "privacy-evidence",
        "Privacy & evidence",
        "Verify audit evidence and review data, retention, temporary-output, and support-sharing boundaries.",
        ("temporary-output-review", "audit-chain-verify", "audit-export-review", "data-control-review", "retention-review", "support-channel-review"),
    ),
    (
        "full-maintenance",
        "Full maintenance",
        "Review every fixed maintenance task without adding notes, files, paths, or customer data.",
        tuple(item["id"] for item in LOCAL_TASKS),
    ),
)
LOCAL_ROUTINES = [
    {"id": identifier, "label": label, "summary": summary, "task_ids": list(task_ids)}
    for identifier, label, summary, task_ids in ROUTINE_ROWS
]
ROUTINE_BY_ID = {item["id"]: item for item in LOCAL_ROUTINES}

TRUSTED_TOOL_TARGETS = {
    "defender-protection": ("Windows Security", "uri", "windowsdefender:"),
    "defender-intelligence": ("Windows Security", "uri", "windowsdefender:"),
    "defender-quick-scan": ("Windows Security", "uri", "windowsdefender:"),
    "windows-update": ("Windows Update", "uri", "ms-settings:windowsupdate"),
    "vaultlink-version": ("Main Locker Update Center", "main", ""),
    "signed-package-check": ("Main Locker Update Center", "main", ""),
    "app-folder-completeness": ("VaultLink app folder", "folder", ""),
    "retired-copy-review": ("VaultLink app folder", "folder", ""),
    "primary-key-test": ("Key Inspector", "script", "key_inspector.py"),
    "backup-key-compare": ("Key Inspector", "script", "key_inspector.py"),
    "key-storage-separation": ("Key Inspector", "script", "key_inspector.py"),
    "owner-usb-review": ("Key Inspector", "script", "key_inspector.py"),
    "disposable-roundtrip": ("Main Locker", "main", ""),
    "locked-copy-health": ("Vault Health Center", "script", "vault_health_center.py"),
    "encrypted-copy-count": ("Locked File Browser", "script", "locked_file_browser.py"),
    "temporary-output-review": ("Storage & Retention Center", "script", "storage_retention_center.py"),
    "appdata-backup-create": ("Main Locker", "main", ""),
    "appdata-backup-verify": ("Backup Verification Center", "script", "backup_verification_center.py"),
    "appdata-backup-separate": ("Backup Verification Center", "script", "backup_verification_center.py"),
    "restore-order-review": ("Backup Verification Center", "script", "backup_verification_center.py"),
    "recovery-kit-review": ("Recovery Kit Builder", "script", "recovery_kit_builder.py"),
    "recovery-drill-run": ("Recovery Drill Center", "script", "recovery_drill_center.py"),
    "replacement-pc-readiness": ("Recovery Kit Builder", "script", "recovery_kit_builder.py"),
    "trusted-helper-handoff": ("Recovery Drill Center", "script", "recovery_drill_center.py"),
    "audit-chain-verify": ("Audit Log Viewer", "script", "audit_log_viewer.py"),
    "audit-export-review": ("Audit Log Viewer", "script", "audit_log_viewer.py"),
    "data-control-review": ("Local Data Control Center", "script", "local_data_control_center.py"),
    "retention-review": ("Storage & Retention Center", "script", "storage_retention_center.py"),
    "license-status-refresh": ("Customer Workspace", "script", "customer_hub.py"),
    "anonymous-seat-review": ("Customer Workspace", "script", "customer_hub.py"),
    "service-status-review": ("Public Service Status", "public", "/status"),
    "support-channel-review": ("Main Locker Bug Center", "main", ""),
}

PRIVACY_BOUNDARIES = [
    "The desktop stores only fixed task IDs, fixed cadence, completion or reopen state, UTC time, anonymous event ID, and hash-chain fields.",
    "No name, contact, key, PIN, USB secret, path, filename, file content, scan result, customer record, process list, screenshot, or free-form note is stored or uploaded.",
    "The public API serves a fixed catalog and receives no customer progress, local result, history, reminder, maintenance command, or machine inventory.",
    "Trusted-tool buttons can open only fixed Windows pages, fixed VaultLink scripts, the fixed app folder, or fixed public pages.",
]

LIMITATIONS = [
    "A completed task is a customer-recorded reminder, not proof that Windows, a backup, a key, a scan, or recovery is healthy.",
    "Schedule scores and snapshot comparisons measure reminder coverage only; they are not security-health, compliance, antivirus, backup, or recovery scores.",
    "VaultLink does not replace Microsoft Defender, Windows Update, independent backups, professional incident response, legal advice, or compliance review.",
    "Calendar files are ordinary local reminders. The app does not install a background service or create Windows scheduled tasks.",
]


def _deep_copy(value):
    return json.loads(json.dumps(value))


def _clean_text(value, default="", limit=360):
    text = str(value or "").replace("\x00", "").replace("\r", " ").replace("\n", " ").strip()
    return text[:limit] if text else str(default)[:limit]


def _fallback_guide(message="Online maintenance catalog unavailable."):
    return {
        "ok": False,
        "maintenance_schema_version": 2,
        "api_version": "Unavailable",
        "service_status": {"mode": "unknown", "message": message},
        "signed_release": {"ready": False, "version": "", "minimum_supported_version": ""},
        "categories": _deep_copy(LOCAL_CATEGORIES),
        "tasks": _deep_copy(LOCAL_TASKS),
        "routines": _deep_copy(LOCAL_ROUTINES),
        "cadence_days": list(ALLOWED_CADENCE_DAYS),
        "privacy_boundaries": list(PRIVACY_BOUNDARIES),
        "limitations": list(LIMITATIONS),
        "accepts_free_text": False,
        "accepts_files": False,
        "accepts_paths": False,
        "accepts_progress": False,
        "accepts_local_results": False,
        "accepts_completion_history": False,
        "accepts_reminders": False,
        "accepts_snapshots": False,
        "accepts_schedule_scores": False,
        "accepts_maintenance_commands": False,
        "customer_records_included": False,
    }


def safe_maintenance_guide(payload):
    source = payload if isinstance(payload, dict) else {}
    fallback = _fallback_guide()
    service = source.get("service_status") if isinstance(source.get("service_status"), dict) else {}
    release = source.get("signed_release") if isinstance(source.get("signed_release"), dict) else {}
    boundaries = source.get("privacy_boundaries") if isinstance(source.get("privacy_boundaries"), list) else []
    limitations = source.get("limitations") if isinstance(source.get("limitations"), list) else []
    cleaned_boundaries = [_clean_text(item, "", 420) for item in boundaries[:4]]
    cleaned_limitations = [_clean_text(item, "", 420) for item in limitations[:4]]
    return {
        "ok": bool(source.get("ok")),
        "maintenance_schema_version": 2,
        "api_version": _clean_text(source.get("api_version"), "Unavailable", 80),
        "service_status": {
            "mode": _clean_text(service.get("mode"), "unknown", 40),
            "message": _clean_text(service.get("message"), "Status unavailable.", 220),
        },
        "signed_release": {
            "ready": bool(release.get("ready")),
            "version": _clean_text(release.get("version"), "", 40),
            "minimum_supported_version": _clean_text(release.get("minimum_supported_version"), "", 40),
        },
        "categories": _deep_copy(LOCAL_CATEGORIES),
        "tasks": _deep_copy(LOCAL_TASKS),
        "routines": _deep_copy(LOCAL_ROUTINES),
        "cadence_days": list(ALLOWED_CADENCE_DAYS),
        "privacy_boundaries": [item for item in cleaned_boundaries if item] or fallback["privacy_boundaries"],
        "limitations": [item for item in cleaned_limitations if item] or fallback["limitations"],
        "accepts_free_text": False,
        "accepts_files": False,
        "accepts_paths": False,
        "accepts_progress": False,
        "accepts_local_results": False,
        "accepts_completion_history": False,
        "accepts_reminders": False,
        "accepts_snapshots": False,
        "accepts_schedule_scores": False,
        "accepts_maintenance_commands": False,
        "customer_records_included": False,
    }


def _is_lower_hex(value, length):
    text = str(value or "")
    return len(text) == length and all(character in "0123456789abcdef" for character in text)


def _linklike(path):
    path = Path(path)
    try:
        info = path.lstat()
        attributes = getattr(info, "st_file_attributes", 0)
        reparse = getattr(os.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return path.is_symlink() or bool(attributes & reparse)
    except OSError:
        return False


def _safe_utc_text(value=""):
    text = str(value or locker.utc_now_text()).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("UTC offset required")
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError):
        raise ValueError("Maintenance time must be a valid UTC timestamp.")


def _parse_utc(value):
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _canonical_record(record):
    payload = dict(record)
    payload.pop("hash", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _validate_history_record(record, sequence, previous_hash):
    if not isinstance(record, dict) or set(record) != HISTORY_FIELDS or record.get("schema_version") != 1:
        raise ValueError(f"Maintenance record {sequence} has an invalid fixed schema.")
    if type(record.get("sequence")) is not int or record["sequence"] != sequence:
        raise ValueError(f"Maintenance record {sequence} has an invalid sequence.")
    if record.get("previous_hash") != previous_hash or not _is_lower_hex(record.get("previous_hash"), 64):
        raise ValueError(f"Maintenance record {sequence} broke the hash chain.")
    if not _is_lower_hex(record.get("hash"), 64) or not _is_lower_hex(record.get("event_id"), 16):
        raise ValueError(f"Maintenance record {sequence} has an invalid identifier.")
    if _parse_utc(record.get("time_utc")) is None or len(str(record.get("time_utc"))) > 40:
        raise ValueError(f"Maintenance record {sequence} has an invalid timestamp.")
    task = TASK_BY_ID.get(str(record.get("task_id", "")))
    if not task or record.get("cadence_days") != task["cadence_days"]:
        raise ValueError(f"Maintenance record {sequence} contains an unknown fixed task.")
    if record.get("state") not in VALID_STATES or record.get("source") not in VALID_SOURCES:
        raise ValueError(f"Maintenance record {sequence} contains an unknown fixed state.")


def load_maintenance_history(path=HISTORY_PATH):
    path = Path(path)
    try:
        if _linklike(path):
            raise ValueError("Maintenance history cannot be a link or junction.")
        if path.exists() and not path.is_file():
            raise ValueError("Maintenance history must be a regular file.")
        if not path.is_file():
            return [], {"valid": True, "message": "No Security Maintenance events have been saved yet."}
        if path.stat().st_size > MAX_HISTORY_BYTES:
            raise ValueError("Maintenance history is larger than the 2 MiB safety limit.")
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) > MAX_HISTORY_RECORDS:
            raise ValueError("Maintenance history exceeds the 500-record safety limit.")
        records = []
        previous_hash = "0" * 64
        for sequence, line in enumerate(lines, 1):
            record = json.loads(line)
            _validate_history_record(record, sequence, previous_hash)
            expected = hashlib.sha256(_canonical_record(record)).hexdigest()
            if not secrets.compare_digest(str(record.get("hash", "")), expected):
                raise ValueError(f"Maintenance record {sequence} failed its hash check.")
            records.append(record)
            previous_hash = expected
        return records, {"valid": True, "message": f"Verified {len(records)} hash-chained Security Maintenance event(s)."}
    except (ValueError, json.JSONDecodeError) as exc:
        return [], {"valid": False, "message": str(exc)[:300]}
    except Exception:
        return [], {"valid": False, "message": "Maintenance history could not be read safely."}


def append_maintenance_events(task_ids, state, source="manual", path=HISTORY_PATH, time_utc=""):
    state = str(state or "")
    source = str(source or "")
    identifiers = [str(value or "") for value in task_ids]
    if state not in VALID_STATES or source not in VALID_SOURCES:
        raise ValueError("Choose only a fixed maintenance event state and source.")
    if not identifiers or len(identifiers) != len(set(identifiers)) or any(identifier not in TASK_BY_ID for identifier in identifiers):
        raise ValueError("Choose one or more unique fixed maintenance tasks.")
    with HISTORY_LOCK:
        path = Path(path)
        if _linklike(path):
            raise ValueError("Maintenance history cannot be a link or junction.")
        records, integrity = load_maintenance_history(path)
        if not integrity["valid"]:
            raise ValueError("Maintenance history integrity failed. Preserve the file and review it before adding events.")
        if len(records) + len(identifiers) > MAX_HISTORY_RECORDS:
            raise ValueError("Maintenance history would exceed 500 records. Export and archive it before adding more events.")
        event_time = _safe_utc_text(time_utc)
        previous_hash = records[-1]["hash"] if records else "0" * 64
        new_records = []
        for offset, identifier in enumerate(identifiers, 1):
            task = TASK_BY_ID[identifier]
            record = {
                "schema_version": 1,
                "sequence": len(records) + offset,
                "time_utc": event_time,
                "event_id": secrets.token_hex(8),
                "task_id": identifier,
                "cadence_days": task["cadence_days"],
                "state": state,
                "source": source,
                "previous_hash": previous_hash,
            }
            record["hash"] = hashlib.sha256(_canonical_record(record)).hexdigest()
            previous_hash = record["hash"]
            new_records.append(record)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write("".join(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n" for record in new_records))
        return new_records


def append_maintenance_event(task_id, state, source="manual", path=HISTORY_PATH, time_utc=""):
    return append_maintenance_events([task_id], state, source, path, time_utc)[0]


def _validate_snapshot_record(record, sequence, previous_hash):
    if not isinstance(record, dict) or set(record) != SNAPSHOT_FIELDS or record.get("schema_version") != 1:
        raise ValueError(f"Maintenance snapshot {sequence} has an invalid fixed schema.")
    if type(record.get("sequence")) is not int or record["sequence"] != sequence:
        raise ValueError(f"Maintenance snapshot {sequence} has an invalid sequence.")
    if record.get("previous_hash") != previous_hash or not _is_lower_hex(record.get("previous_hash"), 64):
        raise ValueError(f"Maintenance snapshot {sequence} broke the hash chain.")
    if not _is_lower_hex(record.get("hash"), 64) or not _is_lower_hex(record.get("event_id"), 16):
        raise ValueError(f"Maintenance snapshot {sequence} has an invalid identifier.")
    if _parse_utc(record.get("time_utc")) is None or len(str(record.get("time_utc"))) > 40:
        raise ValueError(f"Maintenance snapshot {sequence} has an invalid timestamp.")
    bounded_fields = {
        "schedule_score": (0, 100),
        "current_count": (0, len(LOCAL_TASKS)),
        "due_soon_count": (0, len(LOCAL_TASKS)),
        "overdue_count": (0, len(LOCAL_TASKS)),
        "not_started_count": (0, len(LOCAL_TASKS)),
        "scheduled_task_count": (0, len(LOCAL_TASKS)),
        "history_record_count": (0, MAX_HISTORY_RECORDS),
    }
    for field, (minimum, maximum) in bounded_fields.items():
        value = record.get(field)
        if type(value) is not int or value < minimum or value > maximum:
            raise ValueError(f"Maintenance snapshot {sequence} has an invalid fixed count.")
    status_total = (
        record["current_count"]
        + record["due_soon_count"]
        + record["overdue_count"]
        + record["not_started_count"]
    )
    if status_total != len(LOCAL_TASKS):
        raise ValueError(f"Maintenance snapshot {sequence} has inconsistent task counts.")
    if record["scheduled_task_count"] != len(LOCAL_TASKS) - record["not_started_count"]:
        raise ValueError(f"Maintenance snapshot {sequence} has an inconsistent scheduled-task count.")


def load_snapshot_history(path=SNAPSHOT_PATH):
    path = Path(path)
    try:
        if _linklike(path):
            raise ValueError("Maintenance snapshot history cannot be a link or junction.")
        if path.exists() and not path.is_file():
            raise ValueError("Maintenance snapshot history must be a regular file.")
        if not path.is_file():
            return [], {"valid": True, "message": "No Security Maintenance snapshots have been saved yet."}
        if path.stat().st_size > MAX_SNAPSHOT_BYTES:
            raise ValueError("Maintenance snapshot history is larger than the 1 MiB safety limit.")
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) > MAX_SNAPSHOT_RECORDS:
            raise ValueError("Maintenance snapshot history exceeds the 200-record safety limit.")
        records = []
        previous_hash = "0" * 64
        for sequence, line in enumerate(lines, 1):
            record = json.loads(line)
            _validate_snapshot_record(record, sequence, previous_hash)
            expected = hashlib.sha256(_canonical_record(record)).hexdigest()
            if not secrets.compare_digest(str(record.get("hash", "")), expected):
                raise ValueError(f"Maintenance snapshot {sequence} failed its hash check.")
            records.append(record)
            previous_hash = expected
        return records, {"valid": True, "message": f"Verified {len(records)} hash-chained Security Maintenance snapshot(s)."}
    except (ValueError, json.JSONDecodeError) as exc:
        return [], {"valid": False, "message": str(exc)[:300]}
    except Exception:
        return [], {"valid": False, "message": "Maintenance snapshot history could not be read safely."}


def append_maintenance_snapshot(report, path=SNAPSHOT_PATH, time_utc=""):
    if not isinstance(report, dict) or not isinstance(report.get("summary"), dict) or not isinstance(report.get("history"), dict):
        raise ValueError("A current fixed Security Maintenance report is required.")
    summary = report["summary"]
    required = ("schedule_score", "current", "due_soon", "overdue", "not_started", "scheduled_tasks")
    if any(type(summary.get(field)) is not int for field in required):
        raise ValueError("The Security Maintenance report has invalid fixed summary values.")
    if not report["history"].get("integrity_valid"):
        raise ValueError("Maintenance history integrity must be valid before saving a snapshot.")
    history_record_count = report["history"].get("record_count")
    if type(history_record_count) is not int:
        raise ValueError("The Security Maintenance report has an invalid history count.")
    with SNAPSHOT_LOCK:
        path = Path(path)
        if _linklike(path):
            raise ValueError("Maintenance snapshot history cannot be a link or junction.")
        records, integrity = load_snapshot_history(path)
        if not integrity["valid"]:
            raise ValueError("Maintenance snapshot integrity failed. Preserve the file and review it before adding snapshots.")
        if len(records) >= MAX_SNAPSHOT_RECORDS:
            raise ValueError("Maintenance snapshot history reached 200 records. Export an archive before adding more snapshots.")
        record = {
            "schema_version": 1,
            "sequence": len(records) + 1,
            "time_utc": _safe_utc_text(time_utc),
            "event_id": secrets.token_hex(8),
            "schedule_score": summary["schedule_score"],
            "current_count": summary["current"],
            "due_soon_count": summary["due_soon"],
            "overdue_count": summary["overdue"],
            "not_started_count": summary["not_started"],
            "scheduled_task_count": summary["scheduled_tasks"],
            "history_record_count": history_record_count,
            "previous_hash": records[-1]["hash"] if records else "0" * 64,
        }
        _validate_snapshot_record({**record, "hash": "0" * 64}, record["sequence"], record["previous_hash"])
        record["hash"] = hashlib.sha256(_canonical_record(record)).hexdigest()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        return record


def compare_maintenance_snapshots(older, newer):
    for record in (older, newer):
        _validate_snapshot_record(record, int(record.get("sequence", 0)), str(record.get("previous_hash", "")))
        expected = hashlib.sha256(_canonical_record(record)).hexdigest()
        if not secrets.compare_digest(str(record.get("hash", "")), expected):
            raise ValueError("Maintenance snapshot comparison requires verified snapshots.")
    if newer["sequence"] <= older["sequence"]:
        raise ValueError("Choose snapshots in oldest-to-newest order.")
    return {
        "schema_version": 1,
        "report_type": "VaultLink Privacy-Safe Maintenance Snapshot Comparison",
        "older_time_utc": older["time_utc"],
        "newer_time_utc": newer["time_utc"],
        "schedule_score_change": newer["schedule_score"] - older["schedule_score"],
        "current_count_change": newer["current_count"] - older["current_count"],
        "attention_count_change": (
            newer["due_soon_count"] + newer["overdue_count"]
            - older["due_soon_count"]
            - older["overdue_count"]
        ),
        "not_started_count_change": newer["not_started_count"] - older["not_started_count"],
        "scheduled_task_count_change": newer["scheduled_task_count"] - older["scheduled_task_count"],
        "history_record_count_change": newer["history_record_count"] - older["history_record_count"],
        "customer_records_included": False,
    }


def build_maintenance_archive(history, history_integrity, snapshots, snapshot_integrity, now_utc=""):
    if not isinstance(history_integrity, dict) or not history_integrity.get("valid"):
        raise ValueError("Maintenance event history must verify before an archive can be exported.")
    if not isinstance(snapshot_integrity, dict) or not snapshot_integrity.get("valid"):
        raise ValueError("Maintenance snapshot history must verify before an archive can be exported.")
    event_records = list(history or [])
    snapshot_records = list(snapshots or [])
    previous_hash = "0" * 64
    for sequence, record in enumerate(event_records, 1):
        _validate_history_record(record, sequence, previous_hash)
        expected = hashlib.sha256(_canonical_record(record)).hexdigest()
        if not secrets.compare_digest(record["hash"], expected):
            raise ValueError("Maintenance event history failed archive verification.")
        previous_hash = expected
    previous_hash = "0" * 64
    for sequence, record in enumerate(snapshot_records, 1):
        _validate_snapshot_record(record, sequence, previous_hash)
        expected = hashlib.sha256(_canonical_record(record)).hexdigest()
        if not secrets.compare_digest(record["hash"], expected):
            raise ValueError("Maintenance snapshot history failed archive verification.")
        previous_hash = expected
    return {
        "schema_version": 1,
        "report_type": "VaultLink Privacy-Safe Security Maintenance Archive",
        "exported_at_utc": _safe_utc_text(now_utc),
        "event_record_count": len(event_records),
        "event_final_hash": event_records[-1]["hash"] if event_records else "0" * 64,
        "snapshot_record_count": len(snapshot_records),
        "snapshot_final_hash": snapshot_records[-1]["hash"] if snapshot_records else "0" * 64,
        "event_history": event_records,
        "snapshot_history": snapshot_records,
        "privacy_notice": "This non-destructive archive contains only fixed maintenance IDs, fixed cadence, coarse counts, state, UTC time, anonymous event IDs, and integrity hashes.",
        "customer_records_included": False,
    }


def latest_task_events(history):
    latest = {}
    for record in history or []:
        if isinstance(record, dict) and record.get("task_id") in TASK_BY_ID:
            latest[record["task_id"]] = record
    return latest


def maintenance_task_state(task_id, history=None, now_utc=None):
    if task_id not in TASK_BY_ID:
        raise ValueError("The maintenance task ID is not recognized.")
    now = _parse_utc(now_utc) if now_utc else datetime.now(timezone.utc)
    if now is None:
        raise ValueError("The maintenance comparison time is invalid.")
    event = latest_task_events(history or []).get(task_id)
    if not event or event.get("state") == "reopened":
        return {"state": "not-started", "last_completed_utc": "", "next_due_utc": "", "days_remaining": None}
    completed = _parse_utc(event.get("time_utc"))
    if completed is None:
        return {"state": "not-started", "last_completed_utc": "", "next_due_utc": "", "days_remaining": None}
    due = completed + timedelta(days=TASK_BY_ID[task_id]["cadence_days"])
    seconds_remaining = (due - now).total_seconds()
    days_remaining = int(seconds_remaining // 86400)
    if seconds_remaining < 0:
        state = "overdue"
    elif seconds_remaining <= 7 * 86400:
        state = "due-soon"
    else:
        state = "current"
    return {
        "state": state,
        "last_completed_utc": completed.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "next_due_utc": due.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "days_remaining": days_remaining,
    }


def _schedule_label(score):
    if score >= 90:
        return "current"
    if score >= 70:
        return "review-soon"
    if score >= 40:
        return "rebuilding"
    return "not-established"


def _coverage_row(identifier, label, task_ids, task_by_id):
    tasks = [task_by_id[task_id] for task_id in task_ids]
    counts = {state: sum(item["state"] == state for item in tasks) for state in SCHEDULE_SCORE_WEIGHTS}
    score = round(sum(SCHEDULE_SCORE_WEIGHTS[item["state"]] for item in tasks) / len(tasks))
    planning_dates = [_parse_utc(item["planning_due_utc"]) for item in tasks]
    planning_dates = [item for item in planning_dates if item is not None]
    return {
        "id": identifier,
        "label": label,
        "task_count": len(tasks),
        "schedule_score": score,
        "schedule_label": _schedule_label(score),
        "current": counts["current"],
        "due_soon": counts["due-soon"],
        "overdue": counts["overdue"],
        "not_started": counts["not-started"],
        "attention_count": counts["due-soon"] + counts["overdue"],
        "next_planning_due_utc": min(planning_dates).strftime("%Y-%m-%dT%H:%M:%SZ") if planning_dates else "",
    }


def _history_activity(history, now):
    completed = [record for record in history if record.get("state") == "completed"]
    reopened = [record for record in history if record.get("state") == "reopened"]

    def within(days):
        cutoff = now - timedelta(days=days)
        return sum((_parse_utc(record.get("time_utc")) or datetime.min.replace(tzinfo=timezone.utc)) >= cutoff for record in history)

    active_days_30 = {
        parsed.date().isoformat()
        for record in history
        for parsed in [_parse_utc(record.get("time_utc"))]
        if parsed is not None and parsed >= now - timedelta(days=30)
    }
    return {
        "completed_events": len(completed),
        "reopened_events": len(reopened),
        "events_last_7_days": within(7),
        "events_last_30_days": within(30),
        "events_last_90_days": within(90),
        "active_days_last_30": len(active_days_30),
        "last_event_utc": history[-1]["time_utc"] if history else "",
    }


def build_maintenance_report(online_guide=None, history=None, integrity=None, selected_category_id="all", selected_routine_id="all", now_utc=""):
    guide = safe_maintenance_guide(online_guide)
    records = list(history or [])
    history_integrity = integrity if isinstance(integrity, dict) else {"valid": True, "message": "No history loaded."}
    category_id = str(selected_category_id or "all")
    routine_id = str(selected_routine_id or "all")
    if category_id != "all" and category_id not in CATEGORY_BY_ID:
        category_id = "all"
    if routine_id != "all" and routine_id not in ROUTINE_BY_ID:
        routine_id = "all"
    generated = _safe_utc_text(now_utc)
    generated_time = _parse_utc(generated)
    task_rows = []
    summary = {"current": 0, "due_soon": 0, "overdue": 0, "not_started": 0}
    for task in LOCAL_TASKS:
        status = maintenance_task_state(task["id"], records, generated)
        summary[status["state"].replace("-", "_")] += 1
        due = _parse_utc(status["next_due_utc"])
        if due is None:
            due = generated_time + timedelta(days=task["cadence_days"])
        planning_days_remaining = int((due - generated_time).total_seconds() // 86400)
        task_rows.append(
            {
                "id": task["id"],
                "category_id": task["category_id"],
                "category": CATEGORY_BY_ID[task["category_id"]]["title"],
                "title": task["title"],
                "action": task["action"],
                "expected": task["expected"],
                "cadence_days": task["cadence_days"],
                "state": status["state"],
                "last_completed_utc": status["last_completed_utc"],
                "next_due_utc": status["next_due_utc"],
                "days_remaining": status["days_remaining"],
                "planning_due_utc": due.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "planning_days_remaining": planning_days_remaining,
            }
        )
    scheduled = len(task_rows) - summary["not_started"]
    ever_completed = len({record["task_id"] for record in records if record.get("state") == "completed"})
    task_by_id = {item["id"]: item for item in task_rows}
    schedule_score = round(sum(SCHEDULE_SCORE_WEIGHTS[item["state"]] for item in task_rows) / len(task_rows))
    planning = {
        "attention_now": sum(item["state"] in {"due-soon", "overdue"} for item in task_rows),
        "next_7_days": sum(item["planning_days_remaining"] <= 7 for item in task_rows),
        "next_30_days": sum(item["planning_days_remaining"] <= 30 for item in task_rows),
        "next_90_days": sum(item["planning_days_remaining"] <= 90 for item in task_rows),
    }
    categories = [
        _coverage_row(item["id"], item["title"], [task["id"] for task in LOCAL_TASKS if task["category_id"] == item["id"]], task_by_id)
        for item in LOCAL_CATEGORIES
    ]
    routines = [
        _coverage_row(item["id"], item["label"], item["task_ids"], task_by_id)
        for item in LOCAL_ROUTINES
    ]
    priority_rank = {"overdue": 0, "due-soon": 1, "not-started": 2, "current": 3}
    priority_task_ids = [
        item["id"]
        for item in sorted(
            task_rows,
            key=lambda item: (
                priority_rank[item["state"]],
                item["planning_due_utc"],
                item["cadence_days"],
                item["id"],
            ),
        )[:8]
    ]
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": "VaultLink Privacy-Safe Security Maintenance Report",
        "generated_at_utc": generated,
        "desktop_version": locker.DESKTOP_APP_VERSION,
        "catalog": {
            "category_count": len(LOCAL_CATEGORIES),
            "task_count": len(LOCAL_TASKS),
            "routine_count": len(LOCAL_ROUTINES),
            "cadence_days": list(ALLOWED_CADENCE_DAYS),
        },
        "selection": {"category_id": category_id, "routine_id": routine_id},
        "summary": {
            "current": summary["current"],
            "due_soon": summary["due_soon"],
            "overdue": summary["overdue"],
            "not_started": summary["not_started"],
            "scheduled_tasks": scheduled,
            "ever_completed_tasks": ever_completed,
            "attention_tasks": summary["due_soon"] + summary["overdue"],
            "schedule_percent": round((scheduled / len(task_rows)) * 100),
            "schedule_score": schedule_score,
            "schedule_label": _schedule_label(schedule_score),
        },
        "planning": planning,
        "priority_task_ids": priority_task_ids,
        "category_coverage": categories,
        "routine_coverage": routines,
        "tasks": task_rows,
        "history": {
            "record_count": len(records),
            "integrity_valid": bool(history_integrity.get("valid")),
            "integrity_message": _clean_text(history_integrity.get("message"), "History status unavailable.", 300),
            "activity": _history_activity(records, generated_time),
        },
        "online": {
            "api_version": guide["api_version"],
            "service_mode": guide["service_status"]["mode"],
            "signed_desktop_ready": guide["signed_release"]["ready"],
            "signed_desktop_version": guide["signed_release"]["version"],
        },
        "privacy_boundaries": list(guide["privacy_boundaries"]),
        "limitations": list(guide["limitations"]),
        "customer_records_included": False,
    }


def safe_summary(report):
    summary = report["summary"]
    history = report["history"]
    online = report["online"]
    return "\n".join(
        [
            "VaultLink Security Maintenance",
            f"Schedule coverage: {summary['schedule_score']} / 100 | {summary['schedule_label']} | Reminder score only.",
            f"Current: {summary['current']} | Due soon: {summary['due_soon']} | Overdue: {summary['overdue']} | Not started: {summary['not_started']}",
            f"Plan: attention now {report['planning']['attention_now']} | next 7 days {report['planning']['next_7_days']} | next 30 days {report['planning']['next_30_days']} | next 90 days {report['planning']['next_90_days']}",
            f"Active schedule: {summary['scheduled_tasks']} / {report['catalog']['task_count']} | Ever completed: {summary['ever_completed_tasks']} | History: {history['record_count']} | Integrity: {'VALID' if history['integrity_valid'] else 'CHECK'}",
            f"API: {online['api_version']} | Service: {online['service_mode']} | Signed desktop: {online['signed_desktop_version'] or 'not published'}",
            "No names, contacts, keys, PINs, paths, filenames, file contents, scan results, customer records, or free-form notes are included.",
        ]
    )


def safe_report_text(report):
    summary = report["summary"]
    history = report["history"]
    online = report["online"]
    lines = [
        "VAULTLINK SECURITY MAINTENANCE",
        "=" * 78,
        f"Generated UTC        {report['generated_at_utc']}",
        f"Desktop version      {report['desktop_version']}",
        f"Catalog              {report['catalog']['category_count']} CATEGORIES | {report['catalog']['task_count']} TASKS | {report['catalog']['routine_count']} ROUTINES",
        f"Schedule coverage    {summary['schedule_score']} / 100 | {summary['schedule_label'].upper()} | REMINDER SCORE ONLY",
        f"Current              {summary['current']}",
        f"Due soon             {summary['due_soon']}",
        f"Overdue              {summary['overdue']}",
        f"Not started          {summary['not_started']}",
        f"Active schedule      {summary['scheduled_tasks']} / {report['catalog']['task_count']} | {summary['schedule_percent']}%",
        f"Ever completed       {summary['ever_completed_tasks']} / {report['catalog']['task_count']}",
        f"Planning windows     NOW {report['planning']['attention_now']} | 7D {report['planning']['next_7_days']} | 30D {report['planning']['next_30_days']} | 90D {report['planning']['next_90_days']}",
        f"Local history        {history['record_count']} RECORDS | {'VALID' if history['integrity_valid'] else 'CHECK'}",
        f"Online               API {online['api_version']} | {online['service_mode']} | SIGNED {online['signed_desktop_version'] or 'NOT PUBLISHED'}",
        "",
        "PRIORITY QUEUE",
        "-" * 78,
    ]
    for task_id in report["priority_task_ids"]:
        task = next(item for item in report["tasks"] if item["id"] == task_id)
        lines.append(f"{task['state'].upper():11} {task['title']} | PLAN {task['planning_due_utc']}")
    lines.extend(["", "ROUTINE COVERAGE", "-" * 78])
    for routine in report["routine_coverage"]:
        lines.append(
            f"{routine['schedule_score']:3} / 100  {routine['label']} | CURRENT {routine['current']} | "
            f"ATTENTION {routine['attention_count']} | NOT STARTED {routine['not_started']}"
        )
    lines.extend(["", "FIXED TASK STATUS", "-" * 78])
    for task in report["tasks"]:
        due = task["next_due_utc"] or f"first plan {task['planning_due_utc']}"
        lines.append(f"{task['state'].upper():11} {task['title']} | {task['category']} | {task['cadence_days']} DAYS | NEXT {due}")
    lines.extend(["", "HISTORY INTEGRITY", "-" * 78, history["integrity_message"], "", "PRIVACY BOUNDARIES", "-" * 78])
    lines.extend(f"- {item}" for item in report["privacy_boundaries"])
    lines.extend(["", "LIMITATIONS", "-" * 78])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines)


def dashboard_text(report, snapshots=None, snapshot_integrity=None):
    summary = report["summary"]
    activity = report["history"]["activity"]
    snapshot_rows = list(snapshots or [])
    integrity = snapshot_integrity if isinstance(snapshot_integrity, dict) else {"valid": True}
    lines = [
        "MAINTENANCE READINESS DASHBOARD",
        "=" * 70,
        f"Schedule coverage     {summary['schedule_score']} / 100 | {summary['schedule_label'].upper()}",
        "Meaning               Reminder coverage only; not proof of antivirus, backup, key, or recovery health.",
        f"Attention now         {report['planning']['attention_now']}",
        f"Due in 7 / 30 / 90    {report['planning']['next_7_days']} / {report['planning']['next_30_days']} / {report['planning']['next_90_days']}",
        f"Events 7 / 30 / 90    {activity['events_last_7_days']} / {activity['events_last_30_days']} / {activity['events_last_90_days']}",
        f"Active days in 30     {activity['active_days_last_30']}",
        f"Completed / reopened  {activity['completed_events']} / {activity['reopened_events']}",
        f"Last event UTC        {activity['last_event_utc'] or 'none'}",
        f"Snapshots             {len(snapshot_rows)} | {'VALID' if integrity.get('valid') else 'CHECK'}",
        "",
        "CATEGORY COVERAGE",
        "-" * 70,
    ]
    for category in report["category_coverage"]:
        lines.append(
            f"{category['schedule_score']:3}  {category['label']:<22} "
            f"CURRENT {category['current']} | ATTENTION {category['attention_count']} | NOT STARTED {category['not_started']}"
        )
    lines.extend(["", "ROUTINE COVERAGE", "-" * 70])
    for routine in report["routine_coverage"]:
        lines.append(
            f"{routine['schedule_score']:3}  {routine['label']:<22} "
            f"CURRENT {routine['current']} | ATTENTION {routine['attention_count']} | NOT STARTED {routine['not_started']}"
        )
    lines.extend(["", "PRIORITY TASKS", "-" * 70])
    for position, task_id in enumerate(report["priority_task_ids"], 1):
        task = next(item for item in report["tasks"] if item["id"] == task_id)
        lines.append(f"{position:>2}. {task['state'].upper():11} {task['title']} | {task['planning_due_utc'][:10]}")
    return "\n".join(lines)


def snapshot_comparison_text(comparison):
    return "\n".join(
        [
            "MAINTENANCE SNAPSHOT COMPARISON",
            "=" * 70,
            f"Older UTC              {comparison['older_time_utc']}",
            f"Newer UTC              {comparison['newer_time_utc']}",
            f"Schedule score change  {comparison['schedule_score_change']:+d}",
            f"Current task change    {comparison['current_count_change']:+d}",
            f"Attention task change  {comparison['attention_count_change']:+d}",
            f"Not-started change     {comparison['not_started_count_change']:+d}",
            f"Active schedule change {comparison['scheduled_task_count_change']:+d}",
            f"History event change   {comparison['history_record_count_change']:+d}",
            "",
            "A positive score or current-task change reflects reminder coverage only.",
            "It does not prove that Windows, Defender, a backup, a key, or recovery is healthy.",
        ]
    )


def _ics_escape(value):
    return str(value or "").replace("\\", "\\\\").replace("\r", "").replace("\n", "\\n").replace(",", "\\,").replace(";", "\\;")


def build_calendar_text(task_ids=None, history=None, now_utc=None, event_id=""):
    identifiers = list(task_ids or [item["id"] for item in LOCAL_TASKS])
    if not identifiers or len(identifiers) != len(set(identifiers)) or any(identifier not in TASK_BY_ID for identifier in identifiers):
        raise ValueError("Calendar reminders require unique fixed maintenance task IDs.")
    now = _parse_utc(now_utc) if now_utc else datetime.now(timezone.utc)
    if now is None:
        raise ValueError("Calendar time must be a valid UTC timestamp.")
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    token = event_id if _is_lower_hex(event_id, 16) else secrets.token_hex(8)
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//VaultLink//Security Maintenance//EN", "CALSCALE:GREGORIAN", "METHOD:PUBLISH"]
    for task_id in identifiers:
        task = TASK_BY_ID[task_id]
        status = maintenance_task_state(task_id, history or [], now.strftime("%Y-%m-%dT%H:%M:%SZ"))
        due = _parse_utc(status["next_due_utc"])
        if due is None:
            due = now + timedelta(days=task["cadence_days"])
        if due.date() < now.date():
            due = now
        lines.extend(
            [
                "BEGIN:VEVENT",
                f"UID:vaultlink-maintenance-{task_id}-{token}@local",
                f"DTSTAMP:{stamp}",
                f"DTSTART;VALUE=DATE:{due.strftime('%Y%m%d')}",
                f"SUMMARY:{_ics_escape('VaultLink: ' + task['title'])}",
                "DESCRIPTION:" + _ics_escape("Review this fixed task in the local VaultLink Security Maintenance Center. Do not place secrets or customer data in calendar notes."),
                "END:VEVENT",
            ]
        )
    lines.append("END:VCALENDAR")
    return "\r\n".join(lines) + "\r\n"


def launch_trusted_task_tool(task_id):
    target = TRUSTED_TOOL_TARGETS.get(str(task_id or ""))
    if not target:
        raise ValueError("No trusted tool is assigned to this fixed maintenance task.")
    label, kind, value = target
    if kind == "script":
        locker.launch_companion_script(value)
    elif kind == "main":
        locker.launch_main_app_process()
    elif kind == "folder":
        os.startfile(locker.SOURCE_DIR)
    elif kind == "uri":
        if value not in {"windowsdefender:", "ms-settings:windowsupdate"}:
            raise ValueError("The Windows settings target is not allowed.")
        os.startfile(value)
    elif kind == "public":
        if value not in {"/status"}:
            raise ValueError("The public page target is not allowed.")
        settings = locker.load_settings()
        state = locker.load_license_state(settings)
        server = locker.validated_license_server_url(state.get("server_url"))
        webbrowser.open(server.rstrip("/") + value, new=2)
    else:
        raise ValueError("The trusted tool type is not allowed.")
    return label


def collect_inputs():
    guide = _fallback_guide()
    try:
        settings = locker.load_settings()
        state = locker.load_license_state(settings)
        server = locker.validated_license_server_url(state.get("server_url"))
        guide = safe_maintenance_guide(locker.license_api_get_json(server, GUIDE_ENDPOINT))
    except Exception:
        pass
    history, integrity = load_maintenance_history()
    snapshots, snapshot_integrity = load_snapshot_history()
    return guide, history, integrity, snapshots, snapshot_integrity


class SecurityMaintenanceCenter(tk.Tk):
    def __init__(self):
        super().__init__()
        if not locker.ensure_license_feature("security-maintenance-center", parent=self):
            self.after(0, self.destroy)
            return
        self.title("VaultLink Security Maintenance Center")
        self.geometry("1260x920")
        self.minsize(1080, 760)
        self.configure(bg=locker.BG)
        self.results = queue.Queue()
        self.guide = _fallback_guide()
        self.history = []
        self.integrity = {"valid": True, "message": "No history loaded."}
        self.snapshots = []
        self.snapshot_integrity = {"valid": True, "message": "No snapshots loaded."}
        self.report = None
        self.status_var = tk.StringVar(value="Ready to review fixed security maintenance tasks.")
        self.category_var = tk.StringVar(value="All categories")
        self.routine_var = tk.StringVar(value="Monthly core")
        self.state_var = tk.StringVar(value="All states")
        self.plan_var = tk.StringVar(value="All scheduled")
        self.metric_vars = {
            name: tk.StringVar(value="--")
            for name in ("score", "current", "due", "overdue", "not_started", "next_7", "history", "online")
        }
        self._build_ui()
        self.after(100, self.refresh_data)
        self.after(150, self.poll_results)

    def _build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=22, pady=18)
        tk.Label(outer, text="Security Maintenance Center", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 25, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="Schedule and record thirty-two fixed defensive tasks without entering names, notes, paths, files, keys, PINs, scan results, or customer data.",
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 10),
            wraplength=1180,
            justify="left",
        ).pack(anchor="w", pady=(3, 10))

        actions = tk.Frame(outer, bg=locker.BG)
        actions.pack(fill="x", pady=(0, 9))
        action_specs = (
            ("REFRESH", self.refresh_data, "#252936", locker.TEXT),
            ("COMPLETE SELECTED", self.complete_selected, locker.GREEN, locker.BLACK),
            ("REOPEN SELECTED", self.reopen_selected, "#252936", locker.TEXT),
            ("COMPLETE ROUTINE", self.complete_routine, locker.BLUE, locker.BLACK),
            ("OPEN TRUSTED TOOL", self.open_trusted_tool, "#252936", locker.TEXT),
            ("COPY SUMMARY", self.copy_summary, "#252936", locker.TEXT),
            ("EXPORT JSON", self.export_json, locker.YELLOW, locker.BLACK),
            ("EXPORT TEXT", self.export_text, "#252936", locker.TEXT),
            ("CALENDAR", self.export_calendar, "#252936", locker.TEXT),
            ("EXPORT HISTORY", self.export_history, "#252936", locker.TEXT),
            ("SAVE SNAPSHOT", self.save_snapshot, locker.GREEN, locker.BLACK),
            ("COMPARE SNAPSHOTS", self.compare_snapshots, "#252936", locker.TEXT),
            ("EXPORT ARCHIVE", self.export_archive, locker.YELLOW, locker.BLACK),
            ("PUBLIC PLANNER", self.open_public_planner, locker.BLUE, locker.BLACK),
        )
        for row_specs in (action_specs[:7], action_specs[7:]):
            row = tk.Frame(actions, bg=locker.BG)
            row.pack(fill="x", pady=(0, 6))
            for text, command, color, foreground in row_specs:
                tk.Button(row, text=text, command=command, bg=color, fg=foreground, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(0, 6), ipadx=7, ipady=6)

        selectors = tk.Frame(outer, bg=locker.PANEL)
        selectors.pack(fill="x", pady=(0, 10))
        for column in range(4):
            selectors.grid_columnconfigure(column, weight=1)
        self.category_box = self._selector(selectors, "CATEGORY", self.category_var, 0)
        self.routine_box = self._selector(selectors, "ROUTINE", self.routine_var, 1)
        self.state_box = self._selector(selectors, "STATE", self.state_var, 2)
        self.plan_box = self._selector(selectors, "PLAN WINDOW", self.plan_var, 3)
        self.category_box["values"] = ["All categories"] + [item["title"] for item in LOCAL_CATEGORIES]
        self.routine_box["values"] = ["All tasks"] + [item["label"] for item in LOCAL_ROUTINES]
        self.state_box["values"] = ["All states", "Current", "Due soon", "Overdue", "Not started"]
        self.plan_box["values"] = [item[1] for item in PLANNING_WINDOWS]

        metrics = tk.Frame(outer, bg=locker.PANEL)
        metrics.pack(fill="x", pady=(0, 10))
        metric_specs = (
            ("score", "SCHEDULE SCORE"),
            ("current", "CURRENT"),
            ("due", "DUE SOON"),
            ("overdue", "OVERDUE"),
            ("not_started", "NOT STARTED"),
            ("next_7", "NEXT 7 DAYS"),
            ("history", "EVENTS / SNAPSHOTS"),
            ("online", "ONLINE GUIDE"),
        )
        for column, (name, label) in enumerate(metric_specs):
            metrics.grid_columnconfigure(column, weight=1)
            cell = tk.Frame(metrics, bg=locker.PANEL, highlightthickness=1, highlightbackground="#343b49")
            cell.grid(row=0, column=column, sticky="nsew")
            tk.Label(cell, text=label, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 7, "bold")).pack(anchor="w", padx=10, pady=(8, 2))
            tk.Label(cell, textvariable=self.metric_vars[name], bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 10, "bold"), wraplength=180, justify="left").pack(anchor="w", padx=10, pady=(0, 8))

        split = tk.PanedWindow(outer, orient="horizontal", bg=locker.BG, sashwidth=7, showhandle=False)
        split.pack(fill="both", expand=True)
        left = tk.Frame(split, bg=locker.PANEL)
        right = tk.Frame(split, bg=locker.PANEL)
        split.add(left, minsize=650)
        split.add(right, minsize=420)

        style = ttk.Style(self)
        style.configure("Maintenance.Treeview", background=locker.FIELD, foreground=locker.TEXT, fieldbackground=locker.FIELD, rowheight=30, borderwidth=0)
        style.configure("Maintenance.Treeview.Heading", background="#252936", foreground=locker.TEXT, font=("Segoe UI", 8, "bold"))
        self.tree = ttk.Treeview(left, columns=("state", "due", "category", "task", "cadence"), show="headings", style="Maintenance.Treeview", selectmode="browse")
        for identifier, title, width, stretch in (
            ("state", "STATE", 92, False),
            ("due", "NEXT DUE", 110, False),
            ("category", "CATEGORY", 130, False),
            ("task", "FIXED TASK", 320, True),
            ("cadence", "CADENCE", 70, False),
        ):
            self.tree.heading(identifier, text=title)
            self.tree.column(identifier, width=width, stretch=stretch)
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=12)
        scroll.pack(side="right", fill="y", padx=(0, 12), pady=12)
        self.tree.bind("<<TreeviewSelect>>", self.show_selected_detail)
        self.tree.bind("<Double-1>", lambda _event: self.complete_selected())

        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=12)
        detail_tab = tk.Frame(self.notebook, bg=locker.FIELD)
        dashboard_tab = tk.Frame(self.notebook, bg=locker.FIELD)
        snapshot_tab = tk.Frame(self.notebook, bg=locker.FIELD)
        self.notebook.add(detail_tab, text="TASK DETAIL")
        self.notebook.add(dashboard_tab, text="DASHBOARD")
        self.notebook.add(snapshot_tab, text="SNAPSHOTS")
        self.detail_output = self._output_view(detail_tab)
        self.dashboard_output = self._output_view(dashboard_tab)
        self.snapshot_output = self._output_view(snapshot_tab)
        tk.Label(outer, textvariable=self.status_var, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9), wraplength=1180, justify="left").pack(anchor="w", pady=(9, 0))

    def _output_view(self, parent):
        output = scrolledtext.ScrolledText(parent, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", wrap="word", font=("Consolas", 9), padx=12, pady=12)
        output.pack(fill="both", expand=True)
        output.configure(state="disabled")
        return output

    @staticmethod
    def _set_output(output, text):
        output.configure(state="normal")
        output.delete("1.0", "end")
        output.insert("1.0", text)
        output.configure(state="disabled")

    def _selector(self, parent, label, variable, column):
        frame = tk.Frame(parent, bg=locker.PANEL)
        frame.grid(row=0, column=column, sticky="ew", padx=10, pady=9)
        tk.Label(frame, text=label, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 7, "bold")).pack(anchor="w")
        box = ttk.Combobox(frame, textvariable=variable, state="readonly")
        box.pack(fill="x", pady=(4, 0))
        box.bind("<<ComboboxSelected>>", lambda _event: self.rebuild_report())
        return box

    def selected_category_id(self):
        return next((item["id"] for item in LOCAL_CATEGORIES if item["title"] == self.category_var.get()), "all")

    def selected_routine_id(self):
        return next((item["id"] for item in LOCAL_ROUTINES if item["label"] == self.routine_var.get()), "all")

    def selected_state_id(self):
        mapping = {"Current": "current", "Due soon": "due-soon", "Overdue": "overdue", "Not started": "not-started"}
        return mapping.get(self.state_var.get(), "all")

    def selected_plan_id(self):
        return next((identifier for identifier, label, _days in PLANNING_WINDOWS if label == self.plan_var.get()), "all")

    def visible_tasks(self):
        if not self.report:
            return []
        category_id = self.selected_category_id()
        routine_id = self.selected_routine_id()
        state_id = self.selected_state_id()
        plan_id = self.selected_plan_id()
        allowed = set(ROUTINE_BY_ID[routine_id]["task_ids"]) if routine_id in ROUTINE_BY_ID else set(TASK_BY_ID)
        tasks = [
            item
            for item in self.report["tasks"]
            if (category_id == "all" or item["category_id"] == category_id)
            and item["id"] in allowed
            and (state_id == "all" or item["state"] == state_id)
        ]
        if plan_id == "attention":
            tasks = [item for item in tasks if item["state"] in {"due-soon", "overdue"}]
        elif plan_id != "all":
            maximum_days = next(days for identifier, _label, days in PLANNING_WINDOWS if identifier == plan_id)
            tasks = [item for item in tasks if item["planning_days_remaining"] <= maximum_days]
        priority_rank = {"overdue": 0, "due-soon": 1, "not-started": 2, "current": 3}
        return sorted(
            tasks,
            key=lambda item: (
                priority_rank[item["state"]],
                item["planning_due_utc"],
                item["cadence_days"],
                item["id"],
            ),
        )

    def selected_task_id(self):
        selection = self.tree.selection()
        return selection[0] if selection and selection[0] in TASK_BY_ID else ""

    def refresh_data(self):
        self.status_var.set("Refreshing the fixed guide and verifying local maintenance history...")

        def worker():
            try:
                self.results.put(("refresh", collect_inputs()))
            except Exception as exc:
                self.results.put(("error", _clean_text(exc, "Maintenance refresh failed.", 260)))

        threading.Thread(target=worker, daemon=True).start()

    def poll_results(self):
        try:
            while True:
                kind, payload = self.results.get_nowait()
                if kind == "refresh":
                    self.guide, self.history, self.integrity, self.snapshots, self.snapshot_integrity = payload
                    self.rebuild_report()
                    locker.log_event("maintenance_center_refresh", "fixed_catalog", "ok")
                    self.status_var.set("Maintenance refreshed. No customer progress, history, path, file, key, PIN, or local result was sent to the API.")
                else:
                    locker.log_event("maintenance_center_refresh", "fixed_catalog", "failed")
                    self.status_var.set("Could not refresh Security Maintenance.")
                    messagebox.showerror("Maintenance refresh failed", payload, parent=self)
        except queue.Empty:
            pass
        if self.winfo_exists():
            self.after(150, self.poll_results)

    def rebuild_report(self):
        self.report = build_maintenance_report(
            self.guide,
            self.history,
            self.integrity,
            self.selected_category_id(),
            self.selected_routine_id(),
        )
        summary = self.report["summary"]
        self.metric_vars["score"].set(f"{summary['schedule_score']} | {summary['schedule_label'].upper()}")
        self.metric_vars["current"].set(str(summary["current"]))
        self.metric_vars["due"].set(str(summary["due_soon"]))
        self.metric_vars["overdue"].set(str(summary["overdue"]))
        self.metric_vars["not_started"].set(str(summary["not_started"]))
        self.metric_vars["next_7"].set(str(self.report["planning"]["next_7_days"]))
        event_state = "VALID" if self.report["history"]["integrity_valid"] else "CHECK"
        snapshot_state = "VALID" if self.snapshot_integrity.get("valid") else "CHECK"
        self.metric_vars["history"].set(
            f"{self.report['history']['record_count']} / {len(self.snapshots)} | {event_state}/{snapshot_state}"
        )
        self.metric_vars["online"].set(f"API {self.report['online']['api_version']} | {self.report['online']['service_mode']}")
        previous = self.selected_task_id()
        self.tree.delete(*self.tree.get_children())
        for task in self.visible_tasks():
            due = task["planning_due_utc"][:10]
            self.tree.insert("", "end", iid=task["id"], values=(task["state"].upper(), due, task["category"], task["title"], f"{task['cadence_days']}d"))
        if previous and self.tree.exists(previous):
            self.tree.selection_set(previous)
        self._set_output(self.dashboard_output, dashboard_text(self.report, self.snapshots, self.snapshot_integrity))
        if len(self.snapshots) >= 2:
            comparison = compare_maintenance_snapshots(self.snapshots[-2], self.snapshots[-1])
            snapshot_text = snapshot_comparison_text(comparison)
        elif self.snapshots:
            snapshot_text = (
                "MAINTENANCE SNAPSHOTS\n"
                + "=" * 70
                + f"\nSaved snapshots: 1\nLatest UTC: {self.snapshots[-1]['time_utc']}\n"
                + "Save another snapshot to compare coarse schedule coverage."
            )
        else:
            snapshot_text = "MAINTENANCE SNAPSHOTS\n" + "=" * 70 + "\nNo local snapshots have been saved yet."
        snapshot_text += f"\n\nINTEGRITY\n{'-' * 70}\n{self.snapshot_integrity.get('message', 'Snapshot status unavailable.')}"
        self._set_output(self.snapshot_output, snapshot_text)
        self.show_selected_detail()

    def show_selected_detail(self, _event=None):
        if not self.report:
            return
        task_id = self.selected_task_id()
        text = safe_report_text(self.report)
        if task_id:
            task = next(item for item in self.report["tasks"] if item["id"] == task_id)
            detail = [
                task["title"].upper(),
                "=" * 62,
                f"Category: {task['category']}",
                f"State: {task['state']} | Cadence: {task['cadence_days']} days",
                f"Last completed UTC: {task['last_completed_utc'] or 'not recorded'}",
                f"Next due UTC: {task['next_due_utc'] or 'not scheduled'}",
                f"Planning date UTC: {task['planning_due_utc']}",
                "",
                "ACTION",
                task["action"],
                "",
                "EXPECTED",
                task["expected"],
                "",
                f"Trusted tool: {TRUSTED_TOOL_TARGETS[task_id][0]}",
                "",
                text,
            ]
            text = "\n".join(detail)
        self._set_output(self.detail_output, text)

    def _record_selected(self, state):
        task_id = self.selected_task_id()
        if not task_id:
            messagebox.showinfo("Choose a maintenance task", "Select one fixed task first.", parent=self)
            return
        try:
            append_maintenance_event(task_id, state, "manual")
            self.history, self.integrity = load_maintenance_history()
            action = "maintenance_task_complete" if state == "completed" else "maintenance_task_reopen"
            locker.log_event(action, task_id, "ok")
            self.rebuild_report()
            self.status_var.set(f"Recorded {state} for {TASK_BY_ID[task_id]['title']} in the local hash-chained history.")
        except Exception as exc:
            action = "maintenance_task_complete" if state == "completed" else "maintenance_task_reopen"
            locker.log_event(action, task_id, "failed")
            messagebox.showerror("Could not record maintenance event", str(exc), parent=self)

    def complete_selected(self):
        self._record_selected("completed")

    def reopen_selected(self):
        self._record_selected("reopened")

    def complete_routine(self):
        routine_id = self.selected_routine_id()
        if routine_id == "all":
            routine_id = "full-maintenance"
        routine = ROUTINE_BY_ID[routine_id]
        if not messagebox.askyesno(
            "Complete fixed routine",
            f"Record all {len(routine['task_ids'])} fixed tasks in {routine['label']} as completed now?\n\n"
            "This app records your confirmation. It does not prove that the checks were performed.",
            parent=self,
        ):
            return
        try:
            append_maintenance_events(routine["task_ids"], "completed", "routine")
            self.history, self.integrity = load_maintenance_history()
            locker.log_event("maintenance_routine_complete", routine_id, "ok")
            self.rebuild_report()
            self.status_var.set(f"Recorded {len(routine['task_ids'])} fixed {routine['label']} task(s) in local hash-chained history.")
        except Exception as exc:
            locker.log_event("maintenance_routine_complete", routine_id, "failed")
            messagebox.showerror("Could not complete routine", str(exc), parent=self)

    def open_trusted_tool(self):
        task_id = self.selected_task_id()
        if not task_id:
            messagebox.showinfo("Choose a maintenance task", "Select one fixed task first.", parent=self)
            return
        try:
            label = launch_trusted_task_tool(task_id)
            locker.log_event("maintenance_trusted_tool_open", task_id, "ok")
            self.status_var.set(f"Opened {label} for the selected fixed task.")
        except Exception as exc:
            locker.log_event("maintenance_trusted_tool_open", task_id, "failed")
            messagebox.showerror("Could not open trusted tool", str(exc), parent=self)

    def copy_summary(self):
        if not self.report:
            return
        self.clipboard_clear()
        self.clipboard_append(safe_summary(self.report))
        locker.log_event("maintenance_summary_copy", "safe_summary", "ok")
        self.status_var.set("Copied the privacy-safe maintenance summary.")

    def export_json(self):
        if not self.report:
            return
        path = filedialog.asksaveasfilename(parent=self, title="Export Security Maintenance report", defaultextension=".json", filetypes=[("JSON report", "*.json")], initialfile="vaultlink-security-maintenance.json")
        if not path:
            return
        locker.write_text_atomic(Path(path), json.dumps(self.report, indent=2))
        locker.log_event("maintenance_report_export", "safe_report_json", "ok")
        self.status_var.set("Exported the reviewed privacy-safe maintenance JSON.")

    def export_text(self):
        if not self.report:
            return
        path = filedialog.asksaveasfilename(parent=self, title="Export Security Maintenance report", defaultextension=".txt", filetypes=[("Text report", "*.txt")], initialfile="vaultlink-security-maintenance.txt")
        if not path:
            return
        locker.write_text_atomic(Path(path), safe_report_text(self.report))
        locker.log_event("maintenance_report_export", "safe_report_text", "ok")
        self.status_var.set("Exported the printable privacy-safe maintenance report.")

    def export_calendar(self):
        identifiers = [item["id"] for item in self.visible_tasks()]
        if not identifiers:
            messagebox.showinfo("No visible tasks", "Change the filters so at least one fixed task is visible.", parent=self)
            return
        path = filedialog.asksaveasfilename(parent=self, title="Save maintenance calendar", defaultextension=".ics", filetypes=[("Calendar file", "*.ics")], initialfile="vaultlink-security-maintenance.ics")
        if not path:
            return
        locker.write_text_atomic(Path(path), build_calendar_text(identifiers, self.history))
        locker.log_event("maintenance_calendar_export", "fixed_reminders", "ok")
        self.status_var.set(f"Exported {len(identifiers)} fixed privacy-safe calendar reminder(s).")

    def export_history(self):
        if not self.integrity.get("valid"):
            messagebox.showerror("History integrity check failed", "Preserve the original history and review it before exporting.", parent=self)
            return
        path = filedialog.asksaveasfilename(parent=self, title="Export maintenance history", defaultextension=".json", filetypes=[("JSON history", "*.json")], initialfile="vaultlink-security-maintenance-history.json")
        if not path:
            return
        payload = {
            "schema_version": 1,
            "report_type": "VaultLink Privacy-Safe Security Maintenance History",
            "exported_at_utc": locker.utc_now_text(),
            "record_count": len(self.history),
            "integrity_valid": True,
            "records": self.history,
            "privacy_notice": "Only fixed task IDs, fixed cadence, completion or reopen state, UTC time, anonymous event IDs, and hash-chain fields are included.",
        }
        locker.write_text_atomic(Path(path), json.dumps(payload, indent=2))
        locker.log_event("maintenance_history_export", "hash_chained_history", "ok")
        self.status_var.set("Exported the verified fixed-field maintenance history.")

    def save_snapshot(self):
        if not self.report:
            return
        try:
            record = append_maintenance_snapshot(self.report)
            self.snapshots, self.snapshot_integrity = load_snapshot_history()
            locker.log_event("maintenance_snapshot_save", "coarse_schedule_snapshot", "ok")
            self.rebuild_report()
            self.notebook.select(2)
            self.status_var.set(
                f"Saved local snapshot {record['sequence']} with schedule score {record['schedule_score']} / 100. "
                "This is reminder coverage, not a security-health result."
            )
        except Exception as exc:
            locker.log_event("maintenance_snapshot_save", "coarse_schedule_snapshot", "failed")
            messagebox.showerror("Could not save maintenance snapshot", str(exc), parent=self)

    def compare_snapshots(self):
        if len(self.snapshots) < 2:
            messagebox.showinfo("Two snapshots required", "Save at least two local maintenance snapshots first.", parent=self)
            return
        try:
            comparison = compare_maintenance_snapshots(self.snapshots[-2], self.snapshots[-1])
            self._set_output(self.snapshot_output, snapshot_comparison_text(comparison))
            self.notebook.select(2)
            locker.log_event("maintenance_snapshot_compare", "last_two_snapshots", "ok")
            self.status_var.set("Compared the two newest privacy-safe maintenance snapshots.")
        except Exception as exc:
            locker.log_event("maintenance_snapshot_compare", "last_two_snapshots", "failed")
            messagebox.showerror("Could not compare maintenance snapshots", str(exc), parent=self)

    def export_archive(self):
        try:
            payload = build_maintenance_archive(
                self.history,
                self.integrity,
                self.snapshots,
                self.snapshot_integrity,
            )
        except Exception as exc:
            locker.log_event("maintenance_archive_export", "verified_archive", "failed")
            messagebox.showerror("Could not build maintenance archive", str(exc), parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Export verified maintenance archive",
            defaultextension=".json",
            filetypes=[("JSON archive", "*.json")],
            initialfile="vaultlink-security-maintenance-archive.json",
        )
        if not path:
            return
        locker.write_text_atomic(Path(path), json.dumps(payload, indent=2))
        locker.log_event("maintenance_archive_export", "verified_archive", "ok")
        self.status_var.set(
            f"Exported a non-destructive verified archive with {payload['event_record_count']} event(s) "
            f"and {payload['snapshot_record_count']} snapshot(s)."
        )

    def open_public_planner(self):
        try:
            settings = locker.load_settings()
            state = locker.load_license_state(settings)
            server = locker.validated_license_server_url(state.get("server_url"))
            webbrowser.open(server.rstrip("/") + "/maintenance", new=2)
            locker.log_event("maintenance_online_open", "public_workspace", "ok")
            self.status_var.set("Opened the public current-tab-only Security Maintenance planner.")
        except Exception as exc:
            locker.log_event("maintenance_online_open", "public_workspace", "failed")
            messagebox.showerror("Could not open public maintenance planner", str(exc), parent=self)


if len(LOCAL_CATEGORIES) != 8 or len(LOCAL_TASKS) != 32 or len(LOCAL_ROUTINES) != 6:
    raise RuntimeError("The fixed desktop maintenance catalog cardinality changed unexpectedly.")
if len(CATEGORY_BY_ID) != 8 or len(TASK_BY_ID) != 32 or len(ROUTINE_BY_ID) != 6:
    raise RuntimeError("Desktop maintenance IDs must be unique.")
if any(task["category_id"] not in CATEGORY_BY_ID or task["cadence_days"] not in ALLOWED_CADENCE_DAYS for task in LOCAL_TASKS):
    raise RuntimeError("Desktop maintenance tasks must reference a fixed category and cadence.")
if any(sum(task["category_id"] == category_id for task in LOCAL_TASKS) != 4 for category_id in CATEGORY_BY_ID):
    raise RuntimeError("Every desktop maintenance category must contain exactly four tasks.")
if any(not routine["task_ids"] or len(routine["task_ids"]) != len(set(routine["task_ids"])) or not set(routine["task_ids"]).issubset(TASK_BY_ID) for routine in LOCAL_ROUTINES):
    raise RuntimeError("Desktop maintenance routines must reference unique fixed tasks.")
if set(ROUTINE_BY_ID["full-maintenance"]["task_ids"]) != set(TASK_BY_ID):
    raise RuntimeError("The full desktop maintenance routine must contain every fixed task.")
if set(TRUSTED_TOOL_TARGETS) != set(TASK_BY_ID):
    raise RuntimeError("Every fixed maintenance task must have one trusted-tool target.")
if len(SNAPSHOT_FIELDS) != 13 or len(PLANNING_WINDOWS) != 5:
    raise RuntimeError("Maintenance snapshot or planning schemas changed unexpectedly.")
if set(SCHEDULE_SCORE_WEIGHTS) != set(DISPLAY_STATES) - {"all"}:
    raise RuntimeError("Maintenance schedule scoring must cover every fixed task state.")


if __name__ == "__main__":
    locker.log_event("maintenance_center_open", "local_center", "ok")
    SecurityMaintenanceCenter().mainloop()
