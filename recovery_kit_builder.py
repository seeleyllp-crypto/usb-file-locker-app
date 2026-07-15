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


CENTER_ENDPOINT = "/api/v1/recovery-kit"
HISTORY_PATH = locker.APP_DIR / "recovery_kit_history.jsonl"
SETTINGS_PATH = locker.APP_DIR / "recovery_kit_settings.json"
MAX_HISTORY_RECORDS = 500
MAX_HISTORY_BYTES = 2 * 1024 * 1024
ALLOWED_INTERVAL_DAYS = (7, 14, 30, 60, 90)
REPORT_SCHEMA_VERSION = 1

SECTION_SPECS = (
    ("signed-software", "Application", "Signed software kit", "transparent verified reinstall files", ("software-official-source", "software-version-floor", "software-manifest", "software-package-hash", "software-offline-copy")),
    ("master-key-custody", "Access", "Master-key custody", "independent master-key recovery", ("key-primary-test", "key-independent-copy", "key-id-check", "key-data-separation", "key-trusted-custody")),
    ("optional-pin-plan", "Access", "Optional-PIN plan", "exact optional-PIN recovery without recording the PIN", ("pin-scope", "pin-separate", "pin-exact-rules", "pin-disposable-test", "pin-recovery-boundary")),
    ("locked-data-copies", "Data", "Locked-data copies", "authenticated encrypted-container copies", ("locked-scope-count", "locked-second-copy", "locked-independent-place", "locked-preserve-original", "locked-sample-restore")),
    ("app-data-backup", "Data", "App-data backup", "settings, audit, and vault recovery data", ("appdata-create", "appdata-verify", "appdata-second-copy", "appdata-restore-order", "appdata-recent-check")),
    ("license-device-recovery", "Service", "License and device recovery", "privacy-safe customer and device self-service", ("license-center-route", "license-seat-review", "license-device-remove", "license-offline-boundary", "license-support-route")),
    ("audit-evidence", "Evidence", "Audit evidence kit", "reviewed coarse tamper-evident records", ("audit-chain-valid", "audit-safe-export", "audit-independent-copy", "audit-time-order", "audit-privacy-review")),
    ("trusted-person-handoff", "People", "Trusted-person handoff", "a fixed adult-assisted restore order", ("person-choose-adult", "person-explain-parts", "person-separate-secrets", "person-emergency-boundary", "person-practice")),
    ("first-hour-response", "Response", "First-hour response", "bounded first actions that preserve recovery options", ("response-stop-changes", "response-preserve-originals", "response-security-check", "response-choose-runbook", "response-disposable-first")),
    ("continuity-review", "Recovery", "Continuity review", "repeatable schedules and coarse checkpoints", ("review-objective", "review-copy-target", "review-interval", "review-snapshot", "review-escalation")),
)

PROFILE_SPECS = (
    ("personal-pc", "Personal PC", "A complete personal recovery kit for one Windows PC.", ("signed-software", "master-key-custody", "optional-pin-plan", "locked-data-copies", "app-data-backup", "license-device-recovery", "audit-evidence", "first-hour-response", "continuity-review")),
    ("family-handoff", "Family handoff", "A recovery kit that a trusted adult can follow without receiving secrets here.", tuple(item[0] for item in SECTION_SPECS)),
    ("travel-device", "Travel device", "A compact kit for device loss, replacement, and account recovery while away.", ("signed-software", "master-key-custody", "optional-pin-plan", "app-data-backup", "license-device-recovery", "first-hour-response", "continuity-review")),
    ("small-office", "Small office", "A synthetic continuity kit for a small team without client or employee data.", tuple(item[0] for item in SECTION_SPECS)),
    ("high-assurance", "High-assurance review", "Every fixed section for customers who want the broadest recovery rehearsal.", tuple(item[0] for item in SECTION_SPECS)),
)

RUNBOOK_SPECS = (
    ("replacement-pc", "Replacement PC", "Restore on a replacement Windows PC in a controlled order."),
    ("lost-master-usb", "Lost master USB", "Protect recovery options when a master-key copy is missing."),
    ("suspected-malware", "Suspected malware", "Preserve evidence and protect backups without running a malware simulation."),
    ("unlock-failure", "Unlock failure", "Troubleshoot an unlock failure without damaging the locked source."),
    ("service-outage", "Service outage", "Keep local recovery separate from temporary API availability."),
)

RUNBOOK_FALLBACK_STEPS = (
    "Stop unnecessary changes and preserve the original source.",
    "Choose the matching trusted local VaultLink or Windows tool.",
    "Work from a copy and use disposable non-private data first.",
    "Verify the key, app, backup, or service dependency locally.",
    "Keep keys, PINs, paths, files, and identity out of support messages.",
    "Escalate to a trusted adult or qualified professional before destructive action.",
)

KIT_READINESS_CHECKS = (
    ("defender-protection", "Security", "Microsoft Defender protection", 10),
    ("defender-signatures", "Security", "Defender signatures current", 5),
    ("audit-chain", "Evidence", "Local audit integrity", 10),
    ("owner-usb-policy", "Access", "Owner USB policy", 10),
    ("selected-key", "Access", "Selected USB key available", 20),
    ("recovery-test", "Recovery", "Disposable recovery test recorded", 10),
    ("app-data-backup", "Data", "App-data backup available", 15),
    ("signed-release", "Application", "Verified signed release", 10),
    ("app-data-access", "Storage", "App-data access", 5),
    ("cryptography-package", "Application", "Encryption dependency", 5),
)


def _title_from_id(identifier):
    return str(identifier).replace("-", " ").strip().title()


def local_kit_sections():
    sections = []
    for section_id, category, title, focus, item_ids in SECTION_SPECS:
        items = []
        for index, item_id in enumerate(item_ids, 1):
            items.append(
                {
                    "id": item_id,
                    "title": _title_from_id(item_id),
                    "action": f"Review fixed recovery item {index} for {focus} without recording paths, names, secrets, or file contents.",
                    "expected": "The fixed item is understood and can be rehearsed with disposable data.",
                }
            )
        sections.append({"id": section_id, "category": category, "title": title, "summary": f"Prepare {focus}.", "items": items})
    return sections


def local_kit_profiles():
    return [
        {"id": identifier, "label": label, "summary": summary, "section_ids": list(section_ids)}
        for identifier, label, summary, section_ids in PROFILE_SPECS
    ]


def local_emergency_runbooks():
    return [
        {"id": identifier, "label": label, "summary": summary, "steps": list(RUNBOOK_FALLBACK_STEPS)}
        for identifier, label, summary in RUNBOOK_SPECS
    ]


LOCAL_SECTIONS = local_kit_sections()
LOCAL_PROFILES = local_kit_profiles()
LOCAL_RUNBOOKS = local_emergency_runbooks()
VALID_SECTION_IDS = frozenset(item["id"] for item in LOCAL_SECTIONS)
VALID_ITEM_IDS = frozenset(item["id"] for section in LOCAL_SECTIONS for item in section["items"])
VALID_PROFILE_IDS = frozenset(item["id"] for item in LOCAL_PROFILES)
VALID_RUNBOOK_IDS = frozenset(item["id"] for item in LOCAL_RUNBOOKS)
VALID_CHECK_IDS = frozenset(item[0] for item in KIT_READINESS_CHECKS)

SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "sequence",
        "time_utc",
        "event_id",
        "profile_id",
        "runbook_id",
        "completed_item_ids",
        "completed_count",
        "total_items",
        "readiness_score",
        "interval_days",
        "previous_hash",
        "hash",
    }
)


def _fallback_guide(message="Online Recovery Kit catalog unavailable."):
    return {
        "ok": False,
        "recovery_kit_schema_version": 1,
        "api_version": "Unavailable",
        "service_status": {"mode": "offline", "message": message},
        "signed_release": {"ready": False, "version": "", "minimum_supported_version": ""},
        "profiles": LOCAL_PROFILES,
        "sections": LOCAL_SECTIONS,
        "runbooks": LOCAL_RUNBOOKS,
        "review_intervals": list(ALLOWED_INTERVAL_DAYS),
        "privacy_boundaries": [
            "The public API receives no customer progress, key, PIN, path, file, identity, contact, receipt, or local result.",
            "Desktop snapshots contain only fixed IDs, coarse scores and totals, interval, UTC time, event ID, and hash-chain fields.",
            "The kit does not unlock files, inspect arbitrary documents, upload backups, or remotely control a PC.",
        ],
        "limitations": [
            "A completed kit cannot guarantee future recovery or replace tested independent backups.",
            "Suspected-malware guidance is defensive and tabletop only; no malware or destructive simulation is run.",
            "Use Microsoft Defender, trusted adults, and qualified responders for high-impact decisions.",
        ],
    }


def safe_recovery_kit_guide(payload):
    fallback = _fallback_guide()
    source = payload if isinstance(payload, dict) else {}

    def clean(value, default, limit=320):
        return trust.safe_online_text(value, default, limit)

    def clean_list(value, defaults):
        if not isinstance(value, list):
            return list(defaults)
        cleaned = [clean(item, "", 360) for item in value[:6]]
        cleaned = [item for item in cleaned if item]
        return cleaned or list(defaults)

    raw_sections = {str(item.get("id")): item for item in source.get("sections", []) if isinstance(item, dict)}
    sections = []
    for expected in LOCAL_SECTIONS:
        raw = raw_sections.get(expected["id"], {})
        raw_items = {str(item.get("id")): item for item in raw.get("items", []) if isinstance(item, dict)}
        items = []
        for expected_item in expected["items"]:
            item = raw_items.get(expected_item["id"], {})
            items.append(
                {
                    "id": expected_item["id"],
                    "title": clean(item.get("title"), expected_item["title"], 120),
                    "action": clean(item.get("action"), expected_item["action"], 360),
                    "expected": clean(item.get("expected"), expected_item["expected"], 260),
                }
            )
        sections.append(
            {
                "id": expected["id"],
                "category": expected["category"],
                "title": clean(raw.get("title"), expected["title"], 120),
                "summary": clean(raw.get("summary"), expected["summary"], 260),
                "items": items,
            }
        )

    raw_profiles = {str(item.get("id")): item for item in source.get("profiles", []) if isinstance(item, dict)}
    profiles = []
    for expected in LOCAL_PROFILES:
        raw = raw_profiles.get(expected["id"], {})
        profiles.append(
            {
                "id": expected["id"],
                "label": clean(raw.get("label"), expected["label"], 100),
                "summary": clean(raw.get("summary"), expected["summary"], 260),
                "section_ids": list(expected["section_ids"]),
            }
        )

    raw_runbooks = {str(item.get("id")): item for item in source.get("runbooks", []) if isinstance(item, dict)}
    runbooks = []
    for expected in LOCAL_RUNBOOKS:
        raw = raw_runbooks.get(expected["id"], {})
        raw_steps = raw.get("steps") if isinstance(raw.get("steps"), list) and len(raw["steps"]) == 6 else expected["steps"]
        runbooks.append(
            {
                "id": expected["id"],
                "label": clean(raw.get("label"), expected["label"], 100),
                "summary": clean(raw.get("summary"), expected["summary"], 260),
                "steps": [clean(raw_steps[index], expected["steps"][index], 360) for index in range(6)],
            }
        )

    service = source.get("service_status") if isinstance(source.get("service_status"), dict) else {}
    release = source.get("signed_release") if isinstance(source.get("signed_release"), dict) else {}
    return {
        "ok": bool(source.get("ok")),
        "recovery_kit_schema_version": 1,
        "api_version": clean(source.get("api_version"), "Unavailable", 80),
        "service_status": {"mode": clean(service.get("mode"), "unknown", 40), "message": clean(service.get("message"), "Status unavailable.", 220)},
        "signed_release": {
            "ready": bool(release.get("ready")),
            "version": clean(release.get("version"), "", 40),
            "minimum_supported_version": clean(release.get("minimum_supported_version"), "", 40),
        },
        "profiles": profiles,
        "sections": sections,
        "runbooks": runbooks,
        "review_intervals": list(ALLOWED_INTERVAL_DAYS),
        "privacy_boundaries": clean_list(source.get("privacy_boundaries"), fallback["privacy_boundaries"]),
        "limitations": clean_list(source.get("limitations"), fallback["limitations"]),
        "accepts_free_text": False,
        "accepts_files": False,
        "accepts_paths": False,
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


def _profile_item_ids(profile_id):
    profile = next(item for item in LOCAL_PROFILES if item["id"] == profile_id)
    sections = set(profile["section_ids"])
    return frozenset(item["id"] for section in LOCAL_SECTIONS if section["id"] in sections for item in section["items"])


def _validate_snapshot(record, sequence, previous_hash):
    if not isinstance(record, dict) or set(record) != SNAPSHOT_FIELDS or record.get("schema_version") != 1:
        raise ValueError(f"Recovery Kit snapshot {sequence} has an invalid fixed schema.")
    if type(record.get("sequence")) is not int or record["sequence"] != sequence:
        raise ValueError(f"Recovery Kit snapshot {sequence} has an invalid sequence.")
    if record.get("previous_hash") != previous_hash or not _is_lower_hex(record.get("previous_hash"), 64):
        raise ValueError(f"Recovery Kit snapshot {sequence} broke the hash chain.")
    if not _is_lower_hex(record.get("hash"), 64) or not _is_lower_hex(record.get("event_id"), 16):
        raise ValueError(f"Recovery Kit snapshot {sequence} has an invalid identifier.")
    if locker.parse_utc_text(record.get("time_utc")) is None or len(str(record.get("time_utc"))) > 40:
        raise ValueError(f"Recovery Kit snapshot {sequence} has an invalid timestamp.")
    profile_id = record.get("profile_id")
    if profile_id not in VALID_PROFILE_IDS or record.get("runbook_id") not in VALID_RUNBOOK_IDS:
        raise ValueError(f"Recovery Kit snapshot {sequence} contains an unknown fixed value.")
    completed = record.get("completed_item_ids")
    if not isinstance(completed, list) or any(not isinstance(value, str) for value in completed) or completed != sorted(set(completed)):
        raise ValueError(f"Recovery Kit snapshot {sequence} has invalid fixed item states.")
    allowed_items = _profile_item_ids(profile_id)
    if not set(completed).issubset(allowed_items):
        raise ValueError(f"Recovery Kit snapshot {sequence} has invalid fixed item states.")
    numeric = (record.get("completed_count"), record.get("total_items"), record.get("readiness_score"), record.get("interval_days"))
    if any(type(value) is not int for value in numeric):
        raise ValueError(f"Recovery Kit snapshot {sequence} has an invalid numeric value.")
    if record["completed_count"] != len(completed) or record["total_items"] != len(allowed_items):
        raise ValueError(f"Recovery Kit snapshot {sequence} has inconsistent fixed totals.")
    if not 0 <= record["readiness_score"] <= 100 or record["interval_days"] not in ALLOWED_INTERVAL_DAYS:
        raise ValueError(f"Recovery Kit snapshot {sequence} has an out-of-range fixed value.")


def load_snapshot_history(path=HISTORY_PATH):
    path = Path(path)
    if not path.is_file():
        return [], {"valid": True, "message": "No Recovery Kit snapshots have been saved yet."}
    try:
        if path.stat().st_size > MAX_HISTORY_BYTES:
            raise ValueError("Recovery Kit history is larger than the safety limit.")
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) > MAX_HISTORY_RECORDS:
            raise ValueError("Recovery Kit history exceeds the 500-record safety limit.")
        previous_hash = "0" * 64
        records = []
        for sequence, line in enumerate(lines, 1):
            record = json.loads(line)
            _validate_snapshot(record, sequence, previous_hash)
            expected = hashlib.sha256(_canonical_record(record)).hexdigest()
            if not secrets.compare_digest(str(record.get("hash", "")), expected):
                raise ValueError(f"Recovery Kit snapshot {sequence} failed its hash check.")
            records.append(record)
            previous_hash = expected
        return records, {"valid": True, "message": f"Verified {len(records)} hash-chained Recovery Kit snapshot(s)."}
    except Exception as exc:
        return [], {"valid": False, "message": str(exc)[:300]}


def append_snapshot(profile_id, runbook_id, completed_item_ids, readiness_score, interval_days, path=HISTORY_PATH, time_utc=""):
    profile_id = str(profile_id or "")
    runbook_id = str(runbook_id or "")
    readiness_score = int(readiness_score)
    interval_days = int(interval_days)
    if profile_id not in VALID_PROFILE_IDS or runbook_id not in VALID_RUNBOOK_IDS:
        raise ValueError("Choose only a fixed Recovery Kit profile and emergency runbook.")
    allowed_items = _profile_item_ids(profile_id)
    completed = sorted(set(str(value) for value in (completed_item_ids or [])))
    if not set(completed).issubset(allowed_items) or not 0 <= readiness_score <= 100 or interval_days not in ALLOWED_INTERVAL_DAYS:
        raise ValueError("The Recovery Kit snapshot contains an invalid fixed value.")
    path = Path(path)
    records, integrity = load_snapshot_history(path)
    if not integrity["valid"]:
        raise ValueError("Recovery Kit snapshot integrity failed. Preserve the file and review it before adding records.")
    if len(records) >= MAX_HISTORY_RECORDS:
        raise ValueError("Recovery Kit history reached its 500-record limit. Export and archive it first.")
    record = {
        "schema_version": 1,
        "sequence": len(records) + 1,
        "time_utc": time_utc or locker.utc_now_text(),
        "event_id": secrets.token_hex(8),
        "profile_id": profile_id,
        "runbook_id": runbook_id,
        "completed_item_ids": completed,
        "completed_count": len(completed),
        "total_items": len(allowed_items),
        "readiness_score": readiness_score,
        "interval_days": interval_days,
        "previous_hash": records[-1]["hash"] if records else "0" * 64,
    }
    record["hash"] = hashlib.sha256(_canonical_record(record)).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    return record


def load_settings(path=SETTINGS_PATH):
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except Exception:
        raw = {}
    profile_id = str(raw.get("profile_id", "personal-pc"))
    runbook_id = str(raw.get("runbook_id", "replacement-pc"))
    try:
        interval_days = int(raw.get("interval_days", 30))
    except (TypeError, ValueError):
        interval_days = 30
    return {
        "profile_id": profile_id if profile_id in VALID_PROFILE_IDS else "personal-pc",
        "runbook_id": runbook_id if runbook_id in VALID_RUNBOOK_IDS else "replacement-pc",
        "interval_days": interval_days if interval_days in ALLOWED_INTERVAL_DAYS else 30,
    }


def save_settings(profile_id, runbook_id, interval_days, path=SETTINGS_PATH):
    profile_id = str(profile_id or "")
    runbook_id = str(runbook_id or "")
    interval_days = int(interval_days)
    if profile_id not in VALID_PROFILE_IDS or runbook_id not in VALID_RUNBOOK_IDS or interval_days not in ALLOWED_INTERVAL_DAYS:
        raise ValueError("Choose only fixed Recovery Kit settings.")
    payload = {"schema_version": 1, "profile_id": profile_id, "runbook_id": runbook_id, "interval_days": interval_days}
    locker.write_text_atomic(Path(path), json.dumps(payload, indent=2))
    return payload


def _next_due(records, interval_days):
    if not records:
        return "Not scheduled until the first snapshot"
    latest = locker.parse_utc_text(records[-1].get("time_utc"))
    if not latest:
        return "Unknown"
    return (latest + timedelta(days=int(interval_days))).strftime("%Y-%m-%dT%H:%M:%SZ")


def _comparison(records):
    if len(records) < 2:
        return {"available": False, "coverage_delta": 0, "readiness_delta": 0, "gained_item_ids": [], "lost_item_ids": []}
    previous, current = records[-2], records[-1]
    old_items = set(previous.get("completed_item_ids", []))
    new_items = set(current.get("completed_item_ids", []))
    return {
        "available": True,
        "coverage_delta": int(current.get("completed_count", 0)) - int(previous.get("completed_count", 0)),
        "readiness_delta": int(current.get("readiness_score", 0)) - int(previous.get("readiness_score", 0)),
        "gained_item_ids": sorted(new_items - old_items),
        "lost_item_ids": sorted(old_items - new_items),
    }


def build_recovery_kit_report(diagnostic_report, online_guide, profile_id="personal-pc", runbook_id="replacement-pc", completed_item_ids=None, interval_days=30, history=None, integrity=None, generated_at_utc=""):
    diagnostic_report = diagnostic_report if isinstance(diagnostic_report, dict) else {}
    guide = safe_recovery_kit_guide(online_guide)
    profile_id = profile_id if profile_id in VALID_PROFILE_IDS else "personal-pc"
    runbook_id = runbook_id if runbook_id in VALID_RUNBOOK_IDS else "replacement-pc"
    try:
        interval_days = int(interval_days)
    except (TypeError, ValueError):
        interval_days = 30
    if interval_days not in ALLOWED_INTERVAL_DAYS:
        interval_days = 30
    profile = next(item for item in guide["profiles"] if item["id"] == profile_id)
    runbook = next(item for item in guide["runbooks"] if item["id"] == runbook_id)
    allowed_sections = set(profile["section_ids"])
    sections = [item for item in guide["sections"] if item["id"] in allowed_sections]
    allowed_items = {item["id"] for section in sections for item in section["items"]}
    completed = sorted(allowed_items.intersection(str(value) for value in (completed_item_ids or [])))
    check_map = {str(item.get("id")): item for item in diagnostic_report.get("checks", []) if isinstance(item, dict) and item.get("id")}
    checks = []
    for identifier, category, title, weight in KIT_READINESS_CHECKS:
        source = check_map.get(identifier, {})
        passed = bool(source.get("passed"))
        checks.append(
            {
                "id": identifier,
                "category": category,
                "title": title,
                "state": "ready" if passed else "attention",
                "passed": passed,
                "weight": weight,
                "detail": trust.safe_online_text(source.get("detail"), "This readiness result is unavailable.", 320),
                "action": trust.safe_online_text(source.get("action"), "Run Diagnostics Center and review the failed fixed check.", 320),
            }
        )
    readiness_score = sum(item["weight"] for item in checks if item["passed"])
    coverage_score = round((len(completed) / len(allowed_items)) * 100) if allowed_items else 0
    history = list(history or [])
    integrity = integrity if isinstance(integrity, dict) else {"valid": True, "message": "No history loaded."}
    recent = []
    for item in history[-25:]:
        if not isinstance(item, dict) or item.get("profile_id") not in VALID_PROFILE_IDS:
            continue
        recent.append({field: item.get(field) for field in SNAPSHOT_FIELDS})
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": "VaultLink Privacy-Safe Recovery Kit Report",
        "generated_at_utc": generated_at_utc or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "desktop_version": locker.DESKTOP_APP_VERSION,
        "runtime": "owner_lab" if locker.LAB_MODE else "customer",
        "profile": {
            "id": profile["id"],
            "label": profile["label"],
            "summary": profile["summary"],
            "section_ids": list(profile["section_ids"]),
            "section_count": len(sections),
            "item_count": len(allowed_items),
            "completed_item_ids": completed,
            "completed_count": len(completed),
            "coverage_score": coverage_score,
        },
        "sections": sections,
        "runbook": runbook,
        "review_interval_days": interval_days,
        "readiness": {
            "value": readiness_score,
            "maximum": 100,
            "label": "ready" if readiness_score >= 90 else "prepared" if readiness_score >= 70 else "attention" if readiness_score >= 50 else "action",
            "passed": sum(item["passed"] for item in checks),
            "total": len(checks),
            "attention": sum(not item["passed"] for item in checks),
            "ready_check_ids": [item["id"] for item in checks if item["passed"]],
        },
        "checks": checks,
        "history": {
            "integrity_valid": bool(integrity.get("valid")),
            "integrity_message": str(integrity.get("message") or "History status unavailable.")[:300],
            "record_count": len(history),
            "next_due_utc": _next_due(history, interval_days),
            "comparison": _comparison(history),
            "recent_records": recent,
        },
        "online_catalog": {
            "available": bool(guide.get("ok")),
            "api_version": guide.get("api_version", "Unavailable"),
            "service_mode": guide.get("service_status", {}).get("mode", "unknown"),
            "signed_release_ready": bool(guide.get("signed_release", {}).get("ready")),
            "signed_release_version": guide.get("signed_release", {}).get("version", ""),
            "profiles": len(guide["profiles"]),
            "sections": len(guide["sections"]),
            "items": sum(len(item["items"]) for item in guide["sections"]),
            "runbooks": len(guide["runbooks"]),
        },
        "privacy_notice": "This report contains only fixed recovery text, fixed IDs, coarse completion totals, scores, interval, time, and hash-chain fields. It excludes names, contacts, license proof, keys, PINs, paths, filenames, file contents, receipts, screenshots, process lists, and free-form notes.",
        "limitations": list(guide.get("limitations") or _fallback_guide()["limitations"]),
    }


def build_calendar_text(interval_days, now_utc=None, event_id=""):
    interval_days = int(interval_days)
    if interval_days not in ALLOWED_INTERVAL_DAYS:
        raise ValueError("Choose a fixed Recovery Kit review interval.")
    now = now_utc or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    review = now + timedelta(days=interval_days)
    uid = event_id if _is_lower_hex(event_id, 16) else secrets.token_hex(8)
    return "\r\n".join(
        [
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "PRODID:-//VaultLink//Recovery Kit Review//EN",
            "BEGIN:VEVENT",
            f"UID:{uid}@vaultlink.local",
            f"DTSTAMP:{now.strftime('%Y%m%dT%H%M%SZ')}",
            f"DTSTART:{review.strftime('%Y%m%dT%H%M%SZ')}",
            "DURATION:PT30M",
            "SUMMARY:VaultLink Recovery Kit Review",
            "DESCRIPTION:Review fixed kit items with disposable data. Do not put keys, PINs, paths, filenames, file contents, or personal details in this calendar event.",
            "END:VEVENT",
            "END:VCALENDAR",
            "",
        ]
    )


def safe_report_text(report):
    profile = report["profile"]
    readiness = report["readiness"]
    history = report["history"]
    comparison = history["comparison"]
    completed = set(profile["completed_item_ids"])
    lines = [
        "VAULTLINK RECOVERY KIT",
        "======================",
        f"PROFILE              {profile['label']}",
        f"KIT COVERAGE         {profile['completed_count']} / {profile['item_count']} | {profile['coverage_score']}%",
        f"LOCAL READINESS      {readiness['value']} / 100 | {readiness['passed']} / {readiness['total']} checks",
        f"EMERGENCY RUNBOOK    {report['runbook']['label']}",
        f"REVIEW INTERVAL      {report['review_interval_days']} days",
        f"LOCAL SNAPSHOTS      {history['record_count']} | {'VALID' if history['integrity_valid'] else 'CHECK'}",
        f"NEXT REVIEW          {history['next_due_utc']}",
        f"GENERATED            {report['generated_at_utc']}",
        "",
    ]
    if comparison["available"]:
        lines.extend(
            [
                "SNAPSHOT COMPARISON",
                "-------------------",
                f"Coverage item change: {comparison['coverage_delta']:+d}",
                f"Readiness score change: {comparison['readiness_delta']:+d}",
                f"Items gained: {', '.join(comparison['gained_item_ids']) or 'none'}",
                f"Items lost: {', '.join(comparison['lost_item_ids']) or 'none'}",
                "",
            ]
        )
    lines.extend(["KIT ITEMS", "---------"])
    for section in report["sections"]:
        lines.extend(["", f"{section['category'].upper()} | {section['title']}", section["summary"]])
        for item in section["items"]:
            marker = "X" if item["id"] in completed else " "
            lines.extend([f"[{marker}] {item['title']}", f"    {item['action']}", f"    EXPECTED: {item['expected']}"])
    lines.extend(["", "FIRST-HOUR RUNBOOK", "------------------", report["runbook"]["summary"]])
    lines.extend(f"{index}. {step}" for index, step in enumerate(report["runbook"]["steps"], 1))
    lines.extend(["", "PRIVACY", "-------", report["privacy_notice"], "", "LIMITATIONS", "-----------"])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines)


def safe_summary(report):
    profile = report["profile"]
    readiness = report["readiness"]
    return "\n".join(
        [
            f"VaultLink Recovery Kit: {profile['label']}",
            f"Coverage: {profile['completed_count']}/{profile['item_count']} items ({profile['coverage_score']}%)",
            f"Local readiness: {readiness['value']}/100 ({readiness['label']})",
            f"Runbook: {report['runbook']['label']} | review every {report['review_interval_days']} days",
            f"Snapshots: {report['history']['record_count']} | integrity: {'valid' if report['history']['integrity_valid'] else 'review'}",
            "No names, contacts, license proof, keys, PINs, paths, filenames, contents, receipts, or notes are included.",
        ]
    )


def collect_inputs():
    diagnostic_report = diagnostics.collect_diagnostics_report()
    guide = _fallback_guide()
    try:
        app_settings = locker.load_settings()
        state = locker.load_license_state(app_settings)
        server = locker.validated_license_server_url(state.get("server_url"))
        guide = safe_recovery_kit_guide(locker.license_api_get_json(server, CENTER_ENDPOINT))
    except Exception:
        pass
    history, integrity = load_snapshot_history()
    return diagnostic_report, guide, history, integrity, load_settings()


class RecoveryKitBuilder(tk.Tk):
    def __init__(self):
        super().__init__()
        if not locker.ensure_license_feature("recovery-kit-builder", parent=self):
            self.after(0, self.destroy)
            return
        self.title("VaultLink Recovery Kit Builder")
        self.geometry("1200x900")
        self.minsize(1020, 760)
        self.configure(bg=locker.BG)
        self.results = queue.Queue()
        self.guide = _fallback_guide()
        self.diagnostic_report = {}
        self.history = []
        self.integrity = {"valid": True, "message": "No history loaded."}
        self.settings = load_settings()
        self.completed = set()
        self.report = None
        self.status_var = tk.StringVar(value="Ready to build a privacy-safe recovery kit.")
        self.profile_var = tk.StringVar(value="")
        self.section_var = tk.StringVar(value="ALL")
        self.runbook_var = tk.StringVar(value="")
        self.interval_var = tk.StringVar(value=f"{self.settings['interval_days']} days")
        self.metric_vars = {name: tk.StringVar(value="--") for name in ("coverage", "readiness", "catalog", "runbook", "history", "due")}
        self._build_ui()
        self.after(120, self.refresh_data)
        self.after(150, self.poll_results)

    def _build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=22, pady=18)
        tk.Label(outer, text="Recovery Kit Builder", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 25, "bold")).pack(anchor="w")
        tk.Label(outer, text="Prepare fixed recovery steps, a first-hour runbook, and a review schedule without entering identity, contacts, secrets, paths, or file contents.", bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 10), wraplength=1120, justify="left").pack(anchor="w", pady=(3, 11))

        actions = tk.Frame(outer, bg=locker.BG)
        actions.pack(fill="x", pady=(0, 9))
        for text, command, color, foreground in (
            ("REFRESH", self.refresh_data, "#252936", locker.TEXT),
            ("MARK NEXT", self.mark_next, locker.GREEN, locker.BLACK),
            ("MARK SECTION", self.mark_section, "#252936", locker.TEXT),
            ("RESET", self.reset_progress, "#252936", locker.TEXT),
            ("SAVE SNAPSHOT", self.save_snapshot, locker.BLUE, locker.BLACK),
            ("EXPORT JSON", self.export_json, locker.YELLOW, locker.BLACK),
            ("EXPORT TEXT", self.export_text, "#252936", locker.TEXT),
            ("CALENDAR", self.export_calendar, "#252936", locker.TEXT),
            ("COPY RUNBOOK", self.copy_runbook, "#252936", locker.TEXT),
            ("PUBLIC KIT", self.open_public_kit, locker.BLUE, locker.BLACK),
        ):
            tk.Button(actions, text=text, command=command, bg=color, fg=foreground, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(0, 7), ipadx=8, ipady=6)

        selectors = tk.Frame(outer, bg=locker.PANEL)
        selectors.pack(fill="x", pady=(0, 10))
        for column in range(4):
            selectors.grid_columnconfigure(column, weight=1)
        self.profile_box = self._selector(selectors, "KIT PROFILE", self.profile_var, 0, self.selection_changed)
        self.section_box = self._selector(selectors, "SECTION", self.section_var, 1, self.section_changed)
        self.runbook_box = self._selector(selectors, "EMERGENCY RUNBOOK", self.runbook_var, 2, self.selection_changed)
        self.interval_box = self._selector(selectors, "REVIEW INTERVAL", self.interval_var, 3, self.selection_changed)

        metrics = tk.Frame(outer, bg=locker.PANEL)
        metrics.pack(fill="x", pady=(0, 10))
        for column, (name, label) in enumerate((("coverage", "KIT COVERAGE"), ("readiness", "LOCAL READINESS"), ("catalog", "SECTIONS / ITEMS"), ("runbook", "RUNBOOK"), ("history", "SNAPSHOTS"), ("due", "NEXT REVIEW"))):
            metrics.grid_columnconfigure(column, weight=1)
            cell = tk.Frame(metrics, bg=locker.PANEL, highlightthickness=1, highlightbackground=locker.BORDER)
            cell.grid(row=0, column=column, sticky="nsew")
            tk.Label(cell, text=label, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 7, "bold")).pack(anchor="w", padx=10, pady=(8, 2))
            tk.Label(cell, textvariable=self.metric_vars[name], bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 10, "bold"), wraplength=175, justify="left").pack(anchor="w", padx=10, pady=(0, 8))

        split = tk.PanedWindow(outer, orient="horizontal", bg=locker.BG, sashwidth=7, showhandle=False)
        split.pack(fill="both", expand=True)
        left = tk.Frame(split, bg=locker.PANEL)
        right = tk.Frame(split, bg=locker.PANEL)
        split.add(left, minsize=540)
        split.add(right, minsize=430)

        style = ttk.Style(self)
        style.configure("RecoveryKit.Treeview", background=locker.FIELD, foreground=locker.TEXT, fieldbackground=locker.FIELD, rowheight=30, borderwidth=0)
        style.configure("RecoveryKit.Treeview.Heading", background="#252936", foreground=locker.TEXT, font=("Segoe UI", 8, "bold"))
        self.tree = ttk.Treeview(left, columns=("state", "section", "item"), show="headings", style="RecoveryKit.Treeview", selectmode="browse")
        self.tree.heading("state", text="DONE")
        self.tree.heading("section", text="SECTION")
        self.tree.heading("item", text="FIXED KIT ITEM")
        self.tree.column("state", width=52, stretch=False, anchor="center")
        self.tree.column("section", width=145, stretch=False)
        self.tree.column("item", width=420, stretch=True)
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=12)
        scroll.pack(side="right", fill="y", padx=(0, 12), pady=12)
        self.tree.bind("<Double-1>", self.toggle_tree_item)
        self.tree.bind("<Return>", self.toggle_tree_item)

        self.output = scrolledtext.ScrolledText(right, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", wrap="word", font=("Consolas", 9), padx=12, pady=12)
        self.output.pack(fill="both", expand=True, padx=12, pady=12)
        self.output.configure(state="disabled")
        tk.Label(outer, textvariable=self.status_var, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9), wraplength=1120, justify="left").pack(anchor="w", pady=(9, 0))

    def _selector(self, parent, label, variable, column, command):
        frame = tk.Frame(parent, bg=locker.PANEL)
        frame.grid(row=0, column=column, sticky="ew", padx=10, pady=9)
        tk.Label(frame, text=label, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 7, "bold")).pack(anchor="w")
        box = ttk.Combobox(frame, textvariable=variable, state="readonly")
        box.pack(fill="x", pady=(4, 0))
        box.bind("<<ComboboxSelected>>", command)
        return box

    def refresh_data(self):
        self.status_var.set("Refreshing fixed Recovery Kit catalog, local readiness, and snapshot integrity...")

        def worker():
            try:
                self.results.put(("refresh", collect_inputs()))
            except Exception as exc:
                self.results.put(("error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def poll_results(self):
        try:
            while True:
                kind, payload = self.results.get_nowait()
                if kind == "refresh":
                    self.diagnostic_report, self.guide, self.history, self.integrity, self.settings = payload
                    self.populate_selectors()
                    self.rebuild_report()
                    self.status_var.set("Recovery Kit refreshed. No identity, contacts, secrets, paths, files, or customer progress were sent to the API.")
                else:
                    self.status_var.set("Could not refresh Recovery Kit data.")
                    messagebox.showerror("Recovery Kit refresh failed", payload, parent=self)
        except queue.Empty:
            pass
        if self.winfo_exists():
            self.after(150, self.poll_results)

    def populate_selectors(self):
        profiles = self.guide["profiles"]
        runbooks = self.guide["runbooks"]
        self.profile_box["values"] = [item["label"] for item in profiles]
        self.runbook_box["values"] = [item["label"] for item in runbooks]
        self.interval_box["values"] = [f"{item} days" for item in ALLOWED_INTERVAL_DAYS]
        profile = next((item for item in profiles if item["id"] == self.settings["profile_id"]), profiles[0])
        runbook = next((item for item in runbooks if item["id"] == self.settings["runbook_id"]), runbooks[0])
        self.profile_var.set(profile["label"])
        self.runbook_var.set(runbook["label"])
        self.interval_var.set(f"{self.settings['interval_days']} days")
        self.populate_sections()

    def selected_profile(self):
        return next((item for item in self.guide["profiles"] if item["label"] == self.profile_var.get()), self.guide["profiles"][0])

    def selected_runbook(self):
        return next((item for item in self.guide["runbooks"] if item["label"] == self.runbook_var.get()), self.guide["runbooks"][0])

    def selected_interval(self):
        try:
            value = int(self.interval_var.get().split()[0])
        except (TypeError, ValueError, IndexError):
            value = 30
        return value if value in ALLOWED_INTERVAL_DAYS else 30

    def populate_sections(self):
        profile = self.selected_profile()
        sections = [item for item in self.guide["sections"] if item["id"] in set(profile["section_ids"])]
        values = ["ALL"] + [item["title"] for item in sections]
        self.section_box["values"] = values
        if self.section_var.get() not in values:
            self.section_var.set("ALL")

    def visible_sections(self):
        allowed = set(self.selected_profile()["section_ids"])
        sections = [item for item in self.guide["sections"] if item["id"] in allowed]
        if self.section_var.get() == "ALL":
            return sections
        return [item for item in sections if item["title"] == self.section_var.get()]

    def visible_item_ids(self):
        return [item["id"] for section in self.visible_sections() for item in section["items"]]

    def selection_changed(self, _event=None):
        self.populate_sections()
        try:
            save_settings(self.selected_profile()["id"], self.selected_runbook()["id"], self.selected_interval())
        except Exception:
            pass
        self.rebuild_report()

    def section_changed(self, _event=None):
        self.rebuild_report()

    def toggle_tree_item(self, event=None):
        item_id = self.tree.identify_row(event.y) if event is not None and hasattr(event, "y") else self.tree.focus()
        if not item_id:
            return
        if item_id in self.completed:
            self.completed.remove(item_id)
        else:
            self.completed.add(item_id)
        self.rebuild_report()

    def mark_next(self):
        for item_id in self.visible_item_ids():
            if item_id not in self.completed:
                self.completed.add(item_id)
                break
        self.rebuild_report()

    def mark_section(self):
        self.completed.update(self.visible_item_ids())
        self.rebuild_report()

    def reset_progress(self):
        self.completed.clear()
        self.rebuild_report()
        self.status_var.set("Cleared current-session Recovery Kit progress.")

    def rebuild_report(self):
        if not self.guide.get("profiles"):
            return
        profile = self.selected_profile()
        runbook = self.selected_runbook()
        self.report = build_recovery_kit_report(
            self.diagnostic_report,
            self.guide,
            profile["id"],
            runbook["id"],
            self.completed,
            self.selected_interval(),
            self.history,
            self.integrity,
        )
        self.completed.intersection_update(self.report["profile"]["completed_item_ids"])
        self.tree.delete(*self.tree.get_children())
        for section in self.visible_sections():
            for item in section["items"]:
                self.tree.insert("", "end", iid=item["id"], values=("YES" if item["id"] in self.completed else "", section["title"], item["title"]))
        profile_report = self.report["profile"]
        readiness = self.report["readiness"]
        history = self.report["history"]
        catalog = self.report["online_catalog"]
        self.metric_vars["coverage"].set(f"{profile_report['completed_count']} / {profile_report['item_count']} | {profile_report['coverage_score']}%")
        self.metric_vars["readiness"].set(f"{readiness['value']} / 100 | {readiness['passed']} / {readiness['total']}")
        self.metric_vars["catalog"].set(f"{catalog['sections']} / {catalog['items']}")
        self.metric_vars["runbook"].set(self.report["runbook"]["label"])
        self.metric_vars["history"].set(f"{history['record_count']} | {'VALID' if history['integrity_valid'] else 'CHECK'}")
        self.metric_vars["due"].set(history["next_due_utc"])
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", safe_report_text(self.report))
        self.output.configure(state="disabled")

    def save_snapshot(self):
        if not self.report:
            return
        try:
            append_snapshot(
                self.report["profile"]["id"],
                self.report["runbook"]["id"],
                self.report["profile"]["completed_item_ids"],
                self.report["readiness"]["value"],
                self.report["review_interval_days"],
            )
            self.history, self.integrity = load_snapshot_history()
            locker.log_event("recovery_kit_snapshot_save", "coarse_local_snapshot", "ok")
            self.rebuild_report()
            self.status_var.set("Saved a fixed-field hash-chained Recovery Kit snapshot.")
        except Exception as exc:
            locker.log_event("recovery_kit_snapshot_save", "coarse_local_snapshot", "failed")
            messagebox.showerror("Could not save Recovery Kit snapshot", str(exc), parent=self)

    def export_json(self):
        if not self.report:
            return
        path = filedialog.asksaveasfilename(parent=self, title="Export privacy-safe Recovery Kit", defaultextension=".json", filetypes=[("JSON report", "*.json")], initialfile="vaultlink-recovery-kit.json")
        if not path:
            return
        locker.write_text_atomic(Path(path), json.dumps(self.report, indent=2))
        locker.log_event("recovery_kit_export_json", "safe_report", "ok")
        self.status_var.set("Exported the reviewed privacy-safe Recovery Kit JSON.")

    def export_text(self):
        if not self.report:
            return
        path = filedialog.asksaveasfilename(parent=self, title="Export printable Recovery Kit", defaultextension=".txt", filetypes=[("Text report", "*.txt")], initialfile="vaultlink-recovery-kit.txt")
        if not path:
            return
        locker.write_text_atomic(Path(path), safe_report_text(self.report))
        locker.log_event("recovery_kit_export_text", "safe_report", "ok")
        self.status_var.set("Exported the printable privacy-safe Recovery Kit.")

    def export_calendar(self):
        path = filedialog.asksaveasfilename(parent=self, title="Save Recovery Kit review reminder", defaultextension=".ics", filetypes=[("Calendar event", "*.ics")], initialfile="vaultlink-recovery-kit-review.ics")
        if not path:
            return
        locker.write_text_atomic(Path(path), build_calendar_text(self.selected_interval()))
        locker.log_event("recovery_kit_calendar_export", "fixed_review_reminder", "ok")
        self.status_var.set("Exported a fixed privacy-safe Recovery Kit calendar reminder.")

    def copy_runbook(self):
        if not self.report:
            return
        runbook = self.report["runbook"]
        lines = [f"VaultLink first-hour runbook: {runbook['label']}", runbook["summary"]]
        lines.extend(f"{index}. {step}" for index, step in enumerate(runbook["steps"], 1))
        lines.append("Do not include names, contacts, keys, PINs, paths, files, contents, receipts, or private details in support messages.")
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        locker.log_event("recovery_kit_runbook_copy", "fixed_runbook", "ok")
        self.status_var.set("Copied the fixed first-hour runbook.")

    def open_public_kit(self):
        try:
            settings = locker.load_settings()
            state = locker.load_license_state(settings)
            server = locker.validated_license_server_url(state.get("server_url"))
            locker.open_trusted_http_url(server.rstrip("/") + "/recovery-kit")
            locker.log_event("recovery_kit_online_open", "public_workspace", "ok")
            self.status_var.set("Opened the public current-tab-only Recovery Kit workspace.")
        except Exception as exc:
            messagebox.showerror("Could not open public Recovery Kit", str(exc), parent=self)


if __name__ == "__main__":
    RecoveryKitBuilder().mainloop()
