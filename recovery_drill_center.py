import hashlib
import json
import queue
import secrets
import threading
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

import diagnostics_center as diagnostics
import trust_recovery_center as trust
import usb_file_locker as locker


REPORT_SCHEMA_VERSION = 1
DRILL_ENDPOINT = "/api/v1/recovery-drills"
HISTORY_PATH = locker.APP_DIR / "recovery_drill_history.jsonl"
SETTINGS_PATH = locker.APP_DIR / "recovery_drill_settings.json"
ALLOWED_INTERVAL_DAYS = (7, 14, 30, 60, 90)
MAX_HISTORY_RECORDS = 500


def _step(identifier, title, action, expected):
    return {"id": identifier, "title": title, "action": action, "expected": expected}


LOCAL_DRILLS = [
    {
        "id": "key-recovery",
        "category": "Recovery",
        "title": "Recover with a backup key",
        "summary": "Verify that the protected backup is the original matching key without exposing it online.",
        "steps": [
            _step("key-preserve", "Preserve the locked original", "Work with a copied non-private test item and leave the original .locked file unchanged.", "An unchanged recovery source remains available."),
            _step("key-connect", "Connect the backup USB", "Connect the protected backup drive and load its existing master key.", "The key file is readable from the intended removable drive."),
            _step("key-compare", "Compare keys locally", "Use Key Inspector or Compare Backup Key without uploading either key.", "The app confirms matching key IDs and secret material locally."),
            _step("key-unlock", "Unlock disposable data", "Unlock only the copied test item with the original optional PIN.", "The disposable item opens correctly."),
            _step("key-store", "Return the backup to protected storage", "Eject the backup drive and store it separately from the PC and daily-use USB.", "The recovery copy is offline and physically separate."),
        ],
        "success": "A matching backup key recovered disposable data and returned to separate protected storage.",
    },
    {
        "id": "unlock-roundtrip",
        "category": "Recovery",
        "title": "Disposable lock and unlock round trip",
        "summary": "Prove the current key and optional PIN workflow on disposable data before relying on it.",
        "steps": [
            _step("roundtrip-create", "Create disposable test data", "Make a new non-private text file containing no real names, secrets, or client information.", "Only disposable test content is used."),
            _step("roundtrip-lock", "Lock the test file", "Lock it with the currently selected key and intended optional PIN.", "A new authenticated .locked container is created."),
            _step("roundtrip-copy", "Move a copy", "Copy the locked test container to a separate test folder or trusted removable drive.", "The portable copy remains readable by VaultLink."),
            _step("roundtrip-unlock", "Unlock the copied container", "Use the same key and exact optional PIN to unlock the copied container.", "The recovered test content matches the disposable original."),
            _step("roundtrip-clean", "Remove disposable output", "Delete only the disposable unlocked test output after checking it.", "No private data or only recovery copy was removed."),
        ],
        "success": "A complete portable lock and unlock round trip succeeded on disposable data.",
    },
    {
        "id": "app-data-backup",
        "category": "Backup",
        "title": "Create and verify an app-data backup",
        "summary": "Protect settings and audit evidence without including master keys, locked files, or personal documents.",
        "steps": [
            _step("appbackup-destination", "Choose protected storage", "Use a trusted removable drive or protected destination separate from the PC.", "The backup destination is not the same physical device as the live app data."),
            _step("appbackup-create", "Run Back Up App Data", "Create the transparent app-data backup through Privacy Safety Hub or the main app.", "VaultLink reports a completed backup."),
            _step("appbackup-review", "Review the backup summary", "Confirm only expected app settings and privacy-safe audit files are listed.", "No key file, locked document, PIN, or personal file is included."),
            _step("appbackup-test", "Test the backup safely", "Use the built-in validation or restore only into a disposable test copy when available.", "The backup structure is readable without replacing live data."),
            _step("appbackup-eject", "Store it separately", "Eject removable storage and place it away from the PC and master USB.", "A separate protected app-data recovery copy exists."),
        ],
        "success": "A reviewed app-data backup exists on separate protected storage.",
    },
    {
        "id": "locked-file-backup",
        "category": "Backup",
        "title": "Protect locked-file copies",
        "summary": "Maintain independent encrypted copies without placing the key and data together.",
        "steps": [
            _step("filebackup-count", "Count recovery sets", "Count independent locked-file backup sets without listing names or paths in the report.", "At least two recovery locations are understood."),
            _step("filebackup-copy", "Copy locked containers", "Copy .locked files to protected storage without unlocking or modifying them.", "Authenticated encrypted containers exist in another location."),
            _step("filebackup-separate", "Separate keys from data", "Keep the master-key backup away from the locked-file backup.", "Loss of one location does not expose both key and data."),
            _step("filebackup-health", "Run read-only health checks", "Use Vault Health Center on a non-private copied container.", "The copied container header and structure are readable."),
            _step("filebackup-date", "Record only a coarse date", "Record the backup date and total item count without filenames, paths, or contents.", "A privacy-safe freshness record exists."),
        ],
        "success": "Independent encrypted copies exist and remain physically separate from backup keys.",
    },
    {
        "id": "device-replacement",
        "category": "Recovery",
        "title": "Move to a replacement PC",
        "summary": "Prepare a trusted replacement Windows PC while preserving keys, settings, and encrypted originals.",
        "steps": [
            _step("replace-update", "Update the replacement PC", "Install Windows updates and current Microsoft Defender intelligence first.", "The replacement PC reports current protection."),
            _step("replace-app", "Install the signed transparent app", "Use the verified VaultLink folder and confirm its signed update manifest and SHA-256.", "The complete transparent app folder is present."),
            _step("replace-key", "Connect the original key", "Load the existing master key from its intended USB without copying it into cloud storage.", "The expected key ID is readable locally."),
            _step("replace-test", "Run a disposable recovery test", "Use a copied non-private .locked item before opening important data.", "The replacement PC completes a safe recovery round trip."),
            _step("replace-retire", "Retire the old installation", "Deactivate the old anonymous license seat and remove temporary unlocked copies.", "Only intended devices retain licensed access and temporary output."),
        ],
        "success": "A trusted replacement PC passed a disposable recovery test before important data was opened.",
    },
    {
        "id": "update-rollback",
        "category": "Continuity",
        "title": "Practice verified update rollback",
        "summary": "Understand how to restore app files without deleting LocalAppData, keys, settings, logs, or locked files.",
        "steps": [
            _step("rollback-close", "Close duplicate app windows", "Leave only the intended test copy open before examining update files.", "No stale process holds the test app files."),
            _step("rollback-check", "Check the signed release", "Confirm the release signature, package SHA-256, version, and app-data preservation flag.", "The candidate is an exact signed package."),
            _step("rollback-backup", "Locate the updater backup", "Identify the updater-created app-file rollback folder without moving LocalAppData.", "A prior transparent app-file set is available."),
            _step("rollback-test", "Restore only a disposable app copy", "Practice against a copied app folder, never the only live folder during the drill.", "The copied prior app starts without changing customer data."),
            _step("rollback-record", "Record the result", "Save only version, pass or fail, and approximate time in the drill history.", "The result contains no path, key, PIN, or customer data."),
        ],
        "success": "A disposable app copy demonstrated rollback while LocalAppData remained untouched.",
    },
    {
        "id": "offline-continuity",
        "category": "Continuity",
        "title": "Work safely during an API outage",
        "summary": "Confirm that local recovery remains available while online licensing and guidance are unavailable.",
        "steps": [
            _step("offline-preserve", "Preserve local recovery materials", "Keep keys, PIN knowledge, locked files, and app-data backups offline and unchanged.", "Local recovery sources remain available."),
            _step("offline-status", "Check the public status page separately", "Use a trusted device to review service status without entering license or customer data.", "The outage is distinguished from a local key problem."),
            _step("offline-local", "Use local unlock and recovery", "Open the transparent desktop app and use only the existing local key and PIN workflow.", "Local unlock and recovery controls remain available."),
            _step("offline-no-bypass", "Do not bypass licensing security", "Wait for premium online features instead of changing clocks, tokens, or cached license files.", "Local state remains intact for normal synchronization."),
            _step("offline-sync", "Refresh after service returns", "Use License Center to refresh and review the signed update channel.", "Normal online status returns without replacing keys or data."),
        ],
        "success": "Local recovery stayed available and online state recovered without bypasses or data changes.",
    },
    {
        "id": "family-handoff",
        "category": "Continuity",
        "title": "Trusted family recovery handoff",
        "summary": "Teach a trusted adult the recovery sequence without giving unnecessary access to secrets or private files.",
        "steps": [
            _step("family-role", "Choose the recovery helper", "Select one trusted adult who understands the responsibility and privacy boundaries.", "A specific helper is responsible for recovery support."),
            _step("family-map", "Explain the recovery map", "Explain where separate key and data backups are stored without writing secrets together.", "The helper understands the locations and separation rule."),
            _step("family-demo", "Demonstrate disposable recovery", "Run a non-private lock and unlock test while the helper observes.", "The helper can describe the correct order of operations."),
            _step("family-escalate", "Explain when to stop", "Cover missing keys, damaged drives, Defender alerts, and the rule to preserve originals.", "The helper knows when qualified help is needed."),
            _step("family-review", "Schedule the next drill", "Choose a 30, 60, or 90 day review interval in this app.", "The next local due date is visible."),
        ],
        "success": "A trusted adult understands the recovery sequence and its privacy boundaries.",
    },
    {
        "id": "owner-succession",
        "category": "Continuity",
        "title": "Owner succession readiness",
        "summary": "Prepare authorized continuity for the owner USB, signed releases, and recovery records without creating a universal backdoor.",
        "steps": [
            _step("succession-authority", "Document authorized roles", "Use an offline policy to name who may handle owner operations and recovery.", "Authority is explicit and limited."),
            _step("succession-backup", "Verify protected owner backups", "Confirm matching owner and recovery backups exist in separate protected locations.", "Authorized recovery material is redundant and separated."),
            _step("succession-release", "Review release procedure", "Practice the 15-check owner preflight with a private candidate and no customer publication.", "The owner process rejects unsigned or unscanned releases."),
            _step("succession-revoke", "Review license controls", "Demonstrate revocation, restoration, and anonymous seat removal without exposing license keys.", "Authorized staff understand reversible account controls."),
            _step("succession-boundary", "Confirm there is no universal decryption key", "Document that owner controls cannot replace a customer's original matching encryption key and PIN.", "Continuity plans do not promise impossible recovery."),
        ],
        "success": "Authorized continuity exists without weakening customer encryption or creating a universal decryption key.",
    },
    {
        "id": "business-outage",
        "category": "Continuity",
        "title": "Small office outage exercise",
        "summary": "Practice service, device, and data continuity with fixed roles and privacy-safe evidence.",
        "steps": [
            _step("office-scope", "Choose the test scope", "Use one disposable workstation and synthetic files, never live client records.", "The exercise cannot alter production data."),
            _step("office-roles", "Assign response roles", "Assign decision, technical, communication, and recovery roles before the test.", "Each participant knows their responsibility."),
            _step("office-offline", "Simulate one unavailable service", "Disconnect the disposable test environment from the API without disabling security software.", "Local recovery behavior is observed safely."),
            _step("office-restore", "Recover the test workflow", "Use signed app files, a matching test key, and a disposable backup to restore the exercise.", "The synthetic workflow returns without exposing real data."),
            _step("office-review", "Record coarse lessons", "Record only drill ID, completion, score, and approved action items outside VaultLink.", "VaultLink stores no client names, files, or free-form incident details."),
        ],
        "success": "A synthetic office outage was recovered with clear roles and no production data exposure.",
    },
    {
        "id": "account-recovery",
        "category": "Security",
        "title": "Online account recovery exercise",
        "summary": "Verify recovery methods from a trusted device without storing credentials in VaultLink.",
        "steps": [
            _step("account-device", "Use a trusted device", "Open official account security pages on an updated device.", "Recovery work occurs away from a possibly affected PC."),
            _step("account-methods", "Review recovery methods", "Check recovery email, phone, passkeys, authenticator methods, and backup-code custody.", "Only authorized recovery methods remain."),
            _step("account-sessions", "Review active sessions", "Remove unknown devices and remembered sessions through the provider.", "Only recognized sessions remain."),
            _step("account-unique", "Confirm unique passwords", "Use a password manager or trusted method without entering the password into VaultLink.", "Important accounts do not reuse passwords."),
            _step("account-alerts", "Enable provider alerts", "Turn on sign-in and security notifications offered by the provider.", "Unexpected account activity can be noticed quickly."),
        ],
        "success": "Recovery methods and active sessions were reviewed without credentials entering VaultLink.",
    },
    {
        "id": "phishing-response",
        "category": "Security",
        "title": "Phishing response exercise",
        "summary": "Practice handling a synthetic suspicious message without opening, forwarding, or reporting private content.",
        "steps": [
            _step("phish-stop", "Stop interaction", "Do not click links, open attachments, reply, call numbers, or enter information.", "The synthetic message receives no interaction."),
            _step("phish-direct", "Use the provider directly", "Open the known official app or type the official address yourself.", "The claimed alert is checked outside the message."),
            _step("phish-report", "Use built-in reporting", "Practice locating the provider's Report Phishing control without submitting real private mail.", "The trusted reporting path is understood."),
            _step("phish-credential", "Explain credential response", "State that exposed credentials must be changed from another trusted device.", "The response order is understood without entering credentials."),
            _step("phish-scan", "Explain download response", "State that downloads remain closed while Microsoft Defender supplies the scan result.", "No suspicious attachment is run during the drill."),
        ],
        "success": "The phishing response order was practiced using synthetic content only.",
    },
    {
        "id": "ransomware-isolation",
        "category": "Security",
        "title": "Ransomware isolation tabletop",
        "summary": "Practice decisions using a tabletop scenario only; do not run ransomware, malware samples, or file-encryption simulations.",
        "steps": [
            _step("ransom-tabletop", "Use a tabletop scenario only", "Read the fixed scenario without running code, changing files, or disabling protection.", "No malware or destructive simulation is used."),
            _step("ransom-isolate", "State the isolation action", "Disconnect an actually affected PC from networks when files are actively changing.", "The correct containment decision is understood."),
            _step("ransom-preserve", "State the preservation rule", "Do not pay, rerun, rename, edit, or overwrite affected files and notes.", "Evidence and recovery candidates would remain intact."),
            _step("ransom-backups", "Protect offline backups", "Keep known-good backups and matching keys disconnected from an affected PC.", "Recovery materials would stay outside the affected environment."),
            _step("ransom-escalate", "Name the escalation path", "Identify the trusted adult, administrator, insurer, law enforcement contact, or qualified responder.", "High-impact decisions have an approved human escalation path."),
        ],
        "success": "Ransomware decisions were rehearsed safely without executing malware or altering files.",
    },
    {
        "id": "device-loss",
        "category": "Security",
        "title": "Lost device response exercise",
        "summary": "Practice account, license-seat, key, and backup actions from another trusted device.",
        "steps": [
            _step("loss-account", "Secure the Windows account", "Use official account device controls to review sign-ins and the missing device.", "Unknown sessions and device access can be removed."),
            _step("loss-seat", "Remove the anonymous license seat", "Use Customer Center or owner controls without publishing the license key.", "The missing installation loses premium service access."),
            _step("loss-accounts", "Protect important online accounts", "Review sessions and recovery methods from another trusted device.", "Only recognized devices remain."),
            _step("loss-materials", "Locate separate recovery materials", "Confirm the matching key backup, app-data backup, and locked-file copies are separate.", "Recovery does not depend on the missing device."),
            _step("loss-replace", "Plan the replacement test", "Require Defender, signed app files, and disposable recovery before important restoration.", "The replacement process has a safe gate."),
        ],
        "success": "The lost-device response path was understood without exposing credentials or customer data.",
    },
    {
        "id": "audit-integrity",
        "category": "Evidence",
        "title": "Audit integrity review",
        "summary": "Verify the privacy-safe local hash chain and export evidence without collecting content or full paths.",
        "steps": [
            _step("audit-open", "Open Audit Log Viewer", "Use the local viewer instead of editing the JSONL files directly.", "The original chain remains unchanged."),
            _step("audit-verify", "Verify the full chain", "Run integrity verification and note only pass or fail and total records.", "Every sequence and previous-hash link is checked."),
            _step("audit-review", "Review action categories", "Look for failed access, unlock, configuration, scan, removal, and update events.", "Relevant coarse actions are understood without file contents."),
            _step("audit-export", "Export a reviewed safe copy", "Use the viewer export and inspect it before sharing.", "No password, PIN, key, content, customer name, or full path is included."),
            _step("audit-protect", "Protect the export", "Store sensitive business audit exports under appropriate Windows permissions and retention rules.", "Evidence access and retention are deliberate."),
        ],
        "success": "The local audit chain verified and its reviewed export stayed privacy-safe.",
    },
    {
        "id": "privacy-safe-support",
        "category": "Evidence",
        "title": "Prepare a privacy-safe support packet",
        "summary": "Provide useful troubleshooting evidence without sending secrets, private files, or unnecessary identifiers.",
        "steps": [
            _step("support-diagnostics", "Run Diagnostics Center", "Generate the fixed coarse check report and review every field.", "Failed checks are visible without paths or secrets."),
            _step("support-incident", "Choose a fixed incident playbook", "Use Incident Response Center without entering free-form incident details.", "The selected response is represented by a public drill or playbook ID."),
            _step("support-redact", "Remove unnecessary identifiers", "Exclude names, emails, license keys, receipts, device IDs, paths, filenames, and screenshots.", "The packet contains only necessary coarse evidence."),
            _step("support-channel", "Use the official support channel", "Verify the destination before sending the reviewed packet.", "Evidence goes only to the intended trusted recipient."),
            _step("support-copy", "Keep a protected local copy", "Store the reviewed packet under appropriate Windows permissions and retention rules.", "The customer can later verify exactly what was shared."),
        ],
        "success": "A useful support packet was prepared without secrets, file contents, or unnecessary identity data.",
    },
]


READINESS_CHECKS = (
    ("defender-protection", "Windows", "Microsoft Defender protection", 15),
    ("defender-signatures", "Windows", "Current Defender signatures", 5),
    ("audit-chain", "Evidence", "Local audit integrity", 10),
    ("owner-usb-policy", "Recovery", "Owner USB policy", 10),
    ("selected-key", "Recovery", "Selected recovery key", 15),
    ("signed-release", "Updates", "Verified signed release", 10),
    ("recovery-test", "Recovery", "Disposable recovery test", 10),
    ("app-data-backup", "Backup", "Recorded app-data backup", 10),
    ("free-space", "Storage", "Working disk space", 5),
    ("app-data-access", "Storage", "App-data access", 10),
)


def _fallback_guide(message="Online recovery drill catalog unavailable."):
    return {
        "ok": False,
        "recovery_drill_schema_version": 1,
        "api_version": "Unavailable",
        "service_status": {"mode": "unknown", "message": message, "updated_at_utc": ""},
        "signed_release": {"ready": False, "version": "", "minimum_supported_version": ""},
        "drills": json.loads(json.dumps(LOCAL_DRILLS)),
        "privacy_boundaries": [
            "Desktop drill history stores only fixed drill IDs, timestamps, completion totals, readiness scores, and hash-chain fields.",
            "No key, PIN, receipt, identity, machine identity, path, filename, screenshot, process list, file content, or free-form note is stored or uploaded.",
            "The public API serves a fixed catalog and never receives customer progress, local check results, or history.",
        ],
        "limitations": [
            "A completed drill is practice, not proof that every future recovery attempt will succeed.",
            "Use Microsoft Defender and qualified human help for malware, active compromise, financial loss, identity exposure, or damaged storage.",
        ],
        "server_time_utc": "",
        "accepts_free_text": False,
        "accepts_files": False,
        "customer_records_included": False,
    }


def safe_recovery_guide(payload):
    source = payload if isinstance(payload, dict) else {}
    fallback = _fallback_guide()
    if not source.get("ok"):
        return fallback

    def clean(value, default="", limit=320):
        return trust.safe_online_text(value, default, limit)

    def clean_list(values, limit=20):
        if not isinstance(values, (list, tuple)):
            return []
        result = []
        for value in values[:limit]:
            cleaned = clean(value)
            if cleaned:
                result.append(cleaned)
        return result

    drills = []
    raw_drills = source.get("drills")
    if isinstance(raw_drills, (list, tuple)):
        for raw in raw_drills[:20]:
            if not isinstance(raw, dict):
                continue
            steps = []
            raw_steps = raw.get("steps")
            if isinstance(raw_steps, (list, tuple)):
                for item in raw_steps[:8]:
                    if not isinstance(item, dict):
                        continue
                    steps.append(
                        _step(
                            clean(item.get("id"), "step", 80),
                            clean(item.get("title"), "Recovery step", 160),
                            clean(item.get("action"), "Review this fixed step locally."),
                            clean(item.get("expected"), "Record whether this step is complete."),
                        )
                    )
            if steps:
                drills.append(
                    {
                        "id": clean(raw.get("id"), "other", 80),
                        "category": clean(raw.get("category"), "Other", 80),
                        "title": clean(raw.get("title"), "Recovery drill", 160),
                        "summary": clean(raw.get("summary"), "Use the fixed recovery steps."),
                        "steps": steps,
                        "success": clean(raw.get("success"), "The fixed recovery steps were reviewed."),
                    }
                )
    if not drills:
        drills = fallback["drills"]
    service = source.get("service_status") if isinstance(source.get("service_status"), dict) else {}
    release = source.get("signed_release") if isinstance(source.get("signed_release"), dict) else {}
    return {
        "ok": True,
        "recovery_drill_schema_version": 1,
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
        "drills": drills,
        "privacy_boundaries": clean_list(source.get("privacy_boundaries")) or fallback["privacy_boundaries"],
        "limitations": clean_list(source.get("limitations")) or fallback["limitations"],
        "server_time_utc": clean(source.get("server_time_utc"), "", 40),
        "accepts_free_text": False,
        "accepts_files": False,
        "customer_records_included": False,
    }


def _canonical_record(record):
    payload = dict(record)
    payload.pop("hash", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def load_drill_history(path=HISTORY_PATH):
    path = Path(path)
    if not path.is_file():
        return [], {"valid": True, "message": "No recovery drill results have been saved yet."}
    try:
        if path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("Recovery drill history is larger than the safety limit.")
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) > MAX_HISTORY_RECORDS:
            raise ValueError("Recovery drill history exceeds the 500-record safety limit.")
        valid_ids = {item["id"] for item in LOCAL_DRILLS}
        previous_hash = "0" * 64
        records = []
        for sequence, line in enumerate(lines, 1):
            record = json.loads(line)
            if not isinstance(record, dict) or record.get("sequence") != sequence:
                raise ValueError(f"Recovery drill record {sequence} has an invalid sequence.")
            if record.get("previous_hash") != previous_hash:
                raise ValueError(f"Recovery drill record {sequence} broke the hash chain.")
            if record.get("drill_id") not in valid_ids or record.get("result") not in {"complete", "partial"}:
                raise ValueError(f"Recovery drill record {sequence} contains an unknown fixed value.")
            expected = hashlib.sha256(_canonical_record(record)).hexdigest()
            if not secrets.compare_digest(str(record.get("hash", "")), expected):
                raise ValueError(f"Recovery drill record {sequence} failed its hash check.")
            records.append(record)
            previous_hash = expected
        return records, {"valid": True, "message": f"Verified {len(records)} hash-chained recovery drill result(s)."}
    except Exception as exc:
        return [], {"valid": False, "message": str(exc)[:300]}


def append_drill_history(drill_id, completed_count, total_steps, readiness_score, path=HISTORY_PATH, time_utc=""):
    valid_ids = {item["id"] for item in LOCAL_DRILLS}
    drill_id = str(drill_id or "")
    completed_count = int(completed_count)
    total_steps = int(total_steps)
    readiness_score = int(readiness_score)
    if drill_id not in valid_ids:
        raise ValueError("Choose a fixed recovery drill before saving the result.")
    if not 0 < total_steps <= 8 or not 0 < completed_count <= total_steps:
        raise ValueError("Complete at least one fixed step before saving the result.")
    if not 0 <= readiness_score <= 100:
        raise ValueError("The readiness score is outside the allowed range.")
    path = Path(path)
    records, integrity = load_drill_history(path)
    if not integrity["valid"]:
        raise ValueError("Recovery drill history integrity failed. Preserve the file and review it before adding records.")
    if len(records) >= MAX_HISTORY_RECORDS:
        raise ValueError("Recovery drill history reached its 500-record safety limit. Export and archive it before starting a new history file.")
    previous_hash = records[-1]["hash"] if records else "0" * 64
    record = {
        "schema_version": 1,
        "sequence": len(records) + 1,
        "time_utc": time_utc or locker.utc_now_text(),
        "event_id": secrets.token_hex(8),
        "drill_id": drill_id,
        "result": "complete" if completed_count == total_steps else "partial",
        "completed_count": completed_count,
        "total_steps": total_steps,
        "readiness_score": readiness_score,
        "previous_hash": previous_hash,
    }
    record["hash"] = hashlib.sha256(_canonical_record(record)).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    return record


def load_drill_settings(path=SETTINGS_PATH):
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except Exception:
        raw = {}
    try:
        interval = int(raw.get("interval_days", 30))
    except (TypeError, ValueError):
        interval = 30
    return {"interval_days": interval if interval in ALLOWED_INTERVAL_DAYS else 30}


def save_drill_settings(interval_days, path=SETTINGS_PATH):
    interval_days = int(interval_days)
    if interval_days not in ALLOWED_INTERVAL_DAYS:
        raise ValueError("Choose one of the fixed recovery drill intervals.")
    payload = {"schema_version": 1, "interval_days": interval_days}
    locker.write_text_atomic(Path(path), json.dumps(payload, indent=2))
    return payload


def _next_due(records, interval_days):
    if not records:
        return "Not scheduled until the first saved result"
    latest = locker.parse_utc_text(records[-1].get("time_utc"))
    if not latest:
        return "Unknown"
    return (latest + timedelta(days=int(interval_days))).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_recovery_report(diagnostic_report, online_guide, selected_drill_id="", completed_step_ids=None, history=None, integrity=None, interval_days=30, generated_at_utc=""):
    diagnostic_report = diagnostic_report if isinstance(diagnostic_report, dict) else {}
    guide = safe_recovery_guide(online_guide)
    check_map = {str(item.get("id")): item for item in diagnostic_report.get("checks", []) if isinstance(item, dict) and item.get("id")}
    checks = []
    for identifier, category, title, weight in READINESS_CHECKS:
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
                "action": trust.safe_online_text(source.get("action"), "Run Diagnostics Center and review the failed check.", 320),
            }
        )
    score = sum(item["weight"] for item in checks if item["passed"])
    label = "ready" if score >= 90 else "prepared" if score >= 70 else "attention" if score >= 50 else "action"
    drills = guide["drills"]
    selected = next((item for item in drills if item["id"] == selected_drill_id), drills[0])
    valid_step_ids = {item["id"] for item in selected["steps"]}
    completed = sorted(valid_step_ids.intersection(str(value) for value in (completed_step_ids or [])))
    history = list(history or [])
    integrity = integrity if isinstance(integrity, dict) else {"valid": True, "message": "No history loaded."}
    safe_history = [
        {
            "sequence": int(item.get("sequence", 0)),
            "time_utc": str(item.get("time_utc", ""))[:40],
            "event_id": str(item.get("event_id", ""))[:32],
            "drill_id": str(item.get("drill_id", ""))[:80],
            "result": str(item.get("result", ""))[:20],
            "completed_count": int(item.get("completed_count", 0)),
            "total_steps": int(item.get("total_steps", 0)),
            "readiness_score": int(item.get("readiness_score", 0)),
            "previous_hash": str(item.get("previous_hash", ""))[:64],
            "hash": str(item.get("hash", ""))[:64],
        }
        for item in history[-25:]
        if isinstance(item, dict) and item.get("drill_id") in {drill["id"] for drill in LOCAL_DRILLS}
    ]
    generated = generated_at_utc or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": "VaultLink Privacy-Safe Recovery Drill Report",
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
        },
        "checks": checks,
        "selected_drill": {
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
        "history": {
            "integrity_valid": bool(integrity.get("valid")),
            "integrity_message": str(integrity.get("message") or "History status unavailable.")[:300],
            "record_count": len(history),
            "complete_count": sum(item.get("result") == "complete" for item in history if isinstance(item, dict)),
            "partial_count": sum(item.get("result") == "partial" for item in history if isinstance(item, dict)),
            "interval_days": int(interval_days),
            "next_due_utc": _next_due(history, interval_days),
            "recent_records": safe_history,
        },
        "online_catalog": {
            "available": bool(guide.get("ok")),
            "api_version": guide.get("api_version", "Unavailable"),
            "service_mode": guide.get("service_status", {}).get("mode", "unknown"),
            "signed_release_ready": bool(guide.get("signed_release", {}).get("ready")),
            "signed_release_version": guide.get("signed_release", {}).get("version", ""),
            "drill_count": len(drills),
            "step_count": sum(len(item["steps"]) for item in drills),
        },
        "privacy_notice": (
            "This report excludes license keys, receipts, identities, machine identity, passwords, PINs, USB secrets, "
            "paths, filenames, screenshots, process lists, private file contents, and free-form notes. Drill history stays local."
        ),
        "limitations": list(guide.get("limitations") or _fallback_guide()["limitations"]),
    }


def collect_recovery_inputs():
    diagnostic_report = diagnostics.collect_diagnostics_report()
    guide = _fallback_guide()
    try:
        settings = locker.load_settings()
        state = locker.load_license_state(settings)
        server = locker.validated_license_server_url(state.get("server_url"))
        guide = safe_recovery_guide(locker.license_api_get_json(server, DRILL_ENDPOINT))
    except Exception:
        pass
    history, integrity = load_drill_history()
    schedule = load_drill_settings()
    return diagnostic_report, guide, history, integrity, schedule


def safe_recovery_text(report):
    readiness = report["readiness"]
    drill = report["selected_drill"]
    history = report["history"]
    completed = set(drill["completed_step_ids"])
    lines = [
        f"RECOVERY READINESS  {readiness['value']} / {readiness['maximum']}  {readiness['label'].upper()}",
        f"READINESS CHECKS     {readiness['passed']} / {readiness['total']} PASSED",
        f"DRILL                {drill['title']}",
        f"DRILL PROGRESS       {drill['completed_count']} / {drill['total_steps']}",
        f"LOCAL HISTORY        {history['record_count']} RECORDS | {'VALID' if history['integrity_valid'] else 'CHECK'}",
        f"NEXT DUE             {history['next_due_utc']}",
        f"GENERATED            {report['generated_at_utc']}",
        "",
        "READINESS",
        "---------",
    ]
    for item in report["checks"]:
        lines.extend(
            [
                f"[{item['state'].upper():9}] {item['category']} | {item['title']} ({item['weight']} points)",
                f"  {item['detail']}",
                *([] if item["passed"] else [f"  NEXT: {item['action']}"]),
                "",
            ]
        )
    lines.extend(["RECOVERY DRILL", "--------------", drill["summary"], ""])
    for index, step in enumerate(drill["steps"], 1):
        marker = "X" if step["id"] in completed else " "
        lines.extend([f"[{marker}] STEP {index}: {step['title']}", f"    {step['action']}", f"    EXPECTED: {step['expected']}", ""])
    lines.extend([f"SUCCESS: {drill['success']}", "", "PRIVACY", "-------", report["privacy_notice"], "", "LIMITATIONS", "-----------"])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines)


def safe_recovery_summary(report):
    readiness = report["readiness"]
    drill = report["selected_drill"]
    history = report["history"]
    lines = [
        f"VaultLink recovery readiness: {readiness['value']}/100 {readiness['label'].upper()}",
        f"Drill: {drill['title']} ({drill['completed_count']}/{drill['total_steps']} complete)",
        f"Local drill history: {history['record_count']} record(s), integrity {'valid' if history['integrity_valid'] else 'needs review'}, next due {history['next_due_utc']}",
    ]
    lines.extend(f"Attention: {item['title']} - {item['action']}" for item in report["checks"] if not item["passed"])
    lines.append(report["privacy_notice"])
    return "\n".join(lines[:12])


class RecoveryDrillCenter(tk.Tk):
    def __init__(self):
        super().__init__()
        if not locker.ensure_license_feature("recovery-drill-center", parent=self):
            self.after(0, self.destroy)
            return
        self.title("VaultLink Recovery Drill Center")
        self.geometry("1180x860")
        self.minsize(920, 700)
        self.configure(bg=locker.BG)
        self.results = queue.Queue()
        self.busy = False
        self.diagnostic_report = None
        self.guide = _fallback_guide()
        self.history = []
        self.integrity = {"valid": True, "message": "No history loaded."}
        self.interval_days = 30
        self.report = None
        self.completed = {}
        self.category_var = tk.StringVar(value="ALL")
        self.drill_var = tk.StringVar(value=LOCAL_DRILLS[0]["title"])
        self.interval_var = tk.StringVar(value="30 days")
        self.status_var = tk.StringVar(value="Ready to run a privacy-safe recovery exercise.")
        self.metric_vars = {name: tk.StringVar(value="--") for name in ("readiness", "checks", "catalog", "progress", "history", "due")}
        self.title_to_id = {item["title"]: item["id"] for item in LOCAL_DRILLS}
        self.drill_box = None
        self.build_ui()
        self.refresh_async()

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=22, pady=18)
        tk.Label(outer, text="Recovery Drill Center", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 25, "bold")).pack(anchor="w")
        tk.Label(outer, text="Practice recovery before an emergency. Fixed drills, local-only history, reviewed exports, and no secret collection.", bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(3, 12))

        tools = tk.Frame(outer, bg=locker.BG)
        tools.pack(fill="x", pady=(0, 12))
        for text, command, color in (
            ("REFRESH", self.refresh_async, locker.GREEN),
            ("SAVE RESULT", self.save_result, locker.YELLOW),
            ("EXPORT SAFE JSON", self.export_report, "#252936"),
            ("EXPORT HISTORY", self.export_history, "#252936"),
            ("COPY SUMMARY", self.copy_summary, "#252936"),
            ("ONLINE DRILLS", self.open_online, locker.BLUE),
            ("WINDOWS SECURITY", self.open_windows_security, "#252936"),
        ):
            tk.Button(tools, text=text, command=command, bg=color, fg=locker.BLACK if color in {locker.GREEN, locker.YELLOW, locker.BLUE} else locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(0, 7), ipadx=8, ipady=6)
        tk.Button(tools, text="CLOSE", command=self.destroy, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="right", ipadx=9, ipady=6)

        metrics = tk.Frame(outer, bg=locker.PANEL, highlightbackground="#343b49", highlightthickness=1)
        metrics.pack(fill="x", pady=(0, 12))
        for column, (name, label) in enumerate((
            ("readiness", "READINESS"), ("checks", "LOCAL CHECKS"), ("catalog", "CATALOG"),
            ("progress", "DRILL PROGRESS"), ("history", "LOCAL HISTORY"), ("due", "NEXT DUE"),
        )):
            cell = tk.Frame(metrics, bg=locker.PANEL)
            cell.grid(row=0, column=column, sticky="nsew", padx=12, pady=10)
            tk.Label(cell, text=label, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 7, "bold")).pack(anchor="w")
            tk.Label(cell, textvariable=self.metric_vars[name], bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 11, "bold"), wraplength=170, justify="left").pack(anchor="w", pady=(3, 0))
            metrics.grid_columnconfigure(column, weight=1)

        controls = tk.Frame(outer, bg=locker.PANEL, padx=12, pady=10, highlightbackground="#343b49", highlightthickness=1)
        controls.pack(fill="x", pady=(0, 10))
        tk.Label(controls, text="CATEGORY", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 7, "bold")).grid(row=0, column=0, sticky="w")
        categories = ("ALL",) + tuple(sorted({item["category"] for item in LOCAL_DRILLS}))
        category_box = ttk.Combobox(controls, textvariable=self.category_var, state="readonly", width=14, values=categories)
        category_box.grid(row=1, column=0, sticky="ew", padx=(0, 8))
        category_box.bind("<<ComboboxSelected>>", lambda _event: self.filter_drills())
        tk.Label(controls, text="RECOVERY DRILL", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 7, "bold")).grid(row=0, column=1, sticky="w")
        self.drill_box = ttk.Combobox(controls, textvariable=self.drill_var, state="readonly", width=38, values=tuple(self.title_to_id))
        self.drill_box.grid(row=1, column=1, sticky="ew", padx=(0, 8))
        self.drill_box.bind("<<ComboboxSelected>>", lambda _event: self.render())
        tk.Label(controls, text="REVIEW INTERVAL", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 7, "bold")).grid(row=0, column=2, sticky="w")
        interval_box = ttk.Combobox(controls, textvariable=self.interval_var, state="readonly", width=12, values=tuple(f"{value} days" for value in ALLOWED_INTERVAL_DAYS))
        interval_box.grid(row=1, column=2, sticky="ew", padx=(0, 8))
        interval_box.bind("<<ComboboxSelected>>", lambda _event: self.change_interval())
        for column, (text, command, color) in enumerate((
            ("MARK NEXT", self.mark_next, locker.GREEN), ("MARK ALL", self.mark_all, locker.BLUE),
            ("RESET", self.reset_drill, "#252936"), ("RANDOM DRILL", self.random_drill, locker.YELLOW),
        ), start=3):
            tk.Button(controls, text=text, command=command, bg=color, fg=locker.BLACK if color in {locker.GREEN, locker.BLUE, locker.YELLOW} else locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold")).grid(row=1, column=column, sticky="ew", padx=(0 if column == 3 else 7, 0), ipadx=6, ipady=5)
            controls.grid_columnconfigure(column, weight=0)
        controls.grid_columnconfigure(0, weight=0)
        controls.grid_columnconfigure(1, weight=1)
        controls.grid_columnconfigure(2, weight=0)

        self.output = scrolledtext.ScrolledText(outer, wrap="word", bg="#0b0d12", fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Consolas", 9), padx=14, pady=12)
        self.output.pack(fill="both", expand=True)
        self.output.configure(state="disabled")
        tk.Label(outer, textvariable=self.status_var, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(9, 0))

    def selected_drill_id(self):
        return self.title_to_id.get(self.drill_var.get(), LOCAL_DRILLS[0]["id"])

    def refresh_async(self):
        if self.busy:
            return
        self.busy = True
        self.status_var.set("Refreshing local readiness, signed catalog, history, and schedule...")
        threading.Thread(target=self.refresh_worker, daemon=True).start()
        self.after(100, self.poll_results)

    def refresh_worker(self):
        try:
            self.results.put(("ok", collect_recovery_inputs()))
        except Exception as exc:
            self.results.put(("error", str(exc)))

    def poll_results(self):
        try:
            kind, payload = self.results.get_nowait()
        except queue.Empty:
            self.after(100, self.poll_results)
            return
        self.busy = False
        if kind == "error":
            self.status_var.set("Recovery readiness could not be refreshed.")
            messagebox.showerror("Refresh failed", payload, parent=self)
            return
        self.diagnostic_report, self.guide, self.history, self.integrity, schedule = payload
        self.interval_days = int(schedule["interval_days"])
        self.interval_var.set(f"{self.interval_days} days")
        self.refresh_drill_choices()
        self.render()
        mode = self.guide.get("service_status", {}).get("mode", "offline")
        self.status_var.set(f"Recovery workspace refreshed. Public service mode: {mode}.")

    def refresh_drill_choices(self):
        drills = self.guide.get("drills") or LOCAL_DRILLS
        category = self.category_var.get()
        filtered = [item for item in drills if category == "ALL" or item["category"] == category]
        if not filtered:
            filtered = drills
        current_id = self.selected_drill_id()
        self.title_to_id = {item["title"]: item["id"] for item in filtered}
        self.drill_box.configure(values=tuple(self.title_to_id))
        selected = next((item for item in filtered if item["id"] == current_id), filtered[0])
        self.drill_var.set(selected["title"])

    def filter_drills(self):
        self.refresh_drill_choices()
        self.render()

    def render(self):
        if not self.diagnostic_report:
            return
        selected = self.selected_drill_id()
        self.report = build_recovery_report(
            self.diagnostic_report,
            self.guide,
            selected,
            self.completed.setdefault(selected, set()),
            self.history,
            self.integrity,
            self.interval_days,
        )
        readiness = self.report["readiness"]
        drill = self.report["selected_drill"]
        history = self.report["history"]
        catalog = self.report["online_catalog"]
        self.metric_vars["readiness"].set(f"{readiness['value']} / 100 {readiness['label'].upper()}")
        self.metric_vars["checks"].set(f"{readiness['passed']} / {readiness['total']}")
        self.metric_vars["catalog"].set(f"{catalog['drill_count']} drills | {catalog['step_count']} steps")
        self.metric_vars["progress"].set(f"{drill['completed_count']} / {drill['total_steps']}")
        self.metric_vars["history"].set(f"{history['record_count']} | {'VALID' if history['integrity_valid'] else 'CHECK'}")
        due = history["next_due_utc"]
        self.metric_vars["due"].set(due[:10] if due and due[0].isdigit() else due)
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", safe_recovery_text(self.report))
        self.output.configure(state="disabled")

    def mark_next(self):
        if not self.report:
            return
        drill = self.report["selected_drill"]
        completed = self.completed.setdefault(drill["id"], set())
        step = next((item for item in drill["steps"] if item["id"] not in completed), None)
        if step:
            completed.add(step["id"])
            locker.log_event("recovery_drill_progress", drill["id"], "ok")
        self.render()
        self.status_var.set("Marked the next fixed recovery step complete in this app session.")

    def mark_all(self):
        if not self.report:
            return
        drill = self.report["selected_drill"]
        self.completed[drill["id"]] = {item["id"] for item in drill["steps"]}
        self.render()
        self.status_var.set("Marked every fixed step complete in this app session. Save Result records only coarse totals.")

    def reset_drill(self):
        selected = self.selected_drill_id()
        self.completed[selected] = set()
        self.render()
        self.status_var.set("Current drill progress reset in memory.")

    def random_drill(self):
        choices = list(self.title_to_id)
        if not choices:
            return
        self.drill_var.set(secrets.choice(choices))
        self.render()
        self.status_var.set("Selected a random fixed drill from the current category.")

    def change_interval(self):
        try:
            self.interval_days = int(self.interval_var.get().split()[0])
            save_drill_settings(self.interval_days)
            self.render()
            locker.log_event("recovery_drill_schedule", "fixed_interval", "ok")
            self.status_var.set(f"Local recovery review interval set to {self.interval_days} days.")
        except Exception as exc:
            messagebox.showerror("Schedule not saved", str(exc), parent=self)

    def save_result(self):
        if not self.report:
            return
        drill = self.report["selected_drill"]
        try:
            record = append_drill_history(drill["id"], drill["completed_count"], drill["total_steps"], self.report["readiness"]["value"])
            self.history, self.integrity = load_drill_history()
            self.render()
            locker.log_event("recovery_drill_result", drill["id"], "ok")
            self.status_var.set(f"Saved privacy-safe {record['result']} result #{record['sequence']} to the local hash chain.")
        except Exception as exc:
            messagebox.showerror("Result not saved", str(exc), parent=self)

    def export_report(self):
        if not self.report:
            return
        path = filedialog.asksaveasfilename(parent=self, title="Export privacy-safe recovery report", defaultextension=".json", filetypes=[("JSON report", "*.json")], initialfile="vaultlink-recovery-drill-report.json")
        if not path:
            return
        locker.write_text_atomic(Path(path), json.dumps(self.report, indent=2))
        locker.log_event("recovery_drill_export", "safe_report", "ok")
        self.status_var.set("Exported a reviewed privacy-safe recovery drill report.")

    def export_history(self):
        records, integrity = load_drill_history()
        if not integrity["valid"]:
            messagebox.showerror("History integrity failed", integrity["message"], parent=self)
            return
        path = filedialog.asksaveasfilename(parent=self, title="Export privacy-safe drill history", defaultextension=".json", filetypes=[("JSON history", "*.json")], initialfile="vaultlink-recovery-drill-history.json")
        if not path:
            return
        payload = {"schema_version": 1, "exported_at_utc": locker.utc_now_text(), "record_count": len(records), "integrity": integrity, "records": records, "privacy_notice": "No key, PIN, identity, path, filename, file content, or free-form note is included."}
        locker.write_text_atomic(Path(path), json.dumps(payload, indent=2))
        locker.log_event("recovery_drill_history_export", "safe_history", "ok")
        self.status_var.set("Exported the verified privacy-safe local drill history.")

    def copy_summary(self):
        if not self.report:
            return
        self.clipboard_clear()
        self.clipboard_append(safe_recovery_summary(self.report))
        locker.log_event("recovery_drill_copy", "safe_summary", "ok")
        self.status_var.set("Copied a privacy-safe recovery summary.")

    def open_online(self):
        try:
            settings = locker.load_settings()
            state = locker.load_license_state(settings)
            server = locker.validated_license_server_url(state.get("server_url"))
            webbrowser.open(server + "/recovery-drills")
            locker.log_event("recovery_drill_online_open", "public_catalog", "ok")
            self.status_var.set("Opened the public recovery drill workspace.")
        except Exception as exc:
            messagebox.showerror("Could not open online drills", str(exc), parent=self)

    def open_windows_security(self):
        try:
            locker.open_windows_security()
            locker.log_event("recovery_drill_windows_security", "windows_security", "ok")
            self.status_var.set("Opened Windows Security.")
        except Exception as exc:
            messagebox.showerror("Could not open Windows Security", str(exc), parent=self)


def run_app():
    app = RecoveryDrillCenter()
    app.mainloop()


if __name__ == "__main__":
    run_app()
