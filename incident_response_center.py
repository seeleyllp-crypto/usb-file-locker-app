import json
import os
import queue
import threading
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import diagnostics_center as diagnostics
import trust_recovery_center as trust
import usb_file_locker as locker


REPORT_SCHEMA_VERSION = 1
INCIDENT_ENDPOINT = "/api/v1/incident-guide"


def _step(identifier, title, action, expected):
    return {"id": identifier, "title": title, "action": action, "expected": expected}


LOCAL_PLAYBOOKS = [
    {
        "id": "defender-alert",
        "title": "Microsoft Defender alert",
        "summary": "Handle a Defender detection without rerunning, sharing, or manually deleting the suspicious file.",
        "steps": [
            _step("alert-stop-repeat", "Do not run it again", "Close the related app and do not reopen, copy, or send the detected item.", "The item remains untouched while Windows Security handles it."),
            _step("alert-history", "Read Protection History", "Open Windows Security and record only the visible detection name, severity, action, and time.", "You have useful evidence without copying private file contents or full paths."),
            _step("alert-update", "Update security intelligence", "Use Windows Security to check for current Microsoft Defender protection updates.", "The signature date is current before another scan."),
            _step("alert-scan", "Run the recommended scan", "Run a Quick scan, then use Full or Microsoft Defender Offline scan only when Windows Security recommends it.", "Windows Security finishes and shows its own result."),
            _step("alert-accounts", "Protect important accounts", "If account theft is possible, use another trusted device to change important passwords and review sign-ins.", "The potentially affected PC is not used to enter new passwords."),
            _step("alert-escalate", "Escalate safely", "Ask a trusted adult or qualified technician to review unresolved alerts and the privacy-safe report.", "No key, PIN, private file, or malware sample is sent to support."),
        ],
        "escalation": "Keep the detected item quarantined. Seek qualified help when Defender repeats the alert, protection will not turn on, or account theft is suspected.",
    },
    {
        "id": "account-risk",
        "title": "Possible account theft",
        "summary": "Secure online accounts from a different trusted device and preserve a minimal timeline.",
        "steps": [
            _step("account-trusted-device", "Move to a trusted device", "Stop entering passwords on the possibly affected PC and use a different updated device.", "Password changes happen away from the possibly affected PC."),
            _step("account-passwords", "Change important passwords", "Start with email, password manager, banking, Steam, Discord, and any reused password.", "Every important account has a unique new password."),
            _step("account-sessions", "Sign out other sessions", "Use each provider's security page to remove unknown sessions and remembered devices.", "Only recognized devices remain signed in."),
            _step("account-mfa", "Review recovery and MFA", "Check recovery email, phone, passkeys, authenticator methods, and backup codes for unknown changes.", "Recovery methods belong only to the account owner."),
            _step("account-email", "Review email rules", "Check forwarding, filters, sent mail, and deleted mail for changes you did not make.", "No unknown forwarding or mailbox rule remains."),
            _step("account-timeline", "Save a safe timeline", "Record provider name, approximate time, and actions taken without writing passwords, codes, or tokens.", "A support-safe timeline is ready if more help is needed."),
        ],
        "escalation": "Contact the provider and a trusted adult immediately for financial loss, identity theft, or an account you cannot recover.",
    },
    {
        "id": "lost-usb",
        "title": "Lost or stolen master USB",
        "summary": "Protect existing locked files and recover with the matching backup key instead of creating a replacement key.",
        "steps": [
            _step("usb-preserve", "Preserve every locked file", "Do not rename, edit, delete, or overwrite existing .locked files.", "Original encrypted files remain unchanged."),
            _step("usb-backup", "Locate the matching backup key", "Find the protected backup created from the original master key.", "The backup belongs to the original key, not a newly generated key."),
            _step("usb-compare", "Compare the backup locally", "Use Key Inspector or Compare Backup Key without sharing the key file or secret.", "The app confirms the key IDs and secret match locally."),
            _step("usb-recover", "Test one disposable recovery copy", "Unlock a copied non-private item first and verify the result before bulk recovery.", "The copied item unlocks correctly with the backup key and PIN."),
            _step("usb-policy", "Retire the missing owner USB", "After recovery, update the owner USB policy to the intended replacement removable drive.", "The missing drive no longer satisfies owner-only app controls."),
            _step("usb-new-backup", "Create and verify a new backup", "Store a verified backup separately from the PC and daily-use USB.", "A second tested recovery copy exists in a protected location."),
        ],
        "escalation": "A new key cannot unlock data encrypted by a lost key. Preserve the files and seek qualified recovery help if no matching backup exists.",
    },
    {
        "id": "unlock-failure",
        "title": "Locked file will not unlock",
        "summary": "Troubleshoot without changing the encrypted original or guessing with replacement keys.",
        "steps": [
            _step("unlock-preserve", "Keep the original unchanged", "Work from a copy and leave the original .locked file in place.", "There is always an unchanged recovery source."),
            _step("unlock-key", "Reconnect the original key", "Load the same master key used when the file was locked and confirm it in Key Inspector.", "The selected key is readable and matches the expected key ID."),
            _step("unlock-pin", "Check the optional PIN", "Use the exact original PIN, including capitalization, or leave it blank only if no PIN was used.", "The PIN choice matches the original lock operation."),
            _step("unlock-health", "Run Vault Health Center", "Perform the read-only structure and compatibility checks on a copy of the locked item.", "The app reports whether the container structure is readable."),
            _step("unlock-test", "Run a disposable round trip", "Lock and unlock a new non-private test file with the loaded key and intended PIN.", "The current key and PIN workflow succeeds on disposable data."),
            _step("unlock-report", "Export a safe report", "Export Diagnostics or Vault Health totals and review them before asking for support.", "The report contains no filename, path, key, PIN, or file contents."),
        ],
        "escalation": "Never delete or overwrite the only encrypted copy. Support cannot recover data without the original matching key and PIN.",
    },
    {
        "id": "unknown-behavior",
        "title": "Unknown popups or PC behavior",
        "summary": "Reduce risk, use Windows Security, and avoid destructive guesses about normal applications.",
        "steps": [
            _step("behavior-close", "Close the unknown window", "Do not approve prompts, enter passwords, or click links in an unexpected window.", "The unexpected prompt is closed without granting access."),
            _step("behavior-network", "Disconnect only when activity is ongoing", "If you see active unauthorized control or transfers, disconnect Wi-Fi or Ethernet while preserving the PC state.", "Ongoing network access is interrupted without deleting evidence."),
            _step("behavior-security", "Open Windows Security", "Review Protection History, update signatures, and run the scan Windows Security recommends.", "Microsoft Defender provides the detection result."),
            _step("behavior-startup", "Review startup apps", "Use Windows Settings or Task Manager to note unfamiliar startup entries; do not delete items solely because they are unfamiliar.", "Unknown entries are documented for review without damaging normal apps."),
            _step("behavior-updates", "Install trusted updates", "Update Windows and affected software only through their signed built-in updater or official source.", "The system and known applications are current."),
            _step("behavior-report", "Create a reviewed safe report", "Run Diagnostics Center and save only coarse check results after reviewing the export.", "No screenshot, key, password, path, or private content is uploaded automatically."),
        ],
        "escalation": "Use qualified help for persistent remote-control signs, disabled security tools, repeated detections, financial risk, or threats involving a child.",
    },
    {
        "id": "update-integrity",
        "title": "Update or integrity problem",
        "summary": "Recover the transparent app folder while preserving keys, licenses, settings, audit logs, and locked data.",
        "steps": [
            _step("update-close", "Close duplicate app copies", "Leave only the intended VaultLink folder open before retrying the update.", "No older app process is holding update files."),
            _step("update-preserve", "Preserve LocalAppData", "Do not delete the USBFileLocker app-data folder, keys, settings, audit logs, or locked files.", "Customer data stays available for the repaired app."),
            _step("update-center", "Use Update Center", "Check the signed release through the configured VaultLink API instead of downloading an unknown package.", "The release version and signing identity are visible."),
            _step("update-verify", "Require both verification checks", "Install only when the Ed25519 signature and package SHA-256 both verify.", "The updater accepts the exact signed package."),
            _step("update-readiness", "Check space and clock", "Keep at least 500 MB free and enable automatic Windows date, time, and time zone.", "Diagnostics reports normal storage and service-time checks."),
            _step("update-rollback", "Use the rollback copy", "If the verified update fails, preserve the error and restore only app files from the updater backup.", "App data remains untouched while app files return to the prior version."),
        ],
        "escalation": "Do not bypass Defender or signature warnings. Send the exact visible error and reviewed safe diagnostics to the owner.",
    },
    {
        "id": "device-loss",
        "title": "Lost PC or major data loss",
        "summary": "Secure accounts and recover from separately stored keys and backups without exposing secrets online.",
        "steps": [
            _step("device-account", "Secure the Windows account", "Use the official Microsoft account device and sign-in pages from a trusted device.", "Unknown sign-ins are removed and the account password is changed if needed."),
            _step("device-seat", "Deactivate the lost license seat", "Use Customer Center to remove the lost anonymous device seat from the active license.", "The lost installation stops receiving licensed premium access."),
            _step("device-online", "Rotate important online accounts", "Change passwords and review sessions for accounts that were accessible on the lost PC.", "Only recognized devices and recovery methods remain."),
            _step("device-copies", "Locate separate recovery copies", "Gather the matching master-key backup, app-data backup, and any independent copy of locked files.", "Recovery materials come from protected locations separate from the lost PC."),
            _step("device-restore", "Restore on a trusted replacement PC", "Install the transparent signed app folder, verify Defender, then test one disposable recovery copy.", "The replacement environment passes a safe recovery test before bulk work."),
            _step("device-timeline", "Document a safe timeline", "Record approximate times, provider actions, and recovery results without secrets or private contents.", "A minimal reviewed incident record is available for support or insurance."),
        ],
        "escalation": "Contact law enforcement, the device provider, financial institutions, or a qualified professional when theft, financial loss, or identity exposure is involved.",
    },
    {
        "id": "phishing-message",
        "title": "Suspicious email, text, or link",
        "summary": "Contain a possible phishing attempt without opening attachments, signing in through the message, or forwarding private content.",
        "steps": [
            _step("phishing-stop", "Stop interacting with the message", "Do not click more links, open attachments, reply, call listed numbers, or enter information.", "The suspicious message receives no additional interaction."),
            _step("phishing-close", "Close the page or attachment", "Close the message and any page it opened without downloading or running anything else.", "The suspicious content is no longer open."),
            _step("phishing-provider", "Use the provider directly", "Open the official app or type the known official address yourself to check the claimed alert.", "Any real account notice is reviewed outside the suspicious message."),
            _step("phishing-credentials", "Protect exposed credentials", "If a password or code was entered, use another trusted device to change it and end unknown sessions.", "The exposed credential is replaced and unknown sessions are removed."),
            _step("phishing-report", "Report through trusted controls", "Use the mail, message, school, or workplace provider's built-in report-phishing control.", "The provider receives the original report without you forwarding it to other people."),
            _step("phishing-scan", "Check downloads safely", "If anything downloaded or ran, leave it closed and use Microsoft Defender to scan and review Protection History.", "Windows Security supplies the scan result."),
        ],
        "escalation": "Contact the real provider, a trusted adult, or a qualified professional for money loss, identity exposure, school or work compromise, or an account you cannot recover.",
    },
    {
        "id": "ransomware-warning",
        "title": "Ransomware warning or changed files",
        "summary": "Limit further damage, preserve evidence, and use trusted recovery paths without paying, rerunning, or renaming affected files.",
        "steps": [
            _step("ransomware-isolate", "Disconnect the affected PC", "Disconnect Wi-Fi and Ethernet if files are actively changing or a ransom message is visible.", "The affected PC no longer reaches network shares or cloud sync."),
            _step("ransomware-stop", "Do not pay or rerun anything", "Do not contact payment addresses, run alleged decryptors, or reopen the suspected program.", "No payment or additional untrusted code is introduced."),
            _step("ransomware-preserve", "Preserve affected files", "Do not rename, edit, delete, or overwrite encrypted files, notes, or the only backup copies.", "Original evidence and recovery candidates remain unchanged."),
            _step("ransomware-security", "Use Windows Security", "Review Protection History and follow Microsoft Defender recommendations, including Offline scan when offered.", "Windows Security completes its recommended response."),
            _step("ransomware-backups", "Protect separate backups", "Keep disconnected backups and matching VaultLink keys offline until the affected PC is reviewed.", "Known-good recovery material is not exposed to the affected PC."),
            _step("ransomware-help", "Get qualified recovery help", "Use a trusted adult, organization administrator, insurer, law enforcement contact, or qualified incident responder as appropriate.", "Recovery decisions are reviewed before restoring or reconnecting the PC."),
        ],
        "escalation": "Treat active encryption, business systems, financial demands, or sensitive records as urgent. Do not reconnect or restore until a qualified responder says it is safe.",
    },
    {
        "id": "exposed-secret",
        "title": "Password, PIN, or key was exposed",
        "summary": "Replace exposed online credentials and protect VaultLink recovery material without copying secrets into reports or support messages.",
        "steps": [
            _step("secret-stop", "Stop sharing the secret", "Remove it from any unsent draft and do not paste it into chat, email, screenshots, bug reports, or the incident export.", "No new copy of the secret is intentionally shared."),
            _step("secret-scope", "Identify the secret type", "Classify it only as password, one-time code, recovery code, PIN, API token, or VaultLink key without recording the value.", "The correct replacement process can be chosen without storing the secret."),
            _step("secret-rotate", "Replace online credentials", "From a trusted device, change exposed passwords or tokens and revoke unknown sessions or app access.", "The exposed online credential no longer grants access."),
            _step("secret-mfa", "Review account recovery", "Check MFA, passkeys, backup codes, recovery email, and recovery phone for unauthorized changes.", "Only approved recovery methods remain."),
            _step("secret-vault", "Handle VaultLink keys separately", "If a master-key file was copied, preserve locked data and use the documented re-lock migration plan with verified backups.", "Existing encrypted originals remain available while future access is moved carefully."),
            _step("secret-monitor", "Watch for follow-on activity", "Review provider security alerts, sign-ins, and financial activity without entering details into VaultLink.", "Unexpected activity is reported directly to the relevant provider."),
        ],
        "escalation": "Contact the provider and a trusted adult immediately for financial, identity, school, work, or healthcare exposure. VaultLink cannot remotely rotate or recover secrets.",
    },
    {
        "id": "browser-change",
        "title": "Suspicious browser change",
        "summary": "Review unexpected extensions, redirects, notifications, and search changes without deleting normal browser data by guesswork.",
        "steps": [
            _step("browser-close", "Close suspicious tabs", "Close unexpected login, support, prize, warning, or download tabs without approving prompts.", "The suspicious page is no longer active."),
            _step("browser-extensions", "Review installed extensions", "Open the browser's extension page and disable unfamiliar items while recording only their displayed names.", "Unrecognized extensions stop running without exposing browsing data."),
            _step("browser-notifications", "Review notification permission", "Remove notification access for sites you do not recognize in browser privacy settings.", "Unknown sites can no longer send browser notifications."),
            _step("browser-search", "Restore browser settings", "Use built-in settings to review startup pages, search provider, downloads, and proxy settings.", "Expected browser settings are restored through normal controls."),
            _step("browser-security", "Run Windows Security checks", "Update Microsoft Defender and run the scan it recommends if a download or installer may have run.", "Windows Security supplies the local result."),
            _step("browser-account", "Review browser sync", "From the official account security page, remove unknown synced devices and review recent sign-ins.", "Only recognized devices remain connected to browser sync."),
        ],
        "escalation": "Use qualified help when redirects return, security settings cannot be restored, extensions reinstall, or account and financial activity is affected.",
    },
    {
        "id": "backup-failure",
        "title": "Backup or restore failure",
        "summary": "Protect the only good copies, verify key compatibility, and test recovery on disposable data before attempting bulk restoration.",
        "steps": [
            _step("backup-stop", "Stop overwriting backups", "Pause backup or sync jobs that may replace known-good copies with damaged or incomplete data.", "Existing recovery copies remain unchanged."),
            _step("backup-inventory", "Count recovery sources", "Identify separate app-data backups, locked-file copies, and matching key backups without listing private names or paths.", "You know how many independent recovery sources exist."),
            _step("backup-health", "Check storage health", "Use Windows drive error checking and Vault Health read-only checks before writing to the recovery drive.", "Basic storage and container checks finish without changing originals."),
            _step("backup-key", "Verify the matching key", "Use Key Inspector or Compare Backup Key locally and never upload the key file.", "The recovery key matches the expected key ID and secret."),
            _step("backup-test", "Restore one disposable copy", "Copy one non-private test item to a separate folder and verify its full lock-unlock round trip.", "The tested copy opens correctly before any bulk restore."),
            _step("backup-record", "Record a recovery result", "Save only coarse totals, dates, and pass or fail status in the reviewed safe report.", "A support-safe record exists without filenames, paths, keys, PINs, or contents."),
        ],
        "escalation": "Stop when drives disconnect, make unusual sounds, report hardware errors, or contain the only copy. Use a qualified recovery professional before further writes.",
    },
]


def _fallback_guide(message="Online incident guide unavailable."):
    return {
        "ok": False,
        "incident_schema_version": 1,
        "api_version": "Unavailable",
        "service_status": {"mode": "unknown", "message": message, "updated_at_utc": ""},
        "signed_release": {"ready": False, "version": "", "minimum_supported_version": ""},
        "playbooks": json.loads(json.dumps(LOCAL_PLAYBOOKS)),
        "privacy_boundaries": [
            "Checklist progress stays only in this app session unless the customer explicitly exports a reviewed report.",
            "No key, PIN, receipt, customer identity, machine identity, path, filename, screenshot, or file content is collected.",
            "The incident center cannot remotely inspect, quarantine, delete, unlock, scan, or control a customer PC.",
        ],
        "limitations": [
            "Guidance and readiness checks are not malware removal, certification, legal advice, or a guarantee of recovery.",
            "Microsoft Defender and qualified human review remain necessary for malware and high-impact security decisions.",
        ],
        "server_time_utc": "",
        "customer_records_included": False,
        "accepts_free_text": False,
        "accepts_files": False,
    }


def safe_incident_guide(payload):
    source = payload if isinstance(payload, dict) else {}
    fallback = _fallback_guide()
    if not source.get("ok"):
        return fallback

    def clean(value, default="", limit=320):
        return trust.safe_online_text(value, default, limit)

    def clean_list(values, limit=20):
        if not isinstance(values, (list, tuple)):
            return []
        return [clean(value) for value in values[:limit] if clean(value)]

    raw_playbooks = source.get("playbooks")
    playbooks = []
    if isinstance(raw_playbooks, (list, tuple)):
        for raw in raw_playbooks[:16]:
            if not isinstance(raw, dict):
                continue
            steps = []
            raw_steps = raw.get("steps")
            if isinstance(raw_steps, (list, tuple)):
                for raw_step in raw_steps[:8]:
                    if not isinstance(raw_step, dict):
                        continue
                    steps.append(
                        _step(
                            clean(raw_step.get("id"), "step", 80),
                            clean(raw_step.get("title"), "Response step", 160),
                            clean(raw_step.get("action"), "Review this step locally."),
                            clean(raw_step.get("expected"), "Record whether the step is complete."),
                        )
                    )
            if steps:
                playbooks.append(
                    {
                        "id": clean(raw.get("id"), "other", 80),
                        "title": clean(raw.get("title"), "Other incident", 140),
                        "summary": clean(raw.get("summary"), "Use the fixed response steps."),
                        "steps": steps,
                        "escalation": clean(raw.get("escalation"), "Seek qualified help when the issue remains unresolved."),
                    }
                )
    if not playbooks:
        playbooks = fallback["playbooks"]
    service = source.get("service_status") if isinstance(source.get("service_status"), dict) else {}
    release = source.get("signed_release") if isinstance(source.get("signed_release"), dict) else {}
    return {
        "ok": True,
        "incident_schema_version": 1,
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
        "playbooks": playbooks,
        "privacy_boundaries": clean_list(source.get("privacy_boundaries")) or fallback["privacy_boundaries"],
        "limitations": clean_list(source.get("limitations")) or fallback["limitations"],
        "server_time_utc": clean(source.get("server_time_utc"), "", 40),
        "customer_records_included": False,
        "accepts_free_text": False,
        "accepts_files": False,
    }


READINESS_CHECKS = (
    ("defender-protection", "Windows", "Microsoft Defender protection", 20),
    ("defender-signatures", "Windows", "Current Defender signatures", 10),
    ("audit-chain", "Evidence", "Local audit integrity", 15),
    ("owner-usb-policy", "Recovery", "Owner USB policy", 10),
    ("selected-key", "Recovery", "Selected recovery key", 15),
    ("signed-release", "Updates", "Verified signed release", 10),
    ("recovery-test", "Recovery", "Disposable recovery test", 10),
    ("app-data-backup", "Recovery", "Recorded app-data backup", 10),
)


def build_incident_report(diagnostic_report, online_guide, selected_playbook_id="", completed_step_ids=None, generated_at_utc=""):
    diagnostic_report = diagnostic_report if isinstance(diagnostic_report, dict) else {}
    guide = safe_incident_guide(online_guide)
    check_map = {
        str(item.get("id")): item
        for item in diagnostic_report.get("checks", [])
        if isinstance(item, dict) and item.get("id")
    }
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
                "detail": str(source.get("detail") or "This readiness result is unavailable."),
                "action": str(source.get("action") or "Run Diagnostics Center and review the failed check."),
            }
        )
    score = sum(item["weight"] for item in checks if item["passed"])
    label = "ready" if score >= 90 else "prepared" if score >= 70 else "attention" if score >= 50 else "action"
    playbooks = guide["playbooks"]
    selected = next((item for item in playbooks if item["id"] == selected_playbook_id), playbooks[0])
    valid_step_ids = {item["id"] for item in selected["steps"]}
    completed = sorted(valid_step_ids.intersection(str(value) for value in (completed_step_ids or [])))
    generated = generated_at_utc or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": "VaultLink Privacy-Safe Incident Readiness Report",
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
        "selected_playbook": {
            "id": selected["id"],
            "title": selected["title"],
            "summary": selected["summary"],
            "steps": selected["steps"],
            "escalation": selected["escalation"],
            "completed_step_ids": completed,
            "completed_count": len(completed),
            "total_steps": len(selected["steps"]),
        },
        "online_guide": {
            "available": bool(guide.get("ok")),
            "api_version": guide.get("api_version", "Unavailable"),
            "service_mode": guide.get("service_status", {}).get("mode", "unknown"),
            "signed_release_ready": bool(guide.get("signed_release", {}).get("ready")),
            "signed_release_version": guide.get("signed_release", {}).get("version", ""),
            "playbook_count": len(playbooks),
        },
        "privacy_notice": (
            "This report excludes license keys, receipts, customer and machine identity, passwords, PINs, USB secrets, "
            "paths, filenames, screenshots, process lists, private file contents, and free-form incident text."
        ),
        "limitations": list(guide.get("limitations") or _fallback_guide()["limitations"]),
    }


def collect_incident_inputs():
    diagnostic_report = diagnostics.collect_diagnostics_report()
    guide = _fallback_guide()
    try:
        settings = locker.load_settings()
        state = locker.load_license_state(settings)
        server = locker.validated_license_server_url(state.get("server_url"))
        guide = safe_incident_guide(locker.license_api_get_json(server, INCIDENT_ENDPOINT))
    except Exception:
        pass
    return diagnostic_report, guide


def safe_incident_text(report):
    readiness = report["readiness"]
    playbook = report["selected_playbook"]
    completed = set(playbook["completed_step_ids"])
    lines = [
        f"INCIDENT READINESS  {readiness['value']} / {readiness['maximum']}  {readiness['label'].upper()}",
        f"READINESS CHECKS    {readiness['passed']} / {readiness['total']} PASSED",
        f"PLAYBOOK            {playbook['title']}",
        f"PLAYBOOK PROGRESS   {playbook['completed_count']} / {playbook['total_steps']}",
        f"GENERATED           {report['generated_at_utc']}",
        "",
        "LOCAL READINESS",
        "---------------",
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
    lines.extend(["RESPONSE PLAYBOOK", "-----------------", playbook["summary"], ""])
    for index, step in enumerate(playbook["steps"], 1):
        marker = "X" if step["id"] in completed else " "
        lines.extend(
            [
                f"[{marker}] STEP {index}: {step['title']}",
                f"    {step['action']}",
                f"    EXPECTED: {step['expected']}",
                "",
            ]
        )
    lines.extend([f"ESCALATION: {playbook['escalation']}", "", "PRIVACY", "-------", report["privacy_notice"], "", "LIMITATIONS", "-----------"])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines)


def safe_incident_summary(report):
    readiness = report["readiness"]
    playbook = report["selected_playbook"]
    attention = [item for item in report["checks"] if not item["passed"]]
    lines = [
        f"VaultLink incident readiness: {readiness['value']}/100 {readiness['label'].upper()}",
        f"Playbook: {playbook['title']} ({playbook['completed_count']}/{playbook['total_steps']} complete)",
    ]
    lines.extend(f"Attention: {item['title']} - {item['action']}" for item in attention[:6])
    lines.append(report["privacy_notice"])
    return "\n".join(lines)


class IncidentResponseCenter(tk.Tk):
    def __init__(self):
        super().__init__()
        if not locker.ensure_license_feature("incident-response-center", parent=self):
            self.after(0, self.destroy)
            return
        self.title("VaultLink Incident Response Center")
        self.geometry("1080x820")
        self.minsize(860, 660)
        self.configure(bg=locker.BG)
        self.results = queue.Queue()
        self.busy = False
        self.diagnostic_report = None
        self.guide = _fallback_guide()
        self.report = None
        self.completed = {}
        self.playbook_var = tk.StringVar(value=LOCAL_PLAYBOOKS[0]["title"])
        self.status_var = tk.StringVar(value="Ready to build a privacy-safe response plan.")
        self.metric_vars = {
            "readiness": tk.StringVar(value="-- / 100"),
            "checks": tk.StringVar(value="-- / 8"),
            "progress": tk.StringVar(value="0 / 6"),
            "defender": tk.StringVar(value="Not checked"),
            "online": tk.StringVar(value="Not checked"),
        }
        self.title_to_id = {item["title"]: item["id"] for item in LOCAL_PLAYBOOKS}
        self.refresh_button = None
        self.export_button = None
        self.copy_button = None
        self.playbook_box = None
        self.output = None
        self.build_ui()
        locker.log_event("incident_center_open", "local", "ok")
        self.after(150, self.refresh)

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=22)
        tk.Label(outer, text="Incident Response Center", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 24, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="FIXED PLAYBOOKS | LOCAL READINESS | WINDOWS SECURITY | REVIEWED SAFE EXPORT",
            bg=locker.BG,
            fg=locker.YELLOW,
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w", pady=(3, 12))

        primary = tk.Frame(outer, bg=locker.BG)
        primary.pack(fill="x", pady=(0, 8))
        self.refresh_button = tk.Button(primary, text="REFRESH READINESS", command=self.refresh, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold"))
        self.refresh_button.pack(side="left", ipadx=10, ipady=7)
        self.export_button = tk.Button(primary, text="EXPORT SAFE JSON", command=self.export_report, state="disabled", bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.export_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=7)
        self.copy_button = tk.Button(primary, text="COPY SAFE SUMMARY", command=self.copy_summary, state="disabled", bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.copy_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=7)
        tk.Button(primary, text="WINDOWS SECURITY", command=self.open_windows_security, bg=locker.BLUE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=10, ipady=7)

        links = tk.Frame(outer, bg=locker.BG)
        links.pack(fill="x", pady=(0, 10))
        tk.Button(links, text="ONLINE RESPONSE", command=lambda: self.open_server_page("/incident-response"), bg=locker.BLUE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", ipadx=8, ipady=6)
        tk.Button(links, text="DIAGNOSTICS", command=lambda: self.open_companion("diagnostics_center.py", "Diagnostics Center"), bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(8, 0), ipadx=8, ipady=6)
        tk.Button(links, text="AUDIT LOG", command=lambda: self.open_companion("audit_log_viewer.py", "Audit Log Viewer"), bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(8, 0), ipadx=8, ipady=6)
        tk.Button(links, text="VAULT HEALTH", command=lambda: self.open_companion("vault_health_center.py", "Vault Health Center"), bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(8, 0), ipadx=8, ipady=6)

        playbook_row = tk.Frame(outer, bg=locker.PANEL, padx=14, pady=12, highlightbackground="#343b49", highlightthickness=1)
        playbook_row.pack(fill="x", pady=(0, 10))
        tk.Label(playbook_row, text="INCIDENT PLAYBOOK", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        self.playbook_box = ttk.Combobox(playbook_row, textvariable=self.playbook_var, state="readonly", width=34, values=tuple(self.title_to_id))
        self.playbook_box.pack(side="left", padx=(10, 0))
        self.playbook_box.bind("<<ComboboxSelected>>", lambda _event: self.select_playbook())
        tk.Button(playbook_row, text="MARK NEXT COMPLETE", command=self.mark_next, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(10, 0), ipadx=8, ipady=5)
        tk.Button(playbook_row, text="RESET", command=self.reset_playbook, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(8, 0), ipadx=8, ipady=5)
        tk.Label(playbook_row, text="Progress stays in this app session.", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8)).pack(side="right")

        metrics = tk.Frame(outer, bg=locker.PANEL, highlightbackground="#343b49", highlightthickness=1)
        metrics.pack(fill="x")
        for column, (label, key) in enumerate((("READINESS", "readiness"), ("CHECKS", "checks"), ("PLAYBOOK", "progress"), ("DEFENDER", "defender"), ("API GUIDE", "online"))):
            metrics.grid_columnconfigure(column, weight=1, uniform="incident")
            item = tk.Frame(metrics, bg=locker.PANEL, padx=13, pady=10)
            item.grid(row=0, column=column, sticky="nsew")
            tk.Label(item, text=label, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 7, "bold")).pack(anchor="w")
            tk.Label(item, textvariable=self.metric_vars[key], bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 11, "bold"), wraplength=170, justify="left").pack(anchor="w", pady=(4, 0))

        tk.Label(outer, textvariable=self.status_var, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9), wraplength=980, justify="left").pack(anchor="w", pady=(9, 7))
        text_frame = tk.Frame(outer, bg=locker.FIELD)
        text_frame.pack(fill="both", expand=True)
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side="right", fill="y")
        self.output = tk.Text(text_frame, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", wrap="word", font=("Consolas", 10), padx=16, pady=14, yscrollcommand=scrollbar.set)
        self.output.pack(fill="both", expand=True)
        scrollbar.configure(command=self.output.yview)
        self.output.insert("1.0", "No incident readiness report loaded yet.")
        self.output.configure(state="disabled")

    def selected_playbook_id(self):
        return self.title_to_id.get(self.playbook_var.get(), LOCAL_PLAYBOOKS[0]["id"])

    def set_busy(self, value, message=""):
        self.busy = bool(value)
        self.refresh_button.configure(state="disabled" if self.busy else "normal")
        ready = "normal" if self.report and not self.busy else "disabled"
        self.export_button.configure(state=ready)
        self.copy_button.configure(state=ready)
        if message:
            self.status_var.set(message)

    def refresh(self):
        if self.busy:
            return
        self.set_busy(True, "Checking local Defender, audit, USB, update, backup, and recovery readiness...")

        def worker():
            try:
                self.results.put((True, collect_incident_inputs()))
            except Exception:
                self.results.put((False, "Incident readiness checks could not complete safely."))

        threading.Thread(target=worker, name="VaultLinkIncidentReadiness", daemon=True).start()
        self.after(120, self.poll_result)

    def poll_result(self):
        try:
            success, payload = self.results.get_nowait()
        except queue.Empty:
            if self.winfo_exists():
                self.after(120, self.poll_result)
            return
        if not success:
            self.set_busy(False, str(payload))
            locker.log_event("incident_center_refresh", "local", "failed")
            messagebox.showerror("Readiness check failed", str(payload), parent=self)
            return
        self.diagnostic_report, self.guide = payload
        self.refresh_playbook_choices()
        self.rebuild_report()
        self.set_busy(False, f"Incident readiness refreshed at {self.report['generated_at_utc']}.")
        locker.log_event("incident_center_refresh", "local", "ok")

    def refresh_playbook_choices(self):
        playbooks = self.guide.get("playbooks") or LOCAL_PLAYBOOKS
        current_id = self.selected_playbook_id()
        self.title_to_id = {item["title"]: item["id"] for item in playbooks}
        self.playbook_box.configure(values=tuple(self.title_to_id))
        selected = next((item for item in playbooks if item["id"] == current_id), playbooks[0])
        self.playbook_var.set(selected["title"])

    def rebuild_report(self):
        if not self.diagnostic_report:
            return
        selected = self.selected_playbook_id()
        self.report = build_incident_report(self.diagnostic_report, self.guide, selected, self.completed.get(selected, set()))
        readiness = self.report["readiness"]
        playbook = self.report["selected_playbook"]
        self.metric_vars["readiness"].set(f"{readiness['value']} / 100 {readiness['label'].upper()}")
        self.metric_vars["checks"].set(f"{readiness['passed']} / {readiness['total']}")
        self.metric_vars["progress"].set(f"{playbook['completed_count']} / {playbook['total_steps']}")
        defender = next((item for item in self.report["checks"] if item["id"] == "defender-protection"), {})
        self.metric_vars["defender"].set("Protected" if defender.get("passed") else "Review")
        self.metric_vars["online"].set(str(self.report["online_guide"]["api_version"]))
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", safe_incident_text(self.report))
        self.output.configure(state="disabled")
        self.export_button.configure(state="normal")
        self.copy_button.configure(state="normal")

    def select_playbook(self):
        self.rebuild_report()
        if self.report:
            self.status_var.set(f"Selected {self.report['selected_playbook']['title']}.")

    def mark_next(self):
        if not self.report:
            return
        playbook = self.report["selected_playbook"]
        completed = self.completed.setdefault(playbook["id"], set())
        next_step = next((item for item in playbook["steps"] if item["id"] not in completed), None)
        if next_step:
            completed.add(next_step["id"])
            locker.log_event("incident_playbook_progress", playbook["id"], "ok")
        self.rebuild_report()
        if self.report["selected_playbook"]["completed_count"] == self.report["selected_playbook"]["total_steps"]:
            self.status_var.set("All fixed steps are marked complete. Review the result and escalate when needed.")
        elif next_step:
            self.status_var.set(f"Marked complete: {next_step['title']}.")

    def reset_playbook(self):
        selected = self.selected_playbook_id()
        self.completed[selected] = set()
        self.rebuild_report()
        self.status_var.set("Current playbook progress reset in memory.")

    def open_windows_security(self):
        try:
            if os.name != "nt" or not hasattr(os, "startfile"):
                raise OSError("Windows Security is available only on Windows.")
            os.startfile("windowsdefender:")
            self.status_var.set("Opened Windows Security. VaultLink does not read or control that window.")
            locker.log_event("incident_windows_security_open", "local", "ok")
        except Exception as exc:
            locker.log_event("incident_windows_security_open", "local", "failed")
            messagebox.showerror("Could not open Windows Security", str(exc), parent=self)

    def open_companion(self, script, title):
        try:
            locker.launch_companion_script(script)
            self.status_var.set(f"Opened {title}.")
        except Exception as exc:
            messagebox.showerror(f"Could not open {title}", str(exc), parent=self)

    def open_server_page(self, path):
        try:
            settings = locker.load_settings()
            state = locker.load_license_state(settings)
            server = locker.validated_license_server_url(state.get("server_url"))
            webbrowser.open(server + path, new=2)
        except Exception as exc:
            messagebox.showerror("Could not open page", str(exc), parent=self)

    def copy_summary(self):
        if not self.report:
            return
        self.clipboard_clear()
        self.clipboard_append(safe_incident_summary(self.report))
        self.update()
        self.status_var.set("Privacy-safe incident summary copied.")
        locker.log_event("incident_center_copy", "report", "ok")

    def export_report(self):
        if not self.report:
            return
        destination = filedialog.asksaveasfilename(
            parent=self,
            title="Export privacy-safe incident report",
            initialfile="vaultlink-incident-readiness.json",
            defaultextension=".json",
            filetypes=[("JSON report", "*.json"), ("All files", "*.*")],
        )
        if not destination:
            return
        try:
            Path(destination).write_text(json.dumps(self.report, indent=2, ensure_ascii=True), encoding="utf-8")
            self.status_var.set("Privacy-safe incident report exported.")
            locker.log_event("incident_center_export", "report", "ok")
        except Exception as exc:
            locker.log_event("incident_center_export", "report", "failed")
            messagebox.showerror("Export failed", str(exc), parent=self)


if __name__ == "__main__":
    IncidentResponseCenter().mainloop()
