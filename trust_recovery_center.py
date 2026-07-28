import json
import queue
import threading
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox

import usb_file_locker as locker


REPORT_SCHEMA_VERSION = 1
TRUST_ENDPOINT = "/api/v1/trust-center"


def latest_success_time(records, action):
    times = [
        str(record.get("time_utc", ""))
        for record in records or []
        if record.get("action") == action and record.get("result") == "success" and record.get("time_utc")
    ]
    return max(times) if times else ""


def selected_key_ready(settings):
    path = str((settings or {}).get("last_key_path", "") or "").strip()
    if not path:
        return False
    try:
        key = locker.load_key_file(path)
        policy = locker.load_owner_policy(settings or {})
        allowed, _reason = locker.owner_key_allowed(key, policy)
        return bool(allowed)
    except Exception:
        return False


def local_control_pin_ready(settings):
    try:
        import local_control_center

        return bool(local_control_center.control_pin_configured(settings or {}))
    except Exception:
        return False


def safe_online_text(value, fallback="", limit=240):
    text = " ".join(str(value or "").split())[:limit]
    lowered = text.lower()
    if "\\" in text or ":/" in text or "vlk1." in lowered or "vlr1." in lowered:
        return fallback
    return text or fallback


def safe_online_trust_payload(payload):
    source = payload if isinstance(payload, dict) else {}
    if not source.get("ok"):
        return {"ok": False, "message": "Public Trust Center unavailable."}
    score = source.get("score") if isinstance(source.get("score"), dict) else {}
    service = source.get("service_status") if isinstance(source.get("service_status"), dict) else {}
    release = source.get("signed_release") if isinstance(source.get("signed_release"), dict) else {}
    release_checks = release.get("checks") if isinstance(release.get("checks"), dict) else {}
    storage = source.get("storage") if isinstance(source.get("storage"), dict) else {}
    boundaries = source.get("data_boundaries") if isinstance(source.get("data_boundaries"), dict) else {}

    def bounded_number(value, low=0, high=1000000):
        try:
            return min(high, max(low, int(value)))
        except (TypeError, ValueError):
            return low

    def safe_list(values, limit=20):
        if not isinstance(values, (list, tuple)):
            return []
        cleaned = []
        for value in values[:limit]:
            safe_value = safe_online_text(value)
            if safe_value:
                cleaned.append(safe_value)
        return cleaned

    clean_checks = []
    for item in list(source.get("checks") or [])[:30]:
        if not isinstance(item, dict):
            continue
        clean_checks.append(
            {
                "id": safe_online_text(item.get("id"), "check", 80),
                "category": safe_online_text(item.get("category"), "Service", 80),
                "title": safe_online_text(item.get("title"), "Trust check", 160),
                "state": safe_online_text(item.get("state"), "attention", 20),
                "passed": bool(item.get("passed")),
                "weight": bounded_number(item.get("weight"), 0, 100),
                "detail": safe_online_text(item.get("detail"), "No public detail is available."),
                "action": safe_online_text(item.get("action")),
            }
        )
    clean_crypto = []
    for item in list(source.get("cryptography") or [])[:12]:
        if isinstance(item, dict):
            clean_crypto.append(
                {
                    "purpose": safe_online_text(item.get("purpose"), "Security control", 120),
                    "control": safe_online_text(item.get("control"), "No public detail is available."),
                }
            )
    return {
        "ok": True,
        "trust_schema_version": bounded_number(source.get("trust_schema_version"), 1, 10),
        "api_version": safe_online_text(source.get("api_version"), "Unknown", 80),
        "score": {
            "value": bounded_number(score.get("value"), 0, 100),
            "maximum": bounded_number(score.get("maximum"), 1, 100),
            "label": safe_online_text(score.get("label"), "unknown", 20),
            "attention_count": bounded_number(score.get("attention_count"), 0, 100),
        },
        "checks": clean_checks,
        "service_status": {
            "mode": safe_online_text(service.get("mode"), "unknown", 40),
            "message": safe_online_text(service.get("message"), "No public service message."),
            "updated_at_utc": safe_online_text(service.get("updated_at_utc"), "", 40),
        },
        "signed_release": {
            "ready": bool(release.get("ready")),
            "version": safe_online_text(release.get("version"), "", 40),
            "minimum_supported_version": safe_online_text(release.get("minimum_supported_version"), "", 40),
            "published_at_utc": safe_online_text(release.get("published_at_utc"), "", 40),
            "package_filename": safe_online_text(release.get("package_filename"), "", 120),
            "size_bytes": bounded_number(release.get("size_bytes"), 0, 250 * 1024 * 1024),
            "sha256": safe_online_text(release.get("sha256"), "", 64),
            "signing_key_id": safe_online_text(release.get("signing_key_id"), "", 80),
            "checks": {
                key: safe_online_text(release_checks.get(key), "failed", 20)
                for key in ("manifest_schema", "ed25519_signature", "package_size", "package_sha256", "app_data_preservation")
            },
        },
        "storage": {
            "license_state": safe_online_text(storage.get("license_state"), "unknown", 40),
            "audit_exports": safe_online_text(storage.get("audit_exports"), "unknown", 40),
            "private_license_fields_encrypted": bool(storage.get("private_license_fields_encrypted")),
            "support_private_fields_encrypted": bool(storage.get("support_private_fields_encrypted")),
        },
        "cryptography": clean_crypto,
        "data_boundaries": {
            "stays_on_customer_pc": safe_list(boundaries.get("stays_on_customer_pc")),
            "may_reach_api_after_explicit_action": safe_list(boundaries.get("may_reach_api_after_explicit_action")),
            "never_requested_by_api": safe_list(boundaries.get("never_requested_by_api")),
        },
        "recovery_steps": safe_list(source.get("recovery_steps")),
        "limitations": safe_list(source.get("limitations")),
        "safe_to_export": bool(source.get("safe_to_export")),
        "customer_records_included": False,
        "server_time_utc": safe_online_text(source.get("server_time_utc"), "", 40),
    }


def build_local_trust_report(
    settings,
    state,
    defender,
    audit_verification,
    audit_records,
    online_trust=None,
):
    settings = dict(settings or {})
    state = locker.normalize_license_state(state)
    defender = dict(defender or {})
    online = safe_online_trust_payload(online_trust)
    audit_valid, audit_count, audit_message = audit_verification
    details = locker.customer_center_details(state, settings)
    owner_policy_ready = bool(locker.load_owner_policy(settings))
    key_ready = selected_key_ready(settings)
    control_pin_ready = local_control_pin_ready(settings)
    recovery_test = latest_success_time(audit_records, "recovery_self_test")
    backup_time = latest_success_time(audit_records, "backup_app_data")
    signed_release = online.get("signed_release") if isinstance(online.get("signed_release"), dict) else {}
    online_score = online.get("score") if isinstance(online.get("score"), dict) else {}
    checks = []

    def add(identifier, category, title, passed, weight, detail, action):
        checks.append(
            {
                "id": identifier,
                "category": category,
                "title": title,
                "state": "good" if passed else "attention",
                "passed": bool(passed),
                "weight": int(weight),
                "detail": detail,
                "action": action,
            }
        )

    defender_ready = bool(defender.get("available") and defender.get("ProtectedNow"))
    add(
        "defender",
        "Windows",
        "Microsoft Defender protection",
        defender_ready,
        15,
        "Defender reports antivirus, real-time, behavior, and download protection enabled." if defender_ready else "Defender protection could not be confirmed as fully enabled.",
        "Open Windows Security, confirm protection is enabled, and run a current scan.",
    )
    add(
        "audit-chain",
        "Audit",
        "Local audit chain",
        bool(audit_valid),
        15,
        f"{audit_message} {int(audit_count)} event(s) checked.",
        "Preserve the audit folder, export a privacy-safe copy, and investigate the first failed event.",
    )
    add(
        "owner-policy",
        "USB",
        "Owner USB policy",
        owner_policy_ready,
        10,
        "A Windows-protected owner USB policy is configured." if owner_policy_ready else "No owner USB policy is configured for this Windows user.",
        "Register the intended owner USB from the main desktop app.",
    )
    add(
        "selected-key",
        "USB",
        "Selected master key available",
        key_ready,
        10,
        "The selected key can be loaded and is allowed by the current owner policy." if key_ready else "The selected key is missing, unreadable, or does not match the current owner policy.",
        "Reconnect the original USB and select its master key in the desktop app.",
    )
    add(
        "control-pin",
        "Local Control",
        "Separate Local Control PIN",
        control_pin_ready,
        5,
        "A Windows-protected scrypt verifier is configured for the same-PC control website." if control_pin_ready else "The same-PC Local Control website does not have its separate PIN configured.",
        "Open Local Control Center and set a separate 6-64 character control PIN.",
    )
    license_ready = locker.license_is_active(state)
    add(
        "license",
        "Account",
        "Licensed customer services",
        license_ready,
        10,
        str(details.get("license_status") or "License status is unavailable."),
        "Refresh or activate the license in Customer Center. Local unlock and recovery remain available.",
    )
    release_ready = bool(signed_release.get("ready"))
    add(
        "signed-release",
        "Updates",
        "Signed desktop release",
        release_ready,
        10,
        f"Signed release {signed_release.get('version')} passed server-side manifest and package checks." if release_ready else "No verified signed desktop release was returned by the service.",
        "Check the online Trust Center and use only owner-published signed packages.",
    )
    api_ready = bool(online.get("ok") and online_score.get("label") != "action")
    add(
        "api-trust",
        "Service",
        "Online trust posture",
        api_ready,
        10,
        f"Public API trust score: {online_score.get('value', 0)} of {online_score.get('maximum', 100)}." if online.get("ok") else "The public Trust Center could not be reached.",
        "Check the internet connection and public service status without changing local keys or locked data.",
    )
    auto_updates = bool(settings.get("auto_install_signed_updates"))
    add(
        "auto-updates",
        "Updates",
        "Verified automatic updates",
        auto_updates,
        5,
        "Automatic installation is enabled only for verified signed packages." if auto_updates else "Verified automatic installation is not enabled on this PC.",
        "Enable verified automatic updates in Update Center after reviewing the local policy.",
    )
    add(
        "recovery-test",
        "Recovery",
        "Recorded recovery self-test",
        bool(recovery_test),
        5,
        f"Latest successful disposable recovery test: {recovery_test}." if recovery_test else "No successful disposable recovery self-test is recorded in the current audit history.",
        "Run the key and PIN recovery test with disposable data from the main desktop app.",
    )
    add(
        "app-backup",
        "Recovery",
        "Recorded app-data backup",
        bool(backup_time),
        5,
        f"Latest successful app-data backup: {backup_time}." if backup_time else "No successful app-data backup is recorded in the current audit history.",
        "Export an app-data backup to protected removable storage and verify it before relying on it.",
    )

    score = sum(item["weight"] for item in checks if item["passed"])
    maximum = sum(item["weight"] for item in checks)
    label = "ready" if score >= 90 else "attention" if score >= 65 else "action"
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": "VaultLink Privacy-Safe Trust And Recovery Report",
        "generated_at_utc": locker.utc_now_text(),
        "desktop_version": locker.DESKTOP_APP_VERSION,
        "runtime": "owner_lab" if locker.LAB_MODE else "stable_app",
        "score": {
            "value": score,
            "maximum": maximum,
            "label": label,
            "passed": sum(item["passed"] for item in checks),
            "total": len(checks),
        },
        "checks": checks,
        "coarse_status": {
            "license": str(details.get("license_status") or "Unknown"),
            "plan": str(details.get("plan") or "Unknown"),
            "desktop": str(details.get("desktop") or locker.DESKTOP_APP_VERSION),
            "api": str(details.get("api") or "Not checked"),
            "service": str(details.get("service") or "Not checked"),
            "verified_auto_updates": str(details.get("automatic_updates") or "Unknown"),
        },
        "defender": {
            "available": bool(defender.get("available")),
            "protected_now": bool(defender.get("ProtectedNow")),
            "antivirus_enabled": bool(defender.get("AntivirusEnabled")),
            "real_time_protection_enabled": bool(defender.get("RealTimeProtectionEnabled")),
            "behavior_monitor_enabled": bool(defender.get("BehaviorMonitorEnabled")),
            "download_protection_enabled": bool(defender.get("IoavProtectionEnabled")),
            "signature_last_updated": str(defender.get("AntivirusSignatureLastUpdated") or ""),
            "quick_scan_age_days": defender.get("QuickScanAge"),
            "full_scan_age_days": defender.get("FullScanAge"),
        },
        "local_audit": {
            "valid": bool(audit_valid),
            "event_count": int(audit_count),
            "message": str(audit_message),
        },
        "online_trust": online if online.get("ok") else {"ok": False, "message": "Public Trust Center unavailable."},
        "privacy_notice": (
            "This report excludes license keys, license ids, activation receipts, customer identity, machine identity, "
            "USB paths, USB key bytes, PINs, passwords, vault contents, file names, full paths, and file contents."
        ),
        "limitations": [
            "This report is operational guidance, not an antivirus scan, security certification, HIPAA certification, legal opinion, or guarantee.",
            "A passing local check cannot prove that every backup is current or that every future recovery attempt will succeed.",
            "Microsoft Defender remains the malware scanner; VaultLink only reports the coarse status Defender provides.",
        ],
    }


def collect_trust_report():
    settings = locker.load_settings()
    state = locker.load_license_state(settings)
    defender = locker.get_defender_status_report()
    audit_verification = locker.verify_audit_logs()
    audit_records = locker.load_all_audit_records()
    online = None
    try:
        server = locker.validated_license_server_url(state.get("server_url"))
        online = locker.license_api_get_json(server, TRUST_ENDPOINT)
    except Exception:
        online = {"ok": False, "message": "Public Trust Center unavailable."}
    return build_local_trust_report(
        settings,
        state,
        defender,
        audit_verification,
        audit_records,
        online,
    )


def safe_report_text(report):
    lines = [
        f"LOCAL TRUST SCORE  {report['score']['value']} / {report['score']['maximum']}  {report['score']['label'].upper()}",
        f"DESKTOP            {report['desktop_version']}  {report['runtime'].replace('_', ' ').upper()}",
        f"GENERATED          {report['generated_at_utc']}",
        "",
        "LOCAL CHECKS",
        "------------",
    ]
    for item in report.get("checks", []):
        lines.extend(
            [
                f"[{item['state'].upper():9}] {item['title']} ({item['weight']} points)",
                f"  {item['detail']}",
                *( [] if item["passed"] else [f"  NEXT: {item['action']}"] ),
                "",
            ]
        )
    online = report.get("online_trust") or {}
    if online.get("ok"):
        score = online.get("score") or {}
        lines.extend(
            [
                "ONLINE TRUST",
                "------------",
                f"Public score: {score.get('value', 0)} / {score.get('maximum', 100)}  {str(score.get('label', 'unknown')).upper()}",
                f"Service: {(online.get('service_status') or {}).get('mode', 'unknown')}",
                f"Signed desktop: {(online.get('signed_release') or {}).get('version') or 'Not published'}",
                "",
            ]
        )
    lines.extend(["PRIVACY", "-------", report["privacy_notice"], "", "LIMITATIONS", "-----------"])
    lines.extend(f"- {item}" for item in report.get("limitations", []))
    return "\n".join(lines)


class TrustRecoveryCenter(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VaultLink Trust & Recovery Center")
        self.geometry("940x720")
        self.minsize(760, 590)
        self.configure(bg=locker.BG)
        self.report = None
        self.results = queue.Queue()
        self.busy = False
        self.status_var = tk.StringVar(value="Ready to build a privacy-safe local and online trust report.")
        self.metric_vars = {
            "score": tk.StringVar(value="-- / 100"),
            "checks": tk.StringVar(value="-- / --"),
            "defender": tk.StringVar(value="Not checked"),
            "audit": tk.StringVar(value="Not checked"),
            "release": tk.StringVar(value="Not checked"),
        }
        self.refresh_button = None
        self.export_button = None
        self.output = None
        self.build_ui()
        locker.log_event("trust_center_open", "local", "ok")
        self.after(150, self.refresh)

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=22)
        tk.Label(outer, text="Trust & Recovery Center", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 24, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="DEFENDER STATUS | AUDIT INTEGRITY | USB READINESS | SIGNED RELEASE | PUBLIC TRUST",
            bg=locker.BG,
            fg=locker.GREEN,
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w", pady=(3, 13))

        toolbar = tk.Frame(outer, bg=locker.BG)
        toolbar.pack(fill="x", pady=(0, 12))
        self.refresh_button = tk.Button(toolbar, text="REFRESH REPORT", command=self.refresh, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold"))
        self.refresh_button.pack(side="left", ipadx=10, ipady=7)
        self.export_button = tk.Button(toolbar, text="EXPORT SAFE JSON", command=self.export_report, state="disabled", bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.export_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=7)
        tk.Button(toolbar, text="ONLINE TRUST", command=lambda: self.open_server_page("/trust"), bg=locker.BLUE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(8, 0), ipadx=9, ipady=7)
        tk.Button(toolbar, text="RECOVERY READINESS", command=lambda: self.open_server_page("/readiness"), bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(8, 0), ipadx=9, ipady=7)
        tk.Button(toolbar, text="CUSTOMER WORKSPACE", command=lambda: locker.launch_companion_script("customer_hub.py"), bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(8, 0), ipadx=9, ipady=7)

        metrics = tk.Frame(outer, bg=locker.PANEL, highlightbackground="#343b49", highlightthickness=1)
        metrics.pack(fill="x")
        metric_rows = [
            ("LOCAL SCORE", "score"),
            ("CHECKS PASSED", "checks"),
            ("DEFENDER", "defender"),
            ("AUDIT CHAIN", "audit"),
            ("SIGNED RELEASE", "release"),
        ]
        for column, (label, key) in enumerate(metric_rows):
            metrics.grid_columnconfigure(column, weight=1, uniform="metric")
            item = tk.Frame(metrics, bg=locker.PANEL, padx=13, pady=11)
            item.grid(row=0, column=column, sticky="nsew")
            tk.Label(item, text=label, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 7, "bold")).pack(anchor="w")
            tk.Label(item, textvariable=self.metric_vars[key], bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 11, "bold"), wraplength=150, justify="left").pack(anchor="w", pady=(4, 0))

        tk.Label(outer, textvariable=self.status_var, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9), wraplength=850, justify="left").pack(anchor="w", pady=(10, 8))
        text_frame = tk.Frame(outer, bg=locker.FIELD)
        text_frame.pack(fill="both", expand=True)
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side="right", fill="y")
        self.output = tk.Text(text_frame, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", wrap="word", font=("Consolas", 10), padx=16, pady=14, yscrollcommand=scrollbar.set)
        self.output.pack(fill="both", expand=True)
        scrollbar.configure(command=self.output.yview)
        self.output.insert("1.0", "No report loaded yet.")
        self.output.configure(state="disabled")

    def set_busy(self, value, message=""):
        self.busy = bool(value)
        self.refresh_button.configure(state="disabled" if self.busy else "normal")
        self.export_button.configure(state="normal" if self.report and not self.busy else "disabled")
        if message:
            self.status_var.set(message)

    def refresh(self):
        if self.busy:
            return
        self.set_busy(True, "Checking Defender, audit integrity, USB readiness, signed release, and public trust...")

        def worker():
            try:
                self.results.put((True, collect_trust_report()))
            except Exception:
                self.results.put((False, "The trust report could not be built."))

        threading.Thread(target=worker, name="VaultLinkTrustReport", daemon=True).start()
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
            messagebox.showerror("Trust report failed", str(payload), parent=self)
            locker.log_event("trust_center_refresh", "local", "failed")
            return
        self.report = payload
        score = payload["score"]
        self.metric_vars["score"].set(f"{score['value']} / {score['maximum']} {score['label'].upper()}")
        self.metric_vars["checks"].set(f"{score['passed']} / {score['total']}")
        self.metric_vars["defender"].set("Protected" if payload["defender"]["protected_now"] else "Needs attention")
        self.metric_vars["audit"].set("Valid" if payload["local_audit"]["valid"] else "Review required")
        signed = (payload.get("online_trust") or {}).get("signed_release") or {}
        self.metric_vars["release"].set(str(signed.get("version") or "Unavailable"))
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", safe_report_text(payload))
        self.output.configure(state="disabled")
        self.set_busy(False, f"Privacy-safe report refreshed at {payload['generated_at_utc']}.")
        locker.log_event("trust_center_refresh", "local", "ok")

    def open_server_page(self, path):
        try:
            settings = locker.load_settings()
            state = locker.load_license_state(settings)
            server = locker.validated_license_server_url(state.get("server_url"))
            webbrowser.open(server + path, new=2)
        except Exception as exc:
            messagebox.showerror("Could not open page", str(exc), parent=self)

    def export_report(self):
        if not self.report:
            return
        destination = filedialog.asksaveasfilename(
            parent=self,
            title="Export privacy-safe trust report",
            initialfile="vaultlink-trust-recovery-report.json",
            defaultextension=".json",
            filetypes=[("JSON report", "*.json"), ("All files", "*.*")],
        )
        if not destination:
            return
        try:
            Path(destination).write_text(json.dumps(self.report, indent=2, ensure_ascii=True), encoding="utf-8")
            self.status_var.set("Privacy-safe trust report exported.")
            locker.log_event("trust_center_export", "report", "ok")
        except Exception as exc:
            locker.log_event("trust_center_export", "report", "failed")
            messagebox.showerror("Export failed", str(exc), parent=self)


if __name__ == "__main__":
    TrustRecoveryCenter().mainloop()
