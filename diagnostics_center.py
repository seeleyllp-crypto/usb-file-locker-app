import json
import os
import queue
import shutil
import sys
import threading
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import cryptography

import trust_recovery_center as trust
import usb_file_locker as locker


REPORT_SCHEMA_VERSION = 1
DIAGNOSTICS_ENDPOINT = "/api/v1/diagnostics-guide"
REQUIRED_RUNTIME_FILES = (
    "Ensure Dependencies.cmd",
    "usb_file_locker.py",
    "trust_recovery_center.py",
    "diagnostics_center.py",
)


def app_data_access_ready():
    try:
        return locker.APP_DIR.is_dir() and os.access(locker.APP_DIR, os.R_OK | os.W_OK)
    except Exception:
        return False


def runtime_snapshot(settings_readable=True):
    available = sum((locker.SOURCE_DIR / name).is_file() for name in REQUIRED_RUNTIME_FILES)
    try:
        free_bytes = int(shutil.disk_usage(locker.APP_DIR).free)
    except Exception:
        free_bytes = 0
    return {
        "python_version": ".".join(str(value) for value in sys.version_info[:3]),
        "python_supported": sys.version_info >= (3, 9),
        "cryptography_version": str(getattr(cryptography, "__version__", "unknown")),
        "cryptography_ready": bool(getattr(cryptography, "__version__", "")),
        "required_app_files": len(REQUIRED_RUNTIME_FILES),
        "available_app_files": available,
        "package_ready": available == len(REQUIRED_RUNTIME_FILES),
        "app_data_writable": app_data_access_ready(),
        "free_disk_bytes": free_bytes,
        "settings_readable": bool(settings_readable),
    }


def safe_diagnostics_guide(payload):
    source = payload if isinstance(payload, dict) else {}
    if not source.get("ok"):
        return {"ok": False, "message": "Online diagnostics guide unavailable."}
    service = source.get("service_status") if isinstance(source.get("service_status"), dict) else {}
    release = source.get("signed_release") if isinstance(source.get("signed_release"), dict) else {}

    def clean(value, fallback="", limit=240):
        return trust.safe_online_text(value, fallback, limit)

    def bounded_int(value, fallback=1, low=1, high=10):
        try:
            return min(high, max(low, int(value)))
        except (TypeError, ValueError):
            return fallback

    categories = []
    raw_categories = source.get("categories")
    if isinstance(raw_categories, (list, tuple)):
        for category in raw_categories[:12]:
            if not isinstance(category, dict):
                continue
            steps = []
            raw_steps = category.get("steps")
            if isinstance(raw_steps, (list, tuple)):
                for step in raw_steps[:10]:
                    if not isinstance(step, dict):
                        continue
                    steps.append(
                        {
                            "id": clean(step.get("id"), "step", 80),
                            "title": clean(step.get("title"), "Troubleshooting step", 160),
                            "action": clean(step.get("action"), "Review this check in the desktop app."),
                            "expected": clean(step.get("expected"), "Record whether the check passed."),
                        }
                    )
            categories.append(
                {
                    "id": clean(category.get("id"), "other", 80),
                    "title": clean(category.get("title"), "Other problem", 120),
                    "summary": clean(category.get("summary"), "Use the fixed troubleshooting steps."),
                    "steps": steps,
                    "escalation": clean(category.get("escalation"), "Send only a privacy-safe report after reviewing it."),
                }
            )

    def clean_list(values, limit=20):
        if not isinstance(values, (list, tuple)):
            return []
        result = []
        for value in values[:limit]:
            cleaned = clean(value)
            if cleaned:
                result.append(cleaned)
        return result

    return {
        "ok": True,
        "diagnostics_schema_version": bounded_int(source.get("diagnostics_schema_version")),
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
            "published_at_utc": clean(release.get("published_at_utc"), "", 40),
        },
        "categories": categories,
        "privacy_boundaries": clean_list(source.get("privacy_boundaries")),
        "limitations": clean_list(source.get("limitations")),
        "server_time_utc": clean(source.get("server_time_utc"), "", 40),
        "customer_records_included": False,
    }


def build_diagnostics_report(
    settings,
    state,
    defender,
    audit_verification,
    audit_records,
    online_guide,
    runtime,
    now_utc=None,
):
    settings = dict(settings or {})
    state = locker.normalize_license_state(state)
    defender = dict(defender or {})
    runtime = dict(runtime or {})
    guide = safe_diagnostics_guide(online_guide)
    now = now_utc or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)
    audit_valid, audit_count, _audit_message = audit_verification
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
                "detail": str(detail),
                "action": str(action),
            }
        )

    add(
        "python-runtime",
        "Runtime",
        "Supported Python runtime",
        runtime.get("python_supported"),
        5,
        f"Python {runtime.get('python_version', 'unknown')} is available.",
        "Run Ensure Dependencies.cmd from the transparent app folder.",
    )
    add(
        "cryptography-package",
        "Runtime",
        "Encryption dependency",
        runtime.get("cryptography_ready"),
        5,
        f"cryptography {runtime.get('cryptography_version', 'unknown')} imported successfully.",
        "Run Ensure Dependencies.cmd while connected to the internet, then reopen the app.",
    )
    present = int(runtime.get("available_app_files", 0) or 0)
    required = int(runtime.get("required_app_files", len(REQUIRED_RUNTIME_FILES)) or len(REQUIRED_RUNTIME_FILES))
    add(
        "package-files",
        "Runtime",
        "Required app files",
        runtime.get("package_ready"),
        5,
        f"{present} of {required} required transparent app files are available.",
        "Reinstall the complete signed app folder instead of copying one Python file by itself.",
    )
    add(
        "app-data-access",
        "Storage",
        "App-data read and write access",
        runtime.get("app_data_writable"),
        6,
        "Windows reports read and write access for the current user's app-data folder." if runtime.get("app_data_writable") else "Read and write access to app data could not be confirmed.",
        "Check the Windows user permissions for the VaultLink app-data folder without deleting keys or locked data.",
    )
    free_bytes = max(0, int(runtime.get("free_disk_bytes", 0) or 0))
    free_gb = round(free_bytes / (1024 ** 3), 1)
    add(
        "free-space",
        "Storage",
        "Working disk space",
        free_bytes >= 500 * 1024 * 1024,
        4,
        f"About {free_gb} GB is available on the app-data drive.",
        "Free at least 500 MB before creating updates, backups, or temporary recovery copies.",
    )
    add(
        "settings-read",
        "Storage",
        "Settings readable",
        runtime.get("settings_readable"),
        5,
        "Windows-protected settings loaded without exposing their values." if runtime.get("settings_readable") else "Settings could not be loaded safely.",
        "Keep the existing app-data folder, close duplicate app windows, and retry before restoring a known backup.",
    )
    add(
        "audit-chain",
        "Audit",
        "Local audit integrity",
        audit_valid,
        10,
        f"{int(audit_count)} privacy-safe event(s) were checked." if audit_valid else f"Audit verification needs review after {int(audit_count)} event(s).",
        "Preserve the audit folder and export a safe copy before investigating the first failed event.",
    )
    defender_ready = bool(defender.get("available") and defender.get("ProtectedNow"))
    add(
        "defender-protection",
        "Windows",
        "Microsoft Defender protection",
        defender_ready,
        12,
        "Antivirus, real-time, behavior, and downloaded-file protection are enabled." if defender_ready else "Defender protection could not be confirmed as fully enabled.",
        "Open Windows Security, enable protection, update signatures, and run a current scan.",
    )
    signature_time = locker.parse_utc_text(defender.get("AntivirusSignatureLastUpdated"))
    signature_age_seconds = (now - signature_time).total_seconds() if signature_time else None
    signatures_fresh = signature_age_seconds is not None and -86400 <= signature_age_seconds <= 3 * 86400
    signature_age_days = round(max(0, signature_age_seconds or 0) / 86400, 1) if signature_time else None
    add(
        "defender-signatures",
        "Windows",
        "Defender signatures current",
        signatures_fresh,
        4,
        f"Defender signatures are about {signature_age_days} day(s) old." if signature_age_days is not None else "Defender signature age is unavailable.",
        "Use Windows Security to check for protection updates before scanning.",
    )
    try:
        owner_policy_ready = bool(locker.load_owner_policy(settings))
    except Exception:
        owner_policy_ready = False
    add(
        "owner-usb-policy",
        "USB",
        "Owner USB policy",
        owner_policy_ready,
        5,
        "A Windows-protected owner USB policy is configured." if owner_policy_ready else "No readable owner USB policy is configured.",
        "Register the intended removable owner USB from the main desktop app.",
    )
    key_ready = trust.selected_key_ready(settings)
    add(
        "selected-key",
        "USB",
        "Selected USB key available",
        key_ready,
        7,
        "The selected key is readable and allowed by the owner policy." if key_ready else "The selected key is absent, unreadable, or does not match the owner policy.",
        "Reconnect the original USB and load its existing master key. Do not create a replacement for old locked files.",
    )
    control_pin_ready = trust.local_control_pin_ready(settings)
    add(
        "local-control-pin",
        "USB",
        "Separate Local Control PIN",
        control_pin_ready,
        4,
        "A Windows-protected scrypt verifier is configured." if control_pin_ready else "The same-PC controller does not have its separate PIN configured.",
        "Set a separate 6-64 character PIN in Local Control Center.",
    )
    license_ready = locker.license_is_active(state)
    add(
        "license-state",
        "Account",
        "Customer service license",
        license_ready,
        6,
        f"License state is {str(state.get('status', 'unlicensed')).replace('_', ' ')}.",
        "Open License Center and refresh the saved license. Local unlock and recovery remain available.",
    )
    guide_ready = bool(guide.get("ok"))
    add(
        "diagnostics-api",
        "Service",
        "Online diagnostics guide",
        guide_ready,
        6,
        f"Public diagnostics API {guide.get('api_version', 'unknown')} responded." if guide_ready else "The public diagnostics guide could not be reached.",
        "Check the internet connection and public status page; do not change keys or delete locked files.",
    )
    server_time = locker.parse_utc_text(guide.get("server_time_utc")) if guide_ready else None
    clock_skew = abs((now - server_time).total_seconds()) if server_time else None
    clock_ready = clock_skew is not None and clock_skew <= 300
    add(
        "clock-sync",
        "Service",
        "System clock close to service time",
        clock_ready,
        4,
        f"System clock differs from service time by about {round(clock_skew)} second(s)." if clock_skew is not None else "Service time comparison is unavailable.",
        "Turn on automatic date, time, and time-zone settings in Windows, then retry licensing and updates.",
    )
    signed_release = guide.get("signed_release") if isinstance(guide.get("signed_release"), dict) else {}
    release_ready = bool(signed_release.get("ready"))
    add(
        "signed-release",
        "Updates",
        "Signed desktop release available",
        release_ready,
        6,
        f"Signed release {signed_release.get('version')} is available." if release_ready else "No verified signed desktop release was returned.",
        "Use Update Center and install only a package whose Ed25519 signature and SHA-256 digest verify.",
    )
    recovery_time = trust.latest_success_time(audit_records, "recovery_self_test")
    add(
        "recovery-test",
        "Recovery",
        "Disposable recovery test recorded",
        bool(recovery_time),
        3,
        f"Latest successful recovery test: {recovery_time}." if recovery_time else "No successful disposable recovery test is recorded.",
        "Run the key and PIN recovery test with disposable data before relying on the workflow.",
    )
    backup_time = trust.latest_success_time(audit_records, "backup_app_data")
    add(
        "app-data-backup",
        "Recovery",
        "App-data backup recorded",
        bool(backup_time),
        3,
        f"Latest successful app-data backup: {backup_time}." if backup_time else "No successful app-data backup is recorded.",
        "Create and verify an app-data backup on protected removable storage.",
    )

    score = sum(item["weight"] for item in checks if item["passed"])
    maximum = sum(item["weight"] for item in checks)
    category_summary = []
    for category in sorted({item["category"] for item in checks}):
        rows = [item for item in checks if item["category"] == category]
        category_summary.append(
            {
                "category": category,
                "passed": sum(item["passed"] for item in rows),
                "total": len(rows),
                "attention": sum(not item["passed"] for item in rows),
            }
        )
    label = "ready" if score >= 90 else "attention" if score >= 65 else "action"
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": "VaultLink Privacy-Safe Diagnostics Report",
        "generated_at_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "desktop_version": locker.DESKTOP_APP_VERSION,
        "runtime": "owner_lab" if locker.LAB_MODE else "stable_app",
        "score": {
            "value": score,
            "maximum": maximum,
            "label": label,
            "passed": sum(item["passed"] for item in checks),
            "total": len(checks),
            "attention": sum(not item["passed"] for item in checks),
        },
        "checks": checks,
        "category_summary": category_summary,
        "environment": {
            "python_version": str(runtime.get("python_version", "unknown")),
            "cryptography_version": str(runtime.get("cryptography_version", "unknown")),
            "required_app_files": required,
            "available_app_files": present,
            "app_data_writable": bool(runtime.get("app_data_writable")),
            "free_disk_gb": free_gb,
            "diagnostics_api_version": str(guide.get("api_version", "unavailable")),
        },
        "defender": {
            "available": bool(defender.get("available")),
            "protected_now": bool(defender.get("ProtectedNow")),
            "antivirus_enabled": bool(defender.get("AntivirusEnabled")),
            "real_time_protection_enabled": bool(defender.get("RealTimeProtectionEnabled")),
            "behavior_monitor_enabled": bool(defender.get("BehaviorMonitorEnabled")),
            "download_protection_enabled": bool(defender.get("IoavProtectionEnabled")),
            "signatures_fresh": bool(signatures_fresh),
            "signature_age_days": signature_age_days,
        },
        "online_guide": guide if guide_ready else {"ok": False, "message": "Online diagnostics guide unavailable."},
        "privacy_notice": (
            "This report excludes license keys, license ids, activation receipts, customer identity, machine identity, "
            "USB paths, USB key bytes, PINs, passwords, filenames, full paths, vault data, and file contents."
        ),
        "limitations": [
            "Diagnostics are read-only guidance, not an antivirus scan, certification, legal opinion, or guarantee.",
            "A passing check cannot prove every backup, key copy, or future recovery attempt will succeed.",
            "Microsoft Defender remains the malware scanner; VaultLink reports only coarse Defender status.",
        ],
    }


def collect_diagnostics_report():
    settings_readable = True
    try:
        settings = locker.load_settings()
    except Exception:
        settings = {}
        settings_readable = False
    try:
        state = locker.load_license_state(settings)
    except Exception:
        state = locker.normalize_license_state({})
    defender = locker.get_defender_status_report()
    try:
        audit_verification = locker.verify_audit_logs()
    except Exception:
        audit_verification = (False, 0, "Audit verification unavailable.")
    try:
        audit_records = locker.load_all_audit_records()
    except Exception:
        audit_records = []
    runtime = runtime_snapshot(settings_readable)
    guide = {"ok": False, "message": "Online diagnostics guide unavailable."}
    try:
        server = locker.validated_license_server_url(state.get("server_url"))
        guide = locker.license_api_get_json(server, DIAGNOSTICS_ENDPOINT)
    except Exception:
        pass
    return build_diagnostics_report(
        settings,
        state,
        defender,
        audit_verification,
        audit_records,
        guide,
        runtime,
    )


def safe_diagnostics_text(report, view="ALL"):
    selected = str(view or "ALL").strip().upper()
    checks = list(report.get("checks") or [])
    if selected == "ATTENTION":
        checks = [item for item in checks if not item.get("passed")]
    elif selected != "ALL":
        checks = [item for item in checks if str(item.get("category", "")).upper() == selected]
    lines = [
        f"DIAGNOSTIC SCORE  {report['score']['value']} / {report['score']['maximum']}  {report['score']['label'].upper()}",
        f"CHECKS            {report['score']['passed']} / {report['score']['total']} PASSED",
        f"DESKTOP           {report['desktop_version']}  {report['runtime'].replace('_', ' ').upper()}",
        f"GENERATED         {report['generated_at_utc']}",
        f"VIEW              {selected}",
        "",
        "CHECKS",
        "------",
    ]
    if not checks:
        lines.extend(["No checks match this view.", ""])
    for item in checks:
        lines.extend(
            [
                f"[{item['state'].upper():9}] {item['category']} | {item['title']} ({item['weight']} points)",
                f"  {item['detail']}",
                *([] if item["passed"] else [f"  NEXT: {item['action']}"]),
                "",
            ]
        )
    lines.extend(["PRIVACY", "-------", report["privacy_notice"], "", "LIMITATIONS", "-----------"])
    lines.extend(f"- {item}" for item in report.get("limitations", []))
    return "\n".join(lines)


def safe_summary_text(report):
    attention = [item for item in report.get("checks", []) if not item.get("passed")]
    lines = [
        f"VaultLink diagnostics: {report['score']['value']}/{report['score']['maximum']} {report['score']['label'].upper()}",
        f"Checks: {report['score']['passed']}/{report['score']['total']} passed",
        f"Desktop: {report['desktop_version']}",
    ]
    lines.extend(f"Attention: {item['title']} - {item['action']}" for item in attention[:8])
    lines.append(report["privacy_notice"])
    return "\n".join(lines)


class DiagnosticsCenter(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VaultLink Diagnostics Center")
        self.geometry("1020x780")
        self.minsize(800, 620)
        self.configure(bg=locker.BG)
        self.report = None
        self.results = queue.Queue()
        self.busy = False
        self.status_var = tk.StringVar(value="Ready to run privacy-safe read-only diagnostics.")
        self.view_var = tk.StringVar(value="ALL")
        self.metric_vars = {
            "score": tk.StringVar(value="-- / 100"),
            "checks": tk.StringVar(value="-- / 18"),
            "attention": tk.StringVar(value="--"),
            "defender": tk.StringVar(value="Not checked"),
            "api": tk.StringVar(value="Not checked"),
        }
        self.refresh_button = None
        self.export_button = None
        self.copy_button = None
        self.output = None
        self.build_ui()
        locker.log_event("diagnostics_center_open", "local", "ok")
        self.after(150, self.refresh)

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=22)
        tk.Label(outer, text="Diagnostics Center", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 24, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="RUNTIME | STORAGE | DEFENDER | AUDIT | USB | LICENSE | SERVICE | UPDATES | RECOVERY",
            bg=locker.BG,
            fg=locker.GREEN,
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w", pady=(3, 13))

        primary = tk.Frame(outer, bg=locker.BG)
        primary.pack(fill="x", pady=(0, 8))
        self.refresh_button = tk.Button(primary, text="RUN 18 CHECKS", command=self.refresh, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold"))
        self.refresh_button.pack(side="left", ipadx=10, ipady=7)
        self.export_button = tk.Button(primary, text="EXPORT SAFE JSON", command=self.export_report, state="disabled", bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.export_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=7)
        self.copy_button = tk.Button(primary, text="COPY SAFE SUMMARY", command=self.copy_summary, state="disabled", bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.copy_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=7)

        links = tk.Frame(outer, bg=locker.BG)
        links.pack(fill="x", pady=(0, 12))
        tk.Button(links, text="ONLINE DIAGNOSTICS", command=lambda: self.open_server_page("/diagnostics"), bg=locker.BLUE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", ipadx=8, ipady=6)
        tk.Button(links, text="TRUST CENTER", command=lambda: self.open_server_page("/trust"), bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(8, 0), ipadx=8, ipady=6)
        tk.Button(links, text="CUSTOMER WORKSPACE", command=lambda: locker.launch_companion_script("customer_hub.py"), bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(8, 0), ipadx=8, ipady=6)
        tk.Label(links, text="VIEW", bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(side="right", padx=(10, 6))
        view = ttk.Combobox(
            links,
            textvariable=self.view_var,
            state="readonly",
            width=15,
            values=("ALL", "ATTENTION", "RUNTIME", "STORAGE", "WINDOWS", "AUDIT", "USB", "ACCOUNT", "SERVICE", "UPDATES", "RECOVERY"),
        )
        view.pack(side="right")
        view.bind("<<ComboboxSelected>>", lambda _event: self.render_report())

        metrics = tk.Frame(outer, bg=locker.PANEL, highlightbackground="#343b49", highlightthickness=1)
        metrics.pack(fill="x")
        for column, (label, key) in enumerate(
            (("SCORE", "score"), ("PASSED", "checks"), ("ATTENTION", "attention"), ("DEFENDER", "defender"), ("API GUIDE", "api"))
        ):
            metrics.grid_columnconfigure(column, weight=1, uniform="metric")
            item = tk.Frame(metrics, bg=locker.PANEL, padx=13, pady=11)
            item.grid(row=0, column=column, sticky="nsew")
            tk.Label(item, text=label, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 7, "bold")).pack(anchor="w")
            tk.Label(item, textvariable=self.metric_vars[key], bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 11, "bold"), wraplength=160, justify="left").pack(anchor="w", pady=(4, 0))

        tk.Label(outer, textvariable=self.status_var, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9), wraplength=920, justify="left").pack(anchor="w", pady=(10, 8))
        text_frame = tk.Frame(outer, bg=locker.FIELD)
        text_frame.pack(fill="both", expand=True)
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side="right", fill="y")
        self.output = tk.Text(text_frame, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", wrap="word", font=("Consolas", 10), padx=16, pady=14, yscrollcommand=scrollbar.set)
        self.output.pack(fill="both", expand=True)
        scrollbar.configure(command=self.output.yview)
        self.output.insert("1.0", "No diagnostic report loaded yet.")
        self.output.configure(state="disabled")

    def set_busy(self, value, message=""):
        self.busy = bool(value)
        self.refresh_button.configure(state="disabled" if self.busy else "normal")
        ready_state = "normal" if self.report and not self.busy else "disabled"
        self.export_button.configure(state=ready_state)
        self.copy_button.configure(state=ready_state)
        if message:
            self.status_var.set(message)

    def refresh(self):
        if self.busy:
            return
        self.set_busy(True, "Running read-only runtime, storage, Windows, USB, account, update, and recovery checks...")

        def worker():
            try:
                self.results.put((True, collect_diagnostics_report()))
            except Exception:
                self.results.put((False, "Diagnostics could not complete safely."))

        threading.Thread(target=worker, name="VaultLinkDiagnostics", daemon=True).start()
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
            locker.log_event("diagnostics_center_run", "local", "failed")
            messagebox.showerror("Diagnostics failed", str(payload), parent=self)
            return
        self.report = payload
        score = payload["score"]
        self.metric_vars["score"].set(f"{score['value']} / {score['maximum']} {score['label'].upper()}")
        self.metric_vars["checks"].set(f"{score['passed']} / {score['total']}")
        self.metric_vars["attention"].set(str(score["attention"]))
        self.metric_vars["defender"].set("Protected" if payload["defender"]["protected_now"] else "Review")
        online = payload.get("online_guide") or {}
        self.metric_vars["api"].set(str(online.get("api_version") or "Unavailable"))
        self.render_report()
        self.set_busy(False, f"Privacy-safe diagnostics completed at {payload['generated_at_utc']}.")
        locker.log_event("diagnostics_center_run", "local", "ok")

    def render_report(self):
        if not self.report:
            return
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", safe_diagnostics_text(self.report, self.view_var.get()))
        self.output.configure(state="disabled")

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
        self.clipboard_append(safe_summary_text(self.report))
        self.update()
        self.status_var.set("Privacy-safe diagnostic summary copied.")
        locker.log_event("diagnostics_center_copy", "report", "ok")

    def export_report(self):
        if not self.report:
            return
        destination = filedialog.asksaveasfilename(
            parent=self,
            title="Export privacy-safe diagnostics",
            initialfile="vaultlink-diagnostics-report.json",
            defaultextension=".json",
            filetypes=[("JSON report", "*.json"), ("All files", "*.*")],
        )
        if not destination:
            return
        try:
            Path(destination).write_text(json.dumps(self.report, indent=2, ensure_ascii=True), encoding="utf-8")
            self.status_var.set("Privacy-safe diagnostic report exported.")
            locker.log_event("diagnostics_center_export", "report", "ok")
        except Exception as exc:
            locker.log_event("diagnostics_center_export", "report", "failed")
            messagebox.showerror("Export failed", str(exc), parent=self)


if __name__ == "__main__":
    DiagnosticsCenter().mainloop()
