import base64
import hashlib
import hmac
import html
import json
import secrets
import sys
import threading
import time
import urllib.parse
import webbrowser
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

import usb_file_locker as locker


LOCAL_HOST = "127.0.0.1"
SESSION_SECONDS = 15 * 60
MAX_FORM_BYTES = 4096
PIN_SETTING = "local_control_pin_verifier"
PIN_ENTROPY = b"VaultLinkLocalControlPinV1"
PIN_SCRYPT_N = 2**14
PIN_SCRYPT_R = 8
PIN_SCRYPT_P = 1

CONTROL_ACTIONS = {
    "main_locker": {
        "label": "Main Locker",
        "script": None,
        "category": "Core",
        "summary": "Open the main file and folder locking workspace.",
    },
    "customer_workspace": {
        "label": "Customer Workspace",
        "script": "customer_hub.py",
        "category": "Core",
        "summary": "Review privacy-safe account, update, and recovery guidance.",
    },
    "trust_recovery": {
        "label": "Trust & Recovery Center",
        "script": "trust_recovery_center.py",
        "category": "Core",
        "summary": "Review Defender, audit, USB, signed-update, and public trust posture locally.",
    },
    "diagnostics": {
        "label": "Diagnostics Center",
        "script": "diagnostics_center.py",
        "category": "Core",
        "summary": "Run read-only runtime, storage, Defender, USB, service, update, and recovery checks.",
    },
    "incident_response": {
        "label": "Incident Response Center",
        "script": "incident_response_center.py",
        "category": "Core",
        "summary": "Use fixed response playbooks, local readiness checks, Windows Security, and reviewed safe exports.",
    },
    "recovery_drills": {
        "label": "Recovery Drill Center",
        "script": "recovery_drill_center.py",
        "category": "Core",
        "summary": "Practice fixed recovery exercises, score local readiness, schedule reviews, and keep safe hash-chained results.",
    },
    "backup_verification": {
        "label": "Backup Verification Center",
        "script": "backup_verification_center.py",
        "category": "Recovery",
        "summary": "Verify recognized app-data backups, compare coarse checkpoints, and follow a fixed restore order.",
    },
    "recovery_kit": {
        "label": "Recovery Kit Builder",
        "script": "recovery_kit_builder.py",
        "category": "Recovery",
        "summary": "Build a fixed emergency card, first-hour runbook, review reminder, and coarse local snapshots.",
    },
    "data_control": {
        "label": "Local Data Control Center",
        "script": "local_data_control_center.py",
        "category": "Privacy",
        "summary": "Review fourteen fixed data classes, eleven local controls, retention, and coarse hash-chained privacy receipts.",
    },
    "storage_retention": {
        "label": "Storage & Retention Center",
        "script": "storage_retention_center.py",
        "category": "Privacy",
        "summary": "Review fixed storage boundaries and clean only expired VaultLink temporary copies after a bounded preview and typed confirmation.",
    },
    "security_maintenance": {
        "label": "Security Maintenance Center",
        "script": "security_maintenance_center.py",
        "category": "Core",
        "summary": "Track fixed defensive tasks, planning windows, schedule coverage, priority queues, snapshots, and privacy-safe hash-chained local history.",
    },
    "vault_health": {
        "label": "Vault Health Center",
        "script": "vault_health_center.py",
        "category": "Recovery",
        "summary": "Run read-only locked-file and recovery-readiness checks.",
    },
    "locked_browser": {
        "label": "Locked File Browser",
        "script": "locked_file_browser.py",
        "category": "Recovery",
        "summary": "Find locked files without sending their names or paths online.",
    },
    "key_inspector": {
        "label": "Key Inspector",
        "script": "key_inspector.py",
        "category": "Recovery",
        "summary": "Review the selected key and owner-USB readiness locally.",
    },
    "perm_unlock": {
        "label": "PERM Unlock Workbench",
        "script": "perm_unlock_workbench.py",
        "category": "Recovery",
        "summary": "Open the edit-and-relock workflow in its normal desktop window.",
    },
    "personal_vault": {
        "label": "Personal Vault Pad",
        "script": "personal_vault_pad.py",
        "category": "Private Work",
        "summary": "Open the local encrypted personal vault editor.",
    },
    "quick_note": {
        "label": "Quick Lock Note",
        "script": "quick_lock_note.py",
        "category": "Private Work",
        "summary": "Create a short locked note through the desktop app.",
    },
    "audit_log": {
        "label": "Audit Log Viewer",
        "script": "audit_log_viewer.py",
        "category": "Privacy",
        "summary": "Review privacy-safe, hash-chained local activity records.",
    },
    "privacy_hub": {
        "label": "Privacy Safety Hub",
        "script": "privacy_safety_hub.py",
        "category": "Privacy",
        "summary": "Open customer privacy and defensive safety controls.",
    },
    "text_logs": {
        "label": "Text Log Processor",
        "script": "text_log_processor.py",
        "category": "Privacy",
        "summary": "Process pasted text logs without automatic file collection.",
    },
    "breach_guard": {
        "label": "Global Breach Guard",
        "script": "global_breach_guard.py",
        "category": "Monitoring",
        "summary": "Open the local watcher for repeated privacy-safe risk events.",
    },
}


def validate_control_pin(pin):
    pin = str(pin or "")
    if not 6 <= len(pin) <= 64:
        raise ValueError("The local control PIN must be 6 to 64 characters.")
    if len(set(pin)) < 2:
        raise ValueError("Choose a less repetitive local control PIN.")
    return pin


def create_pin_record(pin, salt=None):
    pin = validate_control_pin(pin)
    salt = bytes(salt) if salt is not None else secrets.token_bytes(16)
    digest = hashlib.scrypt(
        pin.encode("utf-8"),
        salt=salt,
        n=PIN_SCRYPT_N,
        r=PIN_SCRYPT_R,
        p=PIN_SCRYPT_P,
        dklen=32,
    )
    return {
        "version": 1,
        "salt": base64.b64encode(salt).decode("ascii"),
        "digest": base64.b64encode(digest).decode("ascii"),
        "n": PIN_SCRYPT_N,
        "r": PIN_SCRYPT_R,
        "p": PIN_SCRYPT_P,
    }


def verify_pin_record(pin, record):
    try:
        if (
            record.get("version") != 1
            or int(record["n"]) != PIN_SCRYPT_N
            or int(record["r"]) != PIN_SCRYPT_R
            or int(record["p"]) != PIN_SCRYPT_P
        ):
            return False
        salt = base64.b64decode(str(record["salt"]).encode("ascii"), validate=True)
        expected = base64.b64decode(str(record["digest"]).encode("ascii"), validate=True)
        if len(salt) != 16 or len(expected) != 32:
            return False
        actual = hashlib.scrypt(
            str(pin or "").encode("utf-8"),
            salt=salt,
            n=int(record["n"]),
            r=int(record["r"]),
            p=int(record["p"]),
            dklen=len(expected),
        )
    except Exception:
        return False
    return hmac.compare_digest(actual, expected)


def seal_pin_record(record):
    plain = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    protected = locker.dpapi_protect(plain, PIN_ENTROPY)
    return base64.b64encode(protected).decode("ascii")


def unseal_pin_record(value):
    protected = base64.b64decode(str(value or "").encode("ascii"), validate=True)
    plain = locker.dpapi_unprotect(protected, PIN_ENTROPY)
    record = json.loads(plain.decode("utf-8"))
    if not isinstance(record, dict) or record.get("version") != 1:
        raise ValueError("The local control PIN verifier is not supported.")
    return record


def save_control_pin(pin):
    settings = locker.load_settings()
    settings[PIN_SETTING] = seal_pin_record(create_pin_record(pin))
    locker.save_settings(settings)


def control_pin_configured(settings=None):
    current = settings if isinstance(settings, dict) else locker.load_settings()
    try:
        unseal_pin_record(current.get(PIN_SETTING))
        return True
    except Exception:
        return False


def verify_selected_key(key_path, expected_key_id=""):
    key = locker.load_key_file(key_path)
    if expected_key_id and not hmac.compare_digest(str(key.get("key_id", "")), str(expected_key_id)):
        raise ValueError("The selected USB key changed after the local website started.")
    settings = locker.load_settings()
    policy = locker.load_owner_policy(settings)
    allowed, reason = locker.owner_key_allowed(key, policy)
    if not allowed:
        raise ValueError(reason)
    return key


def launch_control_action(action_id):
    action = CONTROL_ACTIONS.get(str(action_id or ""))
    if not action:
        raise ValueError("That local control action is not allowed.")
    script_name = action["script"]
    if script_name is None:
        locker.launch_main_app_process()
    else:
        locker.launch_companion_script(script_name)
    return action["label"]


def control_action_available(action):
    script_name = action.get("script")
    if script_name is None:
        return True
    if getattr(sys, "frozen", False):
        return (locker.RUNTIME_DIR / f"{Path(script_name).stem}.exe").is_file()
    return (locker.SOURCE_DIR / script_name).is_file()


def control_action_catalog():
    return [
        {
            "id": action_id,
            "label": action["label"],
            "category": action["category"],
            "summary": action["summary"],
            "available": control_action_available(action),
        }
        for action_id, action in CONTROL_ACTIONS.items()
    ]


def normalized_category_filter(value, apps=None):
    requested = " ".join(str(value or "").split())[:60]
    if not requested or requested.lower() == "all":
        return ""
    categories = {str(item.get("category", "")) for item in (apps or control_action_catalog())}
    for category in categories:
        if category.lower() == requested.lower():
            return category
    return ""


def safe_dashboard_text(value, fallback="Unknown"):
    text = " ".join(str(value or "").split())[:160]
    lowered = text.lower()
    if not text:
        return fallback
    if "\\" in text or ":/" in text or "vlk1." in lowered or "vlr1." in lowered:
        return "Hidden by the local control privacy rule"
    return text


def local_customer_status():
    settings = locker.load_settings()
    state = locker.load_license_state(settings)
    details = locker.customer_center_details(state, settings)
    return {
        "license": safe_dashboard_text(details.get("license_status"), "Unlicensed"),
        "plan": safe_dashboard_text(details.get("plan"), "No active plan"),
        "desktop": safe_dashboard_text(details.get("desktop"), locker.DESKTOP_APP_VERSION),
        "api": safe_dashboard_text(details.get("api")),
        "service": safe_dashboard_text(details.get("service")),
        "automatic_updates": safe_dashboard_text(details.get("automatic_updates")),
    }


class ControlState:
    def __init__(self, key_path, key_id):
        self.key_path = str(key_path)
        self.key_id = str(key_id)
        self.login_csrf = secrets.token_urlsafe(24)
        self.session_token = ""
        self.session_csrf = ""
        self.session_expires_at = 0.0
        self.failed_attempts = []
        self.lockout_until = 0.0
        self.started_at = time.monotonic()
        self.launch_history = []
        self.launch_counts = {
            action_id: {"success": 0, "failure": 0}
            for action_id in CONTROL_ACTIONS
        }
        self.lock = threading.RLock()

    def usb_status(self):
        try:
            verify_selected_key(self.key_path, self.key_id)
            return True, "USB key verified locally."
        except Exception:
            return False, "The selected USB key is missing or no longer matches."

    def authenticate(self, pin, login_csrf):
        now = time.monotonic()
        with self.lock:
            if not hmac.compare_digest(str(login_csrf or ""), self.login_csrf):
                return False, "The login page expired. Refresh and try again."
            self.failed_attempts = [stamp for stamp in self.failed_attempts if now - stamp < 300]
            if now < self.lockout_until:
                seconds = max(1, int(self.lockout_until - now))
                return False, f"Too many attempts. Wait {seconds} seconds."
            usb_ok, usb_message = self.usb_status()
            if not usb_ok:
                return False, usb_message
            try:
                record = unseal_pin_record(locker.load_settings().get(PIN_SETTING))
            except Exception:
                return False, "Configure the local control PIN in the desktop window first."
            if not verify_pin_record(pin, record):
                self.failed_attempts.append(now)
                if len(self.failed_attempts) >= 5:
                    self.lockout_until = now + 60
                    self.failed_attempts.clear()
                locker.log_event("local_control_login", "loopback", "failed")
                return False, "The local control PIN was not accepted."
            self.session_token = secrets.token_urlsafe(32)
            self.session_csrf = secrets.token_urlsafe(24)
            self.session_expires_at = now + SESSION_SECONDS
            self.login_csrf = secrets.token_urlsafe(24)
            self.failed_attempts.clear()
            self.lockout_until = 0.0
            locker.log_event("local_control_login", "loopback", "ok")
            return True, "Local control session unlocked."

    def is_authorized(self, token):
        with self.lock:
            if not self.session_token or time.monotonic() >= self.session_expires_at:
                self.lock_session()
                return False
            return hmac.compare_digest(str(token or ""), self.session_token)

    def run_action(self, token, csrf, action_id):
        with self.lock:
            if not self.is_authorized(token):
                raise PermissionError("The local control session expired.")
            if not hmac.compare_digest(str(csrf or ""), self.session_csrf):
                raise PermissionError("The local control request could not be verified.")
            usb_ok, usb_message = self.usb_status()
            if not usb_ok:
                raise PermissionError(usb_message)
            action_id = str(action_id or "")
            action = CONTROL_ACTIONS.get(action_id)
            if not action:
                raise ValueError("That local control action is not allowed.")
            try:
                label = launch_control_action(action_id)
            except Exception:
                self.record_launch(action_id, "failed")
                locker.log_event("local_control_launch", action_id, "failed")
                raise
            self.record_launch(action_id, "ok")
            self.session_expires_at = time.monotonic() + SESSION_SECONDS
            locker.log_event("local_control_launch", action_id, "ok")
            return label

    def record_launch(self, action_id, result):
        with self.lock:
            action = CONTROL_ACTIONS.get(str(action_id or ""))
            if not action:
                return
            self.launch_history.append(
                {
                    "at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "action_id": str(action_id),
                    "label": action["label"],
                    "result": "ok" if result == "ok" else "failed",
                }
            )
            counts = self.launch_counts.setdefault(str(action_id), {"success": 0, "failure": 0})
            counts["success" if result == "ok" else "failure"] += 1
            self.launch_history = self.launch_history[-20:]

    def extend_session(self, token, csrf):
        with self.lock:
            if not self.is_authorized(token):
                raise PermissionError("The local control session expired.")
            if not hmac.compare_digest(str(csrf or ""), self.session_csrf):
                raise PermissionError("The local control request could not be verified.")
            usb_ok, usb_message = self.usb_status()
            if not usb_ok:
                raise PermissionError(usb_message)
            self.session_expires_at = time.monotonic() + SESSION_SECONDS

    def clear_history(self, token, csrf):
        with self.lock:
            if not self.is_authorized(token):
                raise PermissionError("The local control session expired.")
            if not hmac.compare_digest(str(csrf or ""), self.session_csrf):
                raise PermissionError("The local control request could not be verified.")
            self.launch_history.clear()
            self.launch_counts = {
                action_id: {"success": 0, "failure": 0}
                for action_id in CONTROL_ACTIONS
            }

    def dashboard_snapshot(self):
        with self.lock:
            apps = []
            for item in control_action_catalog():
                counts = self.launch_counts.get(item["id"], {})
                apps.append(
                    {
                        **item,
                        "successful_launches": int(counts.get("success", 0) or 0),
                        "failed_launches": int(counts.get("failure", 0) or 0),
                    }
                )
            remaining = max(0, int(self.session_expires_at - time.monotonic()))
            successful = sum(item["successful_launches"] for item in apps)
            failed = sum(item["failed_launches"] for item in apps)
            category_counts = {}
            for item in apps:
                category_counts[item["category"]] = category_counts.get(item["category"], 0) + 1
            return {
                "version": locker.DESKTOP_APP_VERSION,
                "runtime": "Owner lab" if locker.LAB_MODE else "Stable app",
                "remaining_seconds": remaining,
                "remaining_minutes": (remaining + 59) // 60,
                "server_uptime_seconds": max(0, int(time.monotonic() - self.started_at)),
                "apps": apps,
                "available_apps": sum(bool(item["available"]) for item in apps),
                "category_counts": category_counts,
                "successful_launches": successful,
                "failed_launches": failed,
                "total_launches": successful + failed,
                "customer": local_customer_status(),
                "history": list(reversed(self.launch_history)),
                "history_limit": 20,
            }

    def safe_report(self, token, csrf):
        with self.lock:
            if not self.is_authorized(token):
                raise PermissionError("The local control session expired.")
            if not hmac.compare_digest(str(csrf or ""), self.session_csrf):
                raise PermissionError("The local control request could not be verified.")
            usb_ok, usb_message = self.usb_status()
            if not usb_ok:
                raise PermissionError(usb_message)
            snapshot = self.dashboard_snapshot()
            return {
                "schema_version": 1,
                "report_type": "VaultLink Local Control Privacy-Safe Report",
                "exported_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "version": snapshot["version"],
                "runtime": snapshot["runtime"],
                "session": {
                    "remaining_seconds": snapshot["remaining_seconds"],
                    "server_uptime_seconds": snapshot["server_uptime_seconds"],
                    "usb_verified": True,
                    "apps_available": snapshot["available_apps"],
                    "apps_total": len(snapshot["apps"]),
                    "successful_launches": snapshot["successful_launches"],
                    "failed_launches": snapshot["failed_launches"],
                },
                "coarse_customer_status": snapshot["customer"],
                "categories": dict(snapshot["category_counts"]),
                "apps": [
                    {
                        "id": item["id"],
                        "label": item["label"],
                        "category": item["category"],
                        "available": item["available"],
                        "successful_launches": item["successful_launches"],
                        "failed_launches": item["failed_launches"],
                    }
                    for item in snapshot["apps"]
                ],
                "recent_launches": snapshot["history"],
                "privacy_notice": (
                    "This report excludes USB paths, USB key bytes, key ids, control PINs, PIN verifiers, session tokens, "
                    "CSRF tokens, license keys, receipts, customer identity, file names, full paths, and file contents."
                ),
                "limitations": [
                    "This report covers only the local app launcher session; it is not an antivirus scan or security certification.",
                    "The Local Control website can launch only its fixed approved apps and cannot lock, unlock, choose, read, or upload files.",
                ],
            }

    def lock_session(self):
        with self.lock:
            self.session_token = ""
            self.session_csrf = ""
            self.session_expires_at = 0.0
            self.login_csrf = secrets.token_urlsafe(24)


class LocalControlHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, server_address, handler_class, state):
        self.state = state
        super().__init__(server_address, handler_class)


class LocalControlHandler(BaseHTTPRequestHandler):
    server_version = "VaultLinkLocalControl/3"

    def log_message(self, _format, *_args):
        return

    def allowed_host(self):
        expected_port = self.server.server_address[1]
        return self.headers.get("Host", "") in {
            f"127.0.0.1:{expected_port}",
            f"localhost:{expected_port}",
        }

    def allowed_origin(self):
        if self.headers.get("Sec-Fetch-Site", "") == "cross-site":
            return False
        origin = self.headers.get("Origin", "")
        if not origin:
            return True
        port = self.server.server_address[1]
        return origin in {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}

    def session_cookie(self):
        try:
            jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            morsel = jar.get("VaultLinkLocalSession")
            return morsel.value if morsel else ""
        except Exception:
            return ""

    def send_security_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")

    def send_page(self, body, status=200, cookie=""):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(encoded)

    def send_json_download(self, payload, filename):
        encoded = json.dumps(payload, indent=2, ensure_ascii=True).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(encoded)))
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(encoded)

    def read_form(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid request size.") from exc
        if length < 0 or length > MAX_FORM_BYTES:
            raise ValueError("The local control request is too large.")
        raw = self.rfile.read(length).decode("utf-8", errors="strict")
        parsed = urllib.parse.parse_qs(raw, keep_blank_values=True, max_num_fields=8)
        return {key: values[-1] for key, values in parsed.items()}

    def render(self, message="", tone="", token_override=None, category_filter=""):
        token = self.session_cookie() if token_override is None else token_override
        authenticated = self.server.state.is_authorized(token)
        usb_ok, usb_message = self.server.state.usb_status()
        if authenticated and not usb_ok:
            self.server.state.lock_session()
            authenticated = False
        message_html = html.escape(message)
        tone_class = "good" if tone == "good" else "bad" if tone == "bad" else ""
        if authenticated:
            snapshot = self.server.state.dashboard_snapshot()
            csrf = html.escape(self.server.state.session_csrf, quote=True)
            selected_category = normalized_category_filter(category_filter, snapshot["apps"])
            categories = {}
            for item in snapshot["apps"]:
                categories.setdefault(item["category"], []).append(item)
            filter_links = ['<a class="active" href="/">ALL</a>' if not selected_category else '<a href="/">ALL</a>']
            for category in categories:
                encoded = urllib.parse.quote(category, safe="")
                active = ' class="active"' if category == selected_category else ""
                filter_links.append(
                    f'<a{active} href="/?category={encoded}">{html.escape(category)} ({len(categories[category])})</a>'
                )
            category_sections = []
            for category, items in categories.items():
                if selected_category and category != selected_category:
                    continue
                cards = []
                for item in items:
                    available = bool(item["available"])
                    button_text = f"OPEN {item['label'].upper()}" if available else "APP NOT AVAILABLE"
                    launch_text = f"{item['successful_launches']} OPENED | {item['failed_launches']} FAILED"
                    cards.append(
                        '<form method="post" action="/action" class="tool">'
                        f'<input type="hidden" name="csrf" value="{csrf}">'
                        f'<input type="hidden" name="action" value="{html.escape(item["id"], quote=True)}">'
                        f'<div class="tool-meta"><span class="eyebrow {"good" if available else "bad"}">{"AVAILABLE" if available else "MISSING"}</span><span>{html.escape(launch_text)}</span></div>'
                        f'<h3>{html.escape(item["label"])}</h3>'
                        f'<p>{html.escape(item["summary"])}</p>'
                        f'<button type="submit" {"" if available else "disabled"}>{html.escape(button_text)}</button>'
                        '</form>'
                    )
                category_sections.append(
                    f'<section><div class="section-head"><h2>{html.escape(category)}</h2><span>{len(items)} approved app(s)</span></div>'
                    f'<div class="grid">{"".join(cards)}</div></section>'
                )
            customer = snapshot["customer"]
            status_rows = [
                ("License", customer["license"]),
                ("Plan", customer["plan"]),
                ("Desktop", customer["desktop"]),
                ("API", customer["api"]),
                ("Service", customer["service"]),
                ("Verified auto-updates", customer["automatic_updates"]),
            ]
            status_cards = "".join(
                f'<article class="status-item"><span>{html.escape(label)}</span><strong>{html.escape(value)}</strong></article>'
                for label, value in status_rows
            )
            history_rows = "".join(
                '<div class="history-row">'
                f'<span>{html.escape(item["at_utc"])}</span>'
                f'<strong>{html.escape(item["label"])}</strong>'
                f'<span class="result {html.escape(item["result"])}">{html.escape(item["result"].upper())}</span>'
                '</div>'
                for item in snapshot["history"]
            ) or '<div class="empty">No apps launched in this server session.</div>'
            content = (
                '<section class="status-band"><strong>CONTROL SESSION UNLOCKED</strong>'
                f'<span>{html.escape(usb_message)}</span><span>{snapshot["remaining_minutes"]} minute(s) remaining.</span></section>'
                '<div class="metrics">'
                f'<div class="metric"><span>Apps available</span><strong>{snapshot["available_apps"]} / {len(snapshot["apps"])}</strong></div>'
                f'<div class="metric"><span>Session remaining</span><strong>{snapshot["remaining_seconds"]} sec</strong></div>'
                f'<div class="metric"><span>Launches</span><strong>{snapshot["successful_launches"]} ok / {snapshot["failed_launches"]} failed</strong></div>'
                f'<div class="metric"><span>Server uptime</span><strong>{snapshot["server_uptime_seconds"]} sec</strong></div>'
                f'<div class="metric"><span>Version</span><strong>{html.escape(snapshot["version"])}</strong></div>'
                f'<div class="metric"><span>Runtime</span><strong>{html.escape(snapshot["runtime"])}</strong></div>'
                '</div><div class="toolbar">'
                '<form method="get" action="/"><button type="submit">REFRESH STATUS</button></form>'
                f'<form method="post" action="/extend"><input type="hidden" name="csrf" value="{csrf}"><button type="submit">EXTEND 15 MIN</button></form>'
                f'<form method="post" action="/export-report"><input type="hidden" name="csrf" value="{csrf}"><button type="submit">EXPORT SAFE REPORT</button></form>'
                f'<form method="post" action="/clear-history"><input type="hidden" name="csrf" value="{csrf}"><button type="submit">CLEAR IN-MEMORY HISTORY</button></form>'
                f'<form method="post" action="/logout"><input type="hidden" name="csrf" value="{csrf}"><button class="danger" type="submit">LOCK CONTROL SESSION</button></form>'
                f'</div><nav class="filters" aria-label="App categories">{"".join(filter_links)}</nav>'
                '<section><div class="section-head"><h2>Local Status</h2><span>Coarse values only; no key, receipt, identity, or path.</span></div>'
                f'<div class="status-grid">{status_cards}</div></section>'
                + "".join(category_sections)
                + '<section><div class="section-head"><h2>Recent Launches</h2><span>Last 20 in memory; erased when the server stops.</span></div>'
                f'<div class="history">{history_rows}</div></section>'
                '<section class="privacy"><h2>Control Boundary</h2><p>This page can launch only the approved apps shown above. It cannot choose files, read file contents, type encryption PINs, unlock data, run arbitrary commands, or accept a remote connection.</p></section>'
            )
        else:
            content = f'''<section class="login">
              <h2>Unlock Local Control</h2>
              <p>{html.escape(usb_message)} Enter the separate local control PIN. The PIN and USB secret stay on this PC.</p>
              <form method="post" action="/login">
                <input type="hidden" name="csrf" value="{html.escape(self.server.state.login_csrf, quote=True)}">
                <label for="pin">Local control PIN</label>
                <input id="pin" name="pin" type="password" maxlength="64" autocomplete="off" required autofocus>
                <button type="submit">UNLOCK CONTROL SESSION</button>
              </form>
            </section>'''
        page = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VaultLink Local Control</title><style>
:root{{--bg:#0d1014;--band:#151a20;--panel:#1c222a;--field:#080b0e;--line:#394550;--text:#f4f7f8;--muted:#aab5bf;--green:#62dc86;--blue:#69bee9;--yellow:#ffd166;--red:#ff7b72}}
*{{box-sizing:border-box;letter-spacing:0}}body{{margin:0;min-width:320px;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",Arial,sans-serif}}
header,footer{{background:#11161b;border-color:var(--line);border-style:solid;border-width:0 0 1px}}header>div,main,footer>div{{width:min(1180px,calc(100% - 32px));margin:auto}}header>div{{min-height:70px;display:flex;align-items:center;justify-content:space-between;gap:12px}}header span,footer{{color:var(--muted)}}main{{padding:28px 0 44px}}h1{{font-size:26px;margin:0}}h2{{font-size:18px;margin:0 0 8px}}.notice{{min-height:24px;margin-bottom:12px;color:var(--muted)}}.notice.good{{color:var(--green)}}.notice.bad{{color:var(--red)}}
.login,.status-band{{padding:18px;border:1px solid var(--line);background:var(--band)}}.login{{max-width:560px}}label{{display:block;margin:14px 0 6px;color:var(--muted);font-size:11px;font-weight:800;text-transform:uppercase}}input{{width:100%;height:44px;padding:0 12px;border:1px solid var(--line);border-radius:5px;background:var(--field);color:var(--text);font:inherit}}button{{min-height:42px;padding:0 14px;border:0;border-radius:5px;background:var(--blue);color:#071118;font-weight:800;cursor:pointer}}button:disabled{{cursor:not-allowed;background:#252b32;color:#7e8993}}button.danger{{background:var(--red);color:#160606}}.login button{{margin-top:12px}}.status-band{{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:14px}}.status-band strong{{color:var(--green)}}.status-band span{{color:var(--muted)}}.metrics{{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));border:1px solid var(--line);background:var(--band)}}.metric{{padding:14px;border-right:1px solid var(--line)}}.metric:last-child{{border-right:0}}.metric span,.status-item span{{display:block;color:var(--muted);font-size:10px;font-weight:800;text-transform:uppercase}}.metric strong{{display:block;margin-top:4px;font-size:16px;overflow-wrap:anywhere}}.toolbar{{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}}.filters{{display:flex;flex-wrap:wrap;gap:7px;margin-top:12px}}.filters a{{display:inline-flex;min-height:34px;align-items:center;padding:0 10px;border:1px solid var(--line);border-radius:5px;color:var(--text);text-decoration:none;font-weight:800}}.filters a.active{{border-color:var(--blue);background:var(--blue);color:#071118}}section{{margin-top:22px;padding-top:18px;border-top:1px solid var(--line)}}.section-head{{display:flex;align-items:end;justify-content:space-between;gap:12px;margin-bottom:10px}}.section-head span{{color:var(--muted);text-align:right}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}}.tool{{padding:14px;border:1px solid var(--line);border-radius:6px;background:var(--panel)}}.tool h3{{margin:4px 0 0;font-size:15px}}.tool button{{width:100%;margin-top:12px;background:#29333d;color:var(--text)}}.tool p{{min-height:42px;margin:7px 0 0;color:var(--muted)}}.tool-meta{{display:flex;align-items:center;justify-content:space-between;gap:8px;color:var(--muted);font-size:9px;font-weight:800}}.eyebrow{{font-size:10px;font-weight:800}}.eyebrow.good,.result.ok{{color:var(--green)}}.eyebrow.bad,.result.failed{{color:var(--red)}}.status-grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}}.status-item{{min-width:0;padding:13px;border-left:3px solid var(--blue);background:var(--panel)}}.status-item strong{{display:block;margin-top:4px;overflow-wrap:anywhere}}.history{{display:grid;gap:6px}}.history-row{{display:grid;grid-template-columns:190px minmax(0,1fr) auto;gap:12px;padding:10px 12px;background:var(--panel)}}.history-row span:first-child{{color:var(--muted);font-family:Consolas,monospace}}.result{{font-size:11px;font-weight:800}}.empty{{padding:18px;border:1px dashed var(--line);color:var(--muted);text-align:center}}.privacy p{{margin:0;color:var(--muted)}}footer{{border-width:1px 0 0}}footer>div{{padding:20px 0 24px}}@media(max-width:1000px){{.metrics{{grid-template-columns:repeat(3,1fr)}}}}@media(max-width:760px){{.metrics{{grid-template-columns:repeat(2,1fr)}}.status-grid{{grid-template-columns:1fr 1fr}}.history-row{{grid-template-columns:1fr auto}}.history-row span:first-child{{grid-column:1 / -1}}}}@media(max-width:560px){{header>div,.section-head{{align-items:flex-start;flex-direction:column;padding:14px 0}}.section-head span{{text-align:left}}.metrics,.status-grid{{grid-template-columns:1fr}}.metric{{border-right:0;border-bottom:1px solid var(--line)}}}}
</style></head><body><header><div><h1>VaultLink Local Control</h1><span>LOOPBACK ONLY | SAME PC</span></div></header><main><div class="notice {tone_class}">{message_html}</div>{content}</main><footer><div>Version {html.escape(locker.DESKTOP_APP_VERSION)}. This page cannot receive remote connections, upload secrets, or lock and unlock files itself.</div></footer></body></html>'''
        return page

    def do_GET(self):
        if not self.allowed_host():
            self.send_page("Invalid local host.", status=400)
            return
        parsed_url = urllib.parse.urlsplit(self.path)
        path = parsed_url.path
        if path == "/favicon.ico":
            self.send_response(204)
            self.send_security_headers()
            self.end_headers()
            return
        if path != "/":
            self.send_page("Not found.", status=404)
            return
        query = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=False, max_num_fields=4)
        category = str((query.get("category") or [""])[0])
        self.send_page(self.render(category_filter=category))

    def do_POST(self):
        if not self.allowed_host() or not self.allowed_origin():
            self.send_page(self.render("The request did not come from this local page.", "bad"), status=403)
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/x-www-form-urlencoded":
            self.send_page(self.render("The local control request format is not allowed.", "bad"), status=415)
            return
        try:
            form = self.read_form()
        except Exception as exc:
            self.send_page(self.render(str(exc), "bad"), status=400)
            return
        path = urllib.parse.urlsplit(self.path).path
        if path == "/login":
            ok, message = self.server.state.authenticate(form.get("pin"), form.get("csrf"))
            cookie = ""
            if ok:
                cookie = (
                    f"VaultLinkLocalSession={self.server.state.session_token}; Path=/; "
                    f"Max-Age={SESSION_SECONDS}; HttpOnly; SameSite=Strict"
                )
            self.send_page(
                self.render(message, "good" if ok else "bad", self.server.state.session_token if ok else None),
                status=200 if ok else 401,
                cookie=cookie,
            )
            return
        token = self.session_cookie()
        if path == "/logout":
            if not self.server.state.is_authorized(token) or not hmac.compare_digest(str(form.get("csrf", "")), self.server.state.session_csrf):
                self.send_page(self.render("The control session was already locked.", "bad"), status=403)
                return
            self.server.state.lock_session()
            locker.log_event("local_control_logout", "loopback", "ok")
            self.send_page(
                self.render("Local control session locked.", "good"),
                cookie="VaultLinkLocalSession=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict",
            )
            return
        if path == "/extend":
            try:
                self.server.state.extend_session(token, form.get("csrf"))
                self.send_page(self.render("Local control session extended by 15 minutes.", "good"))
            except PermissionError as exc:
                self.send_page(self.render(str(exc), "bad"), status=403)
            return
        if path == "/clear-history":
            try:
                self.server.state.clear_history(token, form.get("csrf"))
                self.send_page(self.render("In-memory launch history cleared.", "good"))
            except PermissionError as exc:
                self.send_page(self.render(str(exc), "bad"), status=403)
            return
        if path == "/export-report":
            try:
                report = self.server.state.safe_report(token, form.get("csrf"))
                locker.log_event("local_control_report_export", "loopback", "ok")
                self.send_json_download(report, "vaultlink-local-control-report.json")
            except PermissionError as exc:
                locker.log_event("local_control_report_export", "loopback", "failed")
                self.send_page(self.render(str(exc), "bad"), status=403)
            return
        if path == "/action":
            try:
                label = self.server.state.run_action(token, form.get("csrf"), form.get("action"))
                self.send_page(self.render(f"Opened {label} on this PC.", "good"))
            except PermissionError as exc:
                self.send_page(self.render(str(exc), "bad"), status=403)
            except Exception:
                self.send_page(
                    self.render("The approved app could not be opened. Check the desktop Local Control Center.", "bad"),
                    status=400,
                )
            return
        self.send_page("Not found.", status=404)


class LocalControlCenter(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VaultLink Local Control Center")
        self.geometry("680x560")
        self.minsize(620, 520)
        self.configure(bg=locker.BG)
        settings = locker.load_settings()
        self.key_path = tk.StringVar(value=str(settings.get("last_key_path", "") or ""))
        self.status = tk.StringVar(value="Choose the USB key and configure a separate local control PIN.")
        self.server = None
        self.server_thread = None
        self.url = ""
        self.open_button = None
        self.copy_button = None
        self.lock_session_button = None
        self.stop_button = None
        self.last_usb_ready = True
        self.build_ui()
        self.protocol("WM_DELETE_WINDOW", self.close_requested)
        self.after(1500, self.monitor_server_key)

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=26, pady=24)
        tk.Label(outer, text="Local Control Center", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 24, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="SAME-PC WEBSITE | USB PRESENCE CHECK | SEPARATE CONTROL PIN | 15-MINUTE SESSION",
            bg=locker.BG,
            fg=locker.GREEN,
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w", pady=(3, 16))
        panel = tk.Frame(outer, bg=locker.PANEL)
        panel.pack(fill="both", expand=True)
        tk.Label(panel, text="MASTER USB KEY", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=18, pady=(18, 5))
        key_row = tk.Frame(panel, bg=locker.PANEL)
        key_row.pack(fill="x", padx=18)
        tk.Entry(key_row, textvariable=self.key_path, state="readonly", bg=locker.FIELD, fg=locker.TEXT, readonlybackground=locker.FIELD, relief="flat", font=("Segoe UI", 9)).pack(side="left", fill="x", expand=True, ipady=7)
        tk.Button(key_row, text="BROWSE", command=self.choose_key, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", padx=(8, 0), ipadx=10, ipady=6)
        tk.Label(panel, text="The browser never receives the key path, key bytes, or PIN verifier.", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 9)).pack(anchor="w", padx=18, pady=(8, 16))
        pin_row = tk.Frame(panel, bg=locker.PANEL)
        pin_row.pack(fill="x", padx=18)
        tk.Button(pin_row, text="SET OR CHANGE CONTROL PIN", command=self.configure_pin, bg=locker.YELLOW, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=10, ipady=7)
        tk.Label(pin_row, text="This is not the encryption PIN and is never saved as readable text.", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 9), wraplength=330, justify="left").pack(side="left", padx=(12, 0))
        buttons = tk.Frame(panel, bg=locker.PANEL)
        buttons.pack(fill="x", padx=18, pady=(22, 10))
        tk.Button(buttons, text="START LOCAL WEBSITE", command=self.start_server, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 10, "bold")).pack(side="left", ipadx=12, ipady=8)
        self.open_button = tk.Button(buttons, text="OPEN WEBSITE", command=self.open_site, state="disabled", bg=locker.BLUE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 10, "bold"))
        self.open_button.pack(side="left", padx=(8, 0), ipadx=12, ipady=8)
        self.stop_button = tk.Button(buttons, text="STOP", command=self.stop_server, state="disabled", bg=locker.RED, fg=locker.WHITE, relief="flat", font=("Segoe UI", 10, "bold"))
        self.stop_button.pack(side="right", ipadx=12, ipady=8)
        session_buttons = tk.Frame(panel, bg=locker.PANEL)
        session_buttons.pack(fill="x", padx=18, pady=(0, 8))
        self.copy_button = tk.Button(session_buttons, text="COPY LOCAL URL", command=self.copy_url, state="disabled", bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.copy_button.pack(side="left", ipadx=10, ipady=6)
        self.lock_session_button = tk.Button(session_buttons, text="LOCK BROWSER SESSION", command=self.lock_website_session, state="disabled", bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.lock_session_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        tk.Label(session_buttons, text=f"{len(CONTROL_ACTIONS)} approved apps | safe report | 20-entry memory history", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(side="right")
        tk.Label(panel, textvariable=self.status, bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 9), wraplength=560, justify="left").pack(anchor="w", padx=18, pady=(8, 18))

    def choose_key(self):
        path = filedialog.askopenfilename(parent=self, title="Choose master USB key", filetypes=[("USB File Locker key", "*.key"), ("All files", "*.*")])
        if not path:
            return
        try:
            verify_selected_key(path)
            self.key_path.set(path)
            settings = locker.load_settings()
            settings["last_key_path"] = path
            locker.save_settings(settings)
            self.status.set("USB key verified locally. Configure the control PIN or start the website.")
        except Exception as exc:
            messagebox.showerror("USB key not accepted", str(exc), parent=self)

    def require_key(self):
        path = self.key_path.get().strip()
        if not path:
            raise ValueError("Choose the master USB key first.")
        return verify_selected_key(path)

    def configure_pin(self):
        try:
            self.require_key()
        except Exception as exc:
            messagebox.showerror("USB key required", str(exc), parent=self)
            return
        first = simpledialog.askstring("Local control PIN", "Create a separate 6-64 character PIN for the local control website.", show="*", parent=self)
        if first is None:
            return
        second = simpledialog.askstring("Confirm local control PIN", "Enter the same local control PIN again.", show="*", parent=self)
        if second is None:
            return
        if first != second:
            messagebox.showerror("PINs do not match", "The two local control PINs were different.", parent=self)
            return
        try:
            save_control_pin(first)
            self.status.set("Local control PIN saved as a Windows-protected scrypt verifier.")
            locker.log_event("local_control_pin_change", "local", "ok")
        except Exception as exc:
            messagebox.showerror("Could not save PIN", str(exc), parent=self)

    def start_server(self):
        if self.server is not None:
            self.open_site()
            return
        try:
            key = self.require_key()
            if not control_pin_configured():
                raise ValueError("Set the separate local control PIN first.")
            state = ControlState(self.key_path.get().strip(), key.get("key_id", ""))
            server = LocalControlHTTPServer((LOCAL_HOST, 0), LocalControlHandler, state)
        except Exception as exc:
            messagebox.showerror("Could not start local control", str(exc), parent=self)
            return
        self.server = server
        port = server.server_address[1]
        self.url = f"http://{LOCAL_HOST}:{port}/"
        self.server_thread = threading.Thread(target=server.serve_forever, name="VaultLinkLocalControl", daemon=True)
        self.server_thread.start()
        self.open_button.configure(state="normal")
        self.copy_button.configure(state="normal")
        self.lock_session_button.configure(state="normal")
        self.stop_button.configure(state="normal")
        self.last_usb_ready = True
        self.status.set(f"Local website running on this PC only: {self.url}")
        locker.log_event("local_control_start", "loopback", "ok")
        self.open_site()

    def open_site(self):
        if not self.url:
            return
        webbrowser.open(self.url, new=2)

    def copy_url(self):
        if not self.url:
            return
        self.clipboard_clear()
        self.clipboard_append(self.url)
        self.update_idletasks()
        self.status.set("Same-PC local website address copied.")

    def lock_website_session(self):
        if self.server is None:
            return
        self.server.state.lock_session()
        self.status.set("Browser control session locked. The local website is still running.")
        locker.log_event("local_control_desktop_lock", "loopback", "ok")

    def monitor_server_key(self):
        try:
            if self.server is not None:
                ready, _message = self.server.state.usb_status()
                if not ready and self.last_usb_ready:
                    self.server.state.lock_session()
                    self.status.set("USB key removed or changed. Browser control session locked automatically.")
                    locker.log_event("local_control_usb_removed", "loopback", "failed")
                self.last_usb_ready = ready
        finally:
            try:
                exists = bool(self.winfo_exists())
            except tk.TclError:
                exists = False
            if exists:
                self.after(1500, self.monitor_server_key)

    def stop_server(self):
        server = self.server
        if server is None:
            return
        self.server = None
        self.url = ""
        server.state.lock_session()
        server.shutdown()
        server.server_close()
        self.open_button.configure(state="disabled")
        self.copy_button.configure(state="disabled")
        self.lock_session_button.configure(state="disabled")
        self.stop_button.configure(state="disabled")
        self.last_usb_ready = True
        self.status.set("Local control website stopped. No network listener remains.")
        locker.log_event("local_control_stop", "loopback", "ok")

    def close_requested(self):
        self.stop_server()
        self.destroy()


if __name__ == "__main__":
    LocalControlCenter().mainloop()
