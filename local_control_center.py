import base64
import hashlib
import hmac
import html
import json
import secrets
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
    "main_locker": ("Main Locker", None),
    "customer_workspace": ("Customer Workspace", "customer_hub.py"),
    "vault_health": ("Vault Health Center", "vault_health_center.py"),
    "locked_browser": ("Locked File Browser", "locked_file_browser.py"),
    "key_inspector": ("Key Inspector", "key_inspector.py"),
    "personal_vault": ("Personal Vault Pad", "personal_vault_pad.py"),
    "perm_unlock": ("PERM Unlock Workbench", "perm_unlock_workbench.py"),
    "audit_log": ("Audit Log Viewer", "audit_log_viewer.py"),
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
    _label, script_name = action
    if script_name is None:
        locker.launch_main_app_process()
    else:
        locker.launch_companion_script(script_name)
    return action[0]


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
            label = launch_control_action(action_id)
            self.session_expires_at = time.monotonic() + SESSION_SECONDS
            locker.log_event("local_control_launch", str(action_id), "ok")
            return label

    def lock_session(self):
        self.session_token = ""
        self.session_csrf = ""
        self.session_expires_at = 0.0


class LocalControlHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, server_address, handler_class, state):
        self.state = state
        super().__init__(server_address, handler_class)


class LocalControlHandler(BaseHTTPRequestHandler):
    server_version = "VaultLinkLocalControl/1"

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

    def render(self, message="", tone="", token_override=None):
        token = self.session_cookie() if token_override is None else token_override
        authenticated = self.server.state.is_authorized(token)
        usb_ok, usb_message = self.server.state.usb_status()
        if authenticated and not usb_ok:
            self.server.state.lock_session()
            authenticated = False
        message_html = html.escape(message)
        tone_class = "good" if tone == "good" else "bad" if tone == "bad" else ""
        if authenticated:
            cards = []
            for action_id, (label, _script_name) in CONTROL_ACTIONS.items():
                cards.append(
                    '<form method="post" action="/action" class="tool">'
                    f'<input type="hidden" name="csrf" value="{html.escape(self.server.state.session_csrf, quote=True)}">'
                    f'<input type="hidden" name="action" value="{html.escape(action_id, quote=True)}">'
                    f'<button type="submit">{html.escape(label)}</button>'
                    '<p>Launches the approved local Windows app. File actions still require confirmation inside that app.</p>'
                    '</form>'
                )
            content = (
                '<section class="status-band"><strong>CONTROL SESSION UNLOCKED</strong>'
                f'<span>{html.escape(usb_message)}</span><span>Automatically locks after 15 minutes of inactivity.</span></section>'
                '<section><h2>Approved Local Apps</h2><div class="grid">'
                + "".join(cards)
                + '</div></section><form method="post" action="/logout" class="logout">'
                f'<input type="hidden" name="csrf" value="{html.escape(self.server.state.session_csrf, quote=True)}">'
                '<button type="submit">LOCK CONTROL SESSION</button></form>'
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
:root{{--bg:#0d1014;--band:#151a20;--panel:#1c222a;--field:#080b0e;--line:#394550;--text:#f4f7f8;--muted:#aab5bf;--green:#62dc86;--blue:#69bee9;--red:#ff7b72}}
*{{box-sizing:border-box;letter-spacing:0}}body{{margin:0;min-width:320px;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",Arial,sans-serif}}
header,footer{{background:#11161b;border-color:var(--line);border-style:solid;border-width:0 0 1px}}header>div,main,footer>div{{width:min(980px,calc(100% - 32px));margin:auto}}header>div{{min-height:70px;display:flex;align-items:center;justify-content:space-between;gap:12px}}header span,footer{{color:var(--muted)}}main{{padding:28px 0 44px}}h1{{font-size:26px;margin:0}}h2{{font-size:18px;margin:0 0 8px}}.notice{{min-height:24px;margin-bottom:12px;color:var(--muted)}}.notice.good{{color:var(--green)}}.notice.bad{{color:var(--red)}}
.login,.status-band,section{{padding:18px;border:1px solid var(--line);background:var(--band)}}.login{{max-width:560px}}label{{display:block;margin:14px 0 6px;color:var(--muted);font-size:11px;font-weight:800;text-transform:uppercase}}input{{width:100%;height:44px;padding:0 12px;border:1px solid var(--line);border-radius:5px;background:var(--field);color:var(--text);font:inherit}}button{{min-height:42px;padding:0 14px;border:0;border-radius:5px;background:var(--blue);color:#071118;font-weight:800;cursor:pointer}}.login button{{margin-top:12px}}.status-band{{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:16px}}.status-band strong{{color:var(--green)}}.status-band span{{color:var(--muted)}}section+section{{margin-top:16px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-top:12px}}.tool{{padding:14px;border:1px solid var(--line);border-radius:6px;background:var(--panel)}}.tool button{{width:100%;background:#29333d;color:var(--text)}}.tool p{{margin:8px 0 0;color:var(--muted)}}.logout{{margin-top:16px}}.logout button{{background:var(--red);color:#160606}}footer{{border-width:1px 0 0}}footer>div{{padding:20px 0 24px}}@media(max-width:560px){{header>div{{align-items:flex-start;flex-direction:column;padding:14px 0}}}}
</style></head><body><header><div><h1>VaultLink Local Control</h1><span>LOOPBACK ONLY | SAME PC</span></div></header><main><div class="notice {tone_class}">{message_html}</div>{content}</main><footer><div>Version {html.escape(locker.DESKTOP_APP_VERSION)}. This page cannot receive remote connections, upload secrets, or lock and unlock files itself.</div></footer></body></html>'''
        return page

    def do_GET(self):
        if not self.allowed_host():
            self.send_page("Invalid local host.", status=400)
            return
        path = urllib.parse.urlsplit(self.path).path
        if path == "/favicon.ico":
            self.send_response(204)
            self.send_security_headers()
            self.end_headers()
            return
        if path != "/":
            self.send_page("Not found.", status=404)
            return
        self.send_page(self.render())

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
        if path == "/action":
            try:
                label = self.server.state.run_action(token, form.get("csrf"), form.get("action"))
                self.send_page(self.render(f"Opened {label} on this PC.", "good"))
            except PermissionError as exc:
                self.send_page(self.render(str(exc), "bad"), status=403)
            except Exception:
                locker.log_event("local_control_launch", str(form.get("action", "")), "failed")
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
        self.geometry("650x500")
        self.minsize(600, 470)
        self.configure(bg=locker.BG)
        settings = locker.load_settings()
        self.key_path = tk.StringVar(value=str(settings.get("last_key_path", "") or ""))
        self.status = tk.StringVar(value="Choose the USB key and configure a separate local control PIN.")
        self.server = None
        self.server_thread = None
        self.url = ""
        self.open_button = None
        self.stop_button = None
        self.build_ui()
        self.protocol("WM_DELETE_WINDOW", self.close_requested)

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
        self.stop_button.configure(state="normal")
        self.status.set(f"Local website running on this PC only: {self.url}")
        locker.log_event("local_control_start", "loopback", "ok")
        self.open_site()

    def open_site(self):
        if not self.url:
            return
        webbrowser.open(self.url, new=2)

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
        self.stop_button.configure(state="disabled")
        self.status.set("Local control website stopped. No network listener remains.")
        locker.log_event("local_control_stop", "loopback", "ok")

    def close_requested(self):
        self.stop_server()
        self.destroy()


if __name__ == "__main__":
    LocalControlCenter().mainloop()
