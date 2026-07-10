import json
import os
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


API_NAME = "VaultLink API"
API_VERSION = "0.1.0"
ROOT_DIR = Path(__file__).resolve().parent
APP_DIR = ROOT_DIR.parent


FEATURES = [
    {
        "id": "portable-locking",
        "title": "Portable file locking",
        "summary": "Locks files and folders with a USB master key and an optional PIN using portable authenticated encryption.",
        "category": "core",
    },
    {
        "id": "owner-usb-mode",
        "title": "Owner USB mode",
        "summary": "Lets a PC stay tied to a specific owner USB so the app can lock itself again if that drive disappears.",
        "category": "security",
    },
    {
        "id": "personal-vault",
        "title": "Personal vault",
        "summary": "Stores passcodes, recovery codes, account notes, and private records inside a separate encrypted vault.",
        "category": "vault",
    },
    {
        "id": "audit-chain",
        "title": "Audit chain",
        "summary": "Writes privacy-safe signed audit events so verification can catch tampering or unexpected activity.",
        "category": "security",
    },
    {
        "id": "breach-guard",
        "title": "Breach guard",
        "summary": "Watches signed audit events for repeated failed access, owner USB removal, restore events, and other risky patterns.",
        "category": "security",
    },
    {
        "id": "perm-unlock",
        "title": "PERM UNLOCK workflow",
        "summary": "Supports a dedicated edit-and-relock flow so users can work on readable copies and pull them back in safely.",
        "category": "workflow",
    },
]


COMPANION_APPS = [
    {"name": "Privacy Safety Hub", "script": "privacy_safety_hub.py", "purpose": "Launch dashboard for the toolkit."},
    {"name": "Locked File Browser", "script": "locked_file_browser.py", "purpose": "Find .locked files quickly and jump into unlock mode."},
    {"name": "Quick Lock Note", "script": "quick_lock_note.py", "purpose": "Turn pasted text into a locked note fast."},
    {"name": "Key Inspector", "script": "key_inspector.py", "purpose": "Inspect a USB master key and owner-key matching."},
    {"name": "PERM UNLOCK Workbench", "script": "perm_unlock_workbench.py", "purpose": "Manage edit-and-relock items in the PERM UNLOCK folder."},
    {"name": "Personal Vault Pad", "script": "personal_vault_pad.py", "purpose": "Use the vault in a simpler note-style window."},
    {"name": "Audit Log Viewer", "script": "audit_log_viewer.py", "purpose": "Read and export the privacy-safe signed audit trail."},
    {"name": "Text Log Processor", "script": "text_log_processor.py", "purpose": "Parse table-style text logs into a cleaner summary."},
    {"name": "Global Breach Guard", "script": "global_breach_guard.py", "purpose": "Run a topmost global breach watcher."},
]


SECURITY_NOTES = [
    "The public API is intentionally read-only. It does not expose USB secrets, PINs, unlock operations, or remote file access.",
    "Desktop encryption and USB-key logic stay in the Windows app and are not moved into the internet-facing service.",
    "Signed audit events and breach detection stay privacy-safe and do not include file contents or stored secrets.",
]


PLAN_TIERS = [
    {
        "id": "starter",
        "name": "$5 Starter",
        "best_for": "Simple personal file locking",
        "includes": [
            "USB-key file locking",
            "Optional PIN support",
            "Quick lock notes",
            "Basic audit events",
        ],
    },
    {
        "id": "plus",
        "name": "$50 Plus",
        "best_for": "Families and everyday private records",
        "includes": [
            "Everything in Starter",
            "Personal Vault tools",
            "Audit Log Viewer",
            "Locked File Browser",
            "PERM UNLOCK workflow",
        ],
    },
    {
        "id": "pro",
        "name": "$100 Pro",
        "best_for": "Power users who want broader control",
        "includes": [
            "Everything in Plus",
            "Privacy Safety Hub",
            "Global Breach Guard",
            "Text Log Processor",
            "Owner USB mode",
        ],
    },
    {
        "id": "signature",
        "name": "$200 Signature",
        "best_for": "Full toolkit deployments with the richest desktop set",
        "includes": [
            "Everything in Pro",
            "Priority setup profile",
            "Expanded companion-app set",
            "Export-ready audit workflow",
            "Best overall locker bundle",
        ],
    },
]


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def product_payload():
    return {
        "name": "USB File Locker",
        "api_name": API_NAME,
        "api_version": API_VERSION,
        "tagline": "USB-key file locking, personal vault tools, and signed breach-aware audit tracking.",
        "desktop_scripts": sorted(path.name for path in APP_DIR.glob("*.py") if path.name != "__init__.py"),
        "updated_at_utc": utc_now(),
    }


def json_bytes(payload):
    return json.dumps(payload, indent=2).encode("utf-8")


def docs_payload():
    return {
        "service": API_NAME,
        "version": API_VERSION,
        "routes": [
            {"method": "GET", "path": "/", "purpose": "HTML homepage"},
            {"method": "GET", "path": "/docs", "purpose": "JSON route index"},
            {"method": "GET", "path": "/health", "purpose": "Health check"},
            {"method": "GET", "path": "/api/v1/product", "purpose": "Product metadata"},
            {"method": "GET", "path": "/api/v1/features", "purpose": "Feature catalog"},
            {"method": "GET", "path": "/api/v1/companions", "purpose": "Companion app catalog"},
            {"method": "GET", "path": "/api/v1/plans", "purpose": "Plan and tier catalog"},
            {"method": "GET", "path": "/api/v1/security", "purpose": "Public security model"},
            {"method": "GET", "path": "/api/v1/deploy", "purpose": "Railway deploy hints"},
        ],
    }


def homepage_html():
    product = product_payload()
    feature_html = "".join(
        f"<li><strong>{item['title']}</strong><br>{item['summary']}</li>"
        for item in FEATURES[:6]
    )
    app_html = "".join(
        f"<li><strong>{item['name']}</strong><br>{item['purpose']}</li>"
        for item in COMPANION_APPS[:6]
    )
    security_html = "".join(f"<li>{line}</li>" for line in SECURITY_NOTES)
    plan_html = "".join(
        f"<li><strong>{item['name']}</strong><br>{item['best_for']}</li>"
        for item in PLAN_TIERS
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{API_NAME}</title>
  <style>
    :root {{
      --bg: #111317;
      --panel: #1a1e25;
      --line: #2a313c;
      --text: #f1f3f5;
      --muted: #aeb7c4;
      --accent: #74e27f;
      --accent-2: #ffd166;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Arial, sans-serif;
      background:
        radial-gradient(circle at top left, rgba(116, 226, 127, 0.12), transparent 32%),
        radial-gradient(circle at top right, rgba(255, 209, 102, 0.12), transparent 28%),
        var(--bg);
      color: var(--text);
    }}
    .wrap {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 36px 20px 56px;
    }}
    .hero {{
      display: grid;
      gap: 18px;
      padding: 28px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));
    }}
    h1 {{
      margin: 0;
      font-size: clamp(2rem, 4vw, 3.2rem);
      line-height: 1.05;
      letter-spacing: 0;
    }}
    p {{
      margin: 0;
      color: var(--muted);
      line-height: 1.6;
      max-width: 760px;
    }}
    .cta {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-top: 6px;
    }}
    .cta a {{
      text-decoration: none;
      color: var(--text);
      padding: 12px 16px;
      border-radius: 8px;
      border: 1px solid var(--line);
      background: var(--panel);
    }}
    .cta a.primary {{
      background: var(--accent);
      color: #09110b;
      border-color: transparent;
      font-weight: 700;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
      margin-top: 20px;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
    }}
    .card h2 {{
      margin: 0 0 10px;
      font-size: 1.05rem;
    }}
    ul {{
      margin: 0;
      padding-left: 18px;
      color: var(--muted);
      line-height: 1.6;
    }}
    .meta {{
      margin-top: 18px;
      color: var(--muted);
      font-size: 0.95rem;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div>
        <div style="color: var(--accent-2); font-weight: 700; margin-bottom: 10px;">{product['name']}</div>
        <h1>{API_NAME}</h1>
      </div>
      <p>{product['tagline']}</p>
      <div class="cta">
        <a class="primary" href="/docs">Open Route Index</a>
        <a href="/api/v1/product">Product JSON</a>
        <a href="/api/v1/features">Features JSON</a>
      </div>
      <div class="meta">API version {API_VERSION} - Updated {product['updated_at_utc']}</div>
    </section>
    <section class="grid">
      <div class="card">
        <h2>Core Features</h2>
        <ul>{feature_html}</ul>
      </div>
      <div class="card">
        <h2>Companion Apps</h2>
        <ul>{app_html}</ul>
      </div>
      <div class="card">
        <h2>Security Shape</h2>
        <ul>{security_html}</ul>
      </div>
      <div class="card">
        <h2>Plan Tiers</h2>
        <ul>{plan_html}</ul>
      </div>
    </section>
  </div>
</body>
</html>"""


class ApiHandler(BaseHTTPRequestHandler):
    def send_json(self, payload, status=HTTPStatus.OK):
        body = json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html, status=HTTPStatus.OK):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/":
            self.send_html(homepage_html())
            return
        if path == "/docs":
            self.send_json(docs_payload())
            return
        if path == "/health":
            self.send_json({"ok": True, "service": API_NAME, "version": API_VERSION, "time_utc": utc_now()})
            return
        if path == "/api/v1/product":
            self.send_json(product_payload())
            return
        if path == "/api/v1/features":
            self.send_json({"items": FEATURES, "count": len(FEATURES)})
            return
        if path == "/api/v1/companions":
            self.send_json({"items": COMPANION_APPS, "count": len(COMPANION_APPS)})
            return
        if path == "/api/v1/plans":
            self.send_json({"items": PLAN_TIERS, "count": len(PLAN_TIERS)})
            return
        if path == "/api/v1/security":
            self.send_json(
                {
                    "public_api_mode": "read_only",
                    "notes": SECURITY_NOTES,
                    "banned_remote_actions": [
                        "remote unlock",
                        "remote key creation",
                        "remote PIN capture",
                        "remote file reads",
                        "remote vault secret retrieval",
                    ],
                }
            )
            return
        if path == "/api/v1/deploy":
            self.send_json(
                {
                    "provider": "Railway",
                    "root_directory": "usb_locker_api",
                    "start_command": "python main.py",
                    "port_env": os.getenv("PORT", "8000"),
                }
            )
            return

        self.send_json(
            {
                "error": "not_found",
                "message": "Route not found.",
                "docs": "/docs",
            },
            status=HTTPStatus.NOT_FOUND,
        )

    def log_message(self, fmt, *args):
        return


def run():
    port = int(os.getenv("PORT", "8000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), ApiHandler)
    print(f"{API_NAME} listening on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
