import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


API_NAME = "VaultLink API"
API_VERSION = "0.3.0"
ROOT_DIR = Path(__file__).resolve().parent
LICENSE_KEY_PREFIX = "vlk1"
LICENSE_RECEIPT_PREFIX = "vlr1"
AUDIT_DOWNLOAD_PREFIX = "vla1"
DEFAULT_SIGNING_SECRET = "vaultlink-dev-signing-secret-change-me"
MAX_JSON_BODY_BYTES = 4 * 1024 * 1024
MAX_AUDIT_REPORT_BYTES = 3 * 1024 * 1024
MAX_AUDIT_EVENTS = 20000
try:
    AUDIT_EXPORT_RETENTION_HOURS = min(
        max(int(os.getenv("AUDIT_EXPORT_RETENTION_HOURS", "24")), 1),
        168,
    )
except ValueError:
    AUDIT_EXPORT_RETENTION_HOURS = 24
AUDIT_EXPORT_DIR = Path(
    os.getenv("AUDIT_EXPORT_DIR", str(ROOT_DIR / "data" / "audit_exports"))
).expanduser()


FEATURES = [
    {
        "id": "portable-locking",
        "title": "Portable locking tools",
        "summary": "Create new portable .locked files and manage the main locking queue.",
        "category": "starter",
    },
    {
        "id": "quick-lock-note",
        "title": "Quick lock notes",
        "summary": "Create encrypted text notes quickly from the desktop app.",
        "category": "starter",
    },
    {
        "id": "personal-vault",
        "title": "Personal vault",
        "summary": "Store passcodes, recovery codes, account notes, and private records inside a separate encrypted vault.",
        "category": "plus",
    },
    {
        "id": "locked-file-browser",
        "title": "Locked File Browser",
        "summary": "Browse and launch .locked files from a dedicated companion app.",
        "category": "plus",
    },
    {
        "id": "audit-log-viewer",
        "title": "Audit Log Viewer",
        "summary": "Read, export, and verify the privacy-safe audit trail from the richer companion app.",
        "category": "plus",
    },
    {
        "id": "perm-unlock",
        "title": "PERM UNLOCK workflow",
        "summary": "Edit readable working copies and relock them safely with the dedicated workflow.",
        "category": "plus",
    },
    {
        "id": "privacy-safety-hub",
        "title": "Privacy Safety Hub",
        "summary": "Open the dashboard that ties the locker toolkit together.",
        "category": "pro",
    },
    {
        "id": "global-breach-guard",
        "title": "Global Breach Guard",
        "summary": "Run the topmost watcher that checks the signed audit trail and raises alerts.",
        "category": "pro",
    },
    {
        "id": "text-log-processor",
        "title": "Text Log Processor",
        "summary": "Turn pasted audit-style text logs into cleaner summaries and counts.",
        "category": "pro",
    },
    {
        "id": "owner-usb-mode",
        "title": "Owner USB mode",
        "summary": "Tie a PC session to one registered owner USB and relock if that drive disappears.",
        "category": "pro",
    },
    {
        "id": "signature-bundle",
        "title": "Signature bundle extras",
        "summary": "Reserved for the highest tier so the app can expose future white-glove bundle extras.",
        "category": "signature",
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
    "The public API never unlocks files, never receives USB secrets, and never stores PINs or vault contents.",
    "Desktop encryption and USB-key logic stay in the Windows app instead of moving onto the internet-facing service.",
    "Licensing is stateless right now: the server signs license keys and machine receipts, but strict seat counting needs a real database later.",
    "Audit exports are reduced to privacy-safe fields, require an active licensed machine, and use short-lived signed download links.",
]


PLAN_TIERS = [
    {
        "id": "starter",
        "name": "$5 Starter",
        "best_for": "Simple personal locking with note support",
        "rank": 1,
        "includes": [
            "Portable locking tools",
            "Quick lock notes",
            "Create new .locked files",
            "Use the main lock queue",
        ],
        "features": [
            "portable-locking",
            "quick-lock-note",
        ],
    },
    {
        "id": "plus",
        "name": "$50 Plus",
        "best_for": "Families and everyday private records",
        "rank": 2,
        "includes": [
            "Everything in Starter",
            "Personal Vault tools",
            "Audit Log Viewer",
            "Locked File Browser",
            "PERM UNLOCK workflow",
        ],
        "features": [
            "personal-vault",
            "audit-log-viewer",
            "locked-file-browser",
            "perm-unlock",
        ],
    },
    {
        "id": "pro",
        "name": "$100 Pro",
        "best_for": "Power users who want broader desktop control",
        "rank": 3,
        "includes": [
            "Everything in Plus",
            "Privacy Safety Hub",
            "Global Breach Guard",
            "Text Log Processor",
            "Owner USB mode",
        ],
        "features": [
            "privacy-safety-hub",
            "global-breach-guard",
            "text-log-processor",
            "owner-usb-mode",
        ],
    },
    {
        "id": "signature",
        "name": "$200 Signature",
        "best_for": "Full toolkit bundles and future premium extras",
        "rank": 4,
        "includes": [
            "Everything in Pro",
            "Priority setup profile",
            "Expanded companion-app set",
            "Export-ready audit workflow",
            "Best overall locker bundle",
        ],
        "features": [
            "signature-bundle",
        ],
    },
]


PLAN_INDEX = {item["id"]: item for item in PLAN_TIERS}


def utc_now():
    return format_utc(datetime.now(timezone.utc))


def format_utc(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value):
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text).astimezone(timezone.utc)


def plan_entitlements(plan_id):
    plan = PLAN_INDEX.get(plan_id)
    if not plan:
        raise ValueError(f"Unknown plan id: {plan_id}")
    unlocked = []
    seen = set()
    for candidate in sorted(PLAN_TIERS, key=lambda item: item["rank"]):
        if candidate["rank"] > plan["rank"]:
            break
        for feature_id in candidate.get("features", []):
            if feature_id in seen:
                continue
            seen.add(feature_id)
            unlocked.append(feature_id)
    return unlocked


def public_plan_payload(plan):
    return {
        "id": plan["id"],
        "name": plan["name"],
        "best_for": plan["best_for"],
        "rank": plan["rank"],
        "includes": list(plan["includes"]),
        "entitlements": plan_entitlements(plan["id"]),
    }


def signing_secret():
    return os.getenv("LICENSE_SIGNING_SECRET", DEFAULT_SIGNING_SECRET)


def using_default_signing_secret():
    return signing_secret() == DEFAULT_SIGNING_SECRET


def admin_token_configured():
    return bool(os.getenv("LICENSE_ADMIN_TOKEN", "").strip())


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode((text + padding).encode("ascii"))


def json_bytes(payload):
    return json.dumps(payload, indent=2).encode("utf-8")


def canonical_json_bytes(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_token(prefix, payload):
    payload_text = b64url_encode(canonical_json_bytes(payload))
    message = f"{prefix}.{payload_text}".encode("utf-8")
    signature = hmac.new(signing_secret().encode("utf-8"), message, hashlib.sha256).digest()
    return f"{prefix}.{payload_text}.{b64url_encode(signature)}"


def verify_token(token, prefix):
    parts = str(token or "").strip().split(".")
    if len(parts) != 3 or parts[0] != prefix:
        raise ValueError("Wrong token format.")
    payload_text = parts[1]
    signature_text = parts[2]
    message = f"{prefix}.{payload_text}".encode("utf-8")
    expected = b64url_encode(hmac.new(signing_secret().encode("utf-8"), message, hashlib.sha256).digest())
    if not hmac.compare_digest(signature_text, expected):
        raise ValueError("Token signature did not verify.")
    payload = json.loads(b64url_decode(payload_text).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Token payload was not a JSON object.")
    return payload


def current_plan_for_license(license_payload):
    plan_id = license_payload.get("plan_id", "")
    plan = PLAN_INDEX.get(plan_id)
    if not plan:
        raise ValueError("License refers to an unknown plan.")
    return plan


def license_is_expired(license_payload):
    expires_at = parse_utc(license_payload.get("expires_at_utc"))
    if not expires_at:
        return False
    return expires_at < datetime.now(timezone.utc)


def receipt_is_expired(receipt_payload):
    valid_until = parse_utc(receipt_payload.get("valid_until_utc"))
    if not valid_until:
        return False
    return valid_until < datetime.now(timezone.utc)


def product_payload():
    companion_scripts = sorted(
        {
            "usb_file_locker.py",
            "privacy_safety_hub.py",
            "personal_vault_pad.py",
            "audit_log_viewer.py",
            "global_breach_guard.py",
            "text_log_processor.py",
            "locked_file_browser.py",
            "perm_unlock_workbench.py",
            "key_inspector.py",
            "quick_lock_note.py",
        }
    )
    return {
        "name": "USB File Locker",
        "api_name": API_NAME,
        "api_version": API_VERSION,
        "tagline": "USB-key file locking, personal vault tools, signed audit tracking, and API-backed licensing.",
        "desktop_scripts": companion_scripts,
        "updated_at_utc": utc_now(),
    }


def docs_payload():
    return {
        "service": API_NAME,
        "version": API_VERSION,
        "license_mode": "signed_stateless_tokens",
        "routes": [
            {"method": "GET", "path": "/", "purpose": "HTML homepage"},
            {"method": "GET", "path": "/docs", "purpose": "JSON route index"},
            {"method": "GET", "path": "/health", "purpose": "Health check"},
            {"method": "GET", "path": "/api/v1/product", "purpose": "Product metadata"},
            {"method": "GET", "path": "/api/v1/features", "purpose": "Feature catalog"},
            {"method": "GET", "path": "/api/v1/companions", "purpose": "Companion app catalog"},
            {"method": "GET", "path": "/api/v1/plans", "purpose": "Plan and entitlement catalog"},
            {"method": "GET", "path": "/api/v1/security", "purpose": "Public security and licensing notes"},
            {"method": "GET", "path": "/api/v1/deploy", "purpose": "Railway deploy hints"},
            {"method": "POST", "path": "/api/v1/licenses/issue", "purpose": "Admin-only license issuance"},
            {"method": "POST", "path": "/api/v1/licenses/activate", "purpose": "Machine-bound license activation"},
            {"method": "POST", "path": "/api/v1/licenses/verify", "purpose": "License and receipt verification"},
            {"method": "POST", "path": "/api/v1/audit-exports", "purpose": "Upload a privacy-safe audit report from a licensed machine"},
            {"method": "GET", "path": "/api/v1/audit-exports/{export_id}/download", "purpose": "Download an audit export with a short-lived bearer token"},
        ],
        "required_env": [
            {"name": "PORT", "required": False, "purpose": "HTTP bind port on Railway or local runs"},
            {"name": "LICENSE_SIGNING_SECRET", "required": True, "purpose": "HMAC secret for license keys and activation receipts"},
            {"name": "LICENSE_ADMIN_TOKEN", "required": True, "purpose": "Admin-only token required for issuing new licenses"},
            {"name": "AUDIT_EXPORT_DIR", "required": False, "purpose": "Persistent audit-export folder; mount a Railway Volume here for durable retention"},
            {"name": "AUDIT_EXPORT_RETENTION_HOURS", "required": False, "purpose": "Signed export lifetime from 1 to 168 hours; default 24"},
        ],
    }


def homepage_html():
    product = product_payload()
    feature_html = "".join(
        f"<li><strong>{item['title']}</strong><br>{item['summary']}</li>"
        for item in FEATURES[:8]
    )
    app_html = "".join(
        f"<li><strong>{item['name']}</strong><br>{item['purpose']}</li>"
        for item in COMPANION_APPS[:6]
    )
    security_html = "".join(f"<li>{line}</li>" for line in SECURITY_NOTES)
    plan_html = "".join(
        f"<li><strong>{item['name']}</strong><br>{item['best_for']}</li>"
        for item in public_plans()
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
        <a href="/api/v1/plans">Plans JSON</a>
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


def public_plans():
    return [public_plan_payload(item) for item in sorted(PLAN_TIERS, key=lambda item: item["rank"])]


def require_json_object(payload):
    if not isinstance(payload, dict):
        raise ValueError("Body must be a JSON object.")
    return payload


def issue_license(payload):
    plan_id = str(payload.get("plan_id", "")).strip().lower()
    if plan_id not in PLAN_INDEX:
        raise ValueError("Choose a valid plan id.")
    expires_at = parse_utc(payload.get("expires_at_utc"))
    if expires_at and expires_at <= datetime.now(timezone.utc):
        raise ValueError("expires_at_utc must be in the future.")
    max_devices = int(payload.get("max_devices", 1) or 1)
    if max_devices < 1 or max_devices > 1000:
        raise ValueError("max_devices must be between 1 and 1000.")
    plan = PLAN_INDEX[plan_id]
    license_payload = {
        "license_id": payload.get("license_id") or f"LIC-{secrets.token_hex(8).upper()}",
        "product": "USB File Locker",
        "plan_id": plan["id"],
        "plan_name": plan["name"],
        "entitlements": plan_entitlements(plan["id"]),
        "customer_label": str(payload.get("customer_label", "")).strip(),
        "customer_email": str(payload.get("customer_email", "")).strip(),
        "issued_at_utc": utc_now(),
        "expires_at_utc": format_utc(expires_at) if expires_at else "",
        "max_devices": max_devices,
        "issuer": API_NAME,
    }
    license_key = sign_token(LICENSE_KEY_PREFIX, license_payload)
    return {
        "ok": True,
        "issued": True,
        "license_key": license_key,
        "license": license_payload,
        "plan": public_plan_payload(plan),
        "server_time_utc": utc_now(),
        "limitations": [
            "This API currently uses stateless signed tokens.",
            "Strict seat enforcement needs a database-backed activation ledger later.",
        ],
    }


def activate_license(payload):
    license_key = str(payload.get("license_key", "")).strip()
    machine_id = str(payload.get("machine_id", "")).strip()
    machine_name = str(payload.get("machine_name", "")).strip()
    if not license_key:
        raise ValueError("license_key is required.")
    if not machine_id:
        raise ValueError("machine_id is required.")
    license_payload = verify_token(license_key, LICENSE_KEY_PREFIX)
    if license_is_expired(license_payload):
        plan = current_plan_for_license(license_payload)
        return {
            "ok": True,
            "active": False,
            "status": "expired",
            "plan": public_plan_payload(plan),
            "license": {
                "license_id": license_payload.get("license_id", ""),
                "plan_id": plan["id"],
                "plan_name": plan["name"],
                "expires_at_utc": license_payload.get("expires_at_utc", ""),
            },
            "message": "This license has expired.",
            "server_time_utc": utc_now(),
        }
    plan = current_plan_for_license(license_payload)
    activated_at = datetime.now(timezone.utc)
    valid_until = activated_at + timedelta(days=30)
    receipt_payload = {
        "receipt_id": f"RCT-{secrets.token_hex(8).upper()}",
        "license_id": license_payload.get("license_id", ""),
        "plan_id": plan["id"],
        "machine_id": machine_id,
        "machine_name": machine_name,
        "activated_at_utc": format_utc(activated_at),
        "valid_until_utc": format_utc(valid_until),
        "app_version": str(payload.get("app_version", "")).strip(),
    }
    receipt = sign_token(LICENSE_RECEIPT_PREFIX, receipt_payload)
    return {
        "ok": True,
        "active": True,
        "status": "active",
        "plan": public_plan_payload(plan),
        "license": {
            "license_id": license_payload.get("license_id", ""),
            "plan_id": plan["id"],
            "plan_name": plan["name"],
            "expires_at_utc": license_payload.get("expires_at_utc", ""),
            "customer_label": license_payload.get("customer_label", ""),
            "customer_email": license_payload.get("customer_email", ""),
        },
        "activation": receipt_payload,
        "receipt": receipt,
        "server_time_utc": utc_now(),
    }


def verify_license(payload):
    license_key = str(payload.get("license_key", "")).strip()
    machine_id = str(payload.get("machine_id", "")).strip()
    receipt = str(payload.get("receipt", "")).strip()
    if not license_key:
        raise ValueError("license_key is required.")
    if not machine_id:
        raise ValueError("machine_id is required.")
    license_payload = verify_token(license_key, LICENSE_KEY_PREFIX)
    plan = current_plan_for_license(license_payload)
    license_view = {
        "license_id": license_payload.get("license_id", ""),
        "plan_id": plan["id"],
        "plan_name": plan["name"],
        "expires_at_utc": license_payload.get("expires_at_utc", ""),
        "customer_label": license_payload.get("customer_label", ""),
        "customer_email": license_payload.get("customer_email", ""),
    }
    if license_is_expired(license_payload):
        return {
            "ok": True,
            "active": False,
            "status": "expired",
            "plan": public_plan_payload(plan),
            "license": license_view,
            "message": "This license has expired.",
            "server_time_utc": utc_now(),
        }
    if not receipt:
        return {
            "ok": True,
            "active": False,
            "status": "activation_required",
            "plan": public_plan_payload(plan),
            "license": license_view,
            "message": "Activate this license on this PC to get a machine-bound receipt.",
            "server_time_utc": utc_now(),
        }
    receipt_payload = verify_token(receipt, LICENSE_RECEIPT_PREFIX)
    if receipt_payload.get("license_id") != license_payload.get("license_id"):
        return {
            "ok": True,
            "active": False,
            "status": "receipt_mismatch",
            "plan": public_plan_payload(plan),
            "license": license_view,
            "message": "The saved activation receipt belongs to a different license.",
            "server_time_utc": utc_now(),
        }
    if receipt_payload.get("machine_id") != machine_id:
        return {
            "ok": True,
            "active": False,
            "status": "wrong_machine",
            "plan": public_plan_payload(plan),
            "license": license_view,
            "message": "The saved activation receipt belongs to a different PC.",
            "server_time_utc": utc_now(),
        }
    if receipt_is_expired(receipt_payload):
        return {
            "ok": True,
            "active": False,
            "status": "receipt_expired",
            "plan": public_plan_payload(plan),
            "license": license_view,
            "activation": receipt_payload,
            "message": "The saved activation receipt expired. Activate again on this PC.",
            "server_time_utc": utc_now(),
        }
    return {
        "ok": True,
        "active": True,
        "status": "active",
        "plan": public_plan_payload(plan),
        "license": license_view,
        "activation": receipt_payload,
        "server_time_utc": utc_now(),
    }


def clean_audit_text(value, limit):
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    return " ".join(text.split())[:limit]


def clean_audit_hash(value):
    text = clean_audit_text(value, 64).lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        return ""
    return text


def clean_audit_event(record):
    if not isinstance(record, dict):
        raise ValueError("Every audit event must be a JSON object.")
    try:
        sequence = max(int(record.get("sequence", 0)), 0)
    except (TypeError, ValueError):
        sequence = 0
    result = clean_audit_text(record.get("result"), 16).lower()
    if result not in {"success", "failure"}:
        result = "unknown"
    return {
        "sequence": sequence,
        "time_utc": clean_audit_text(record.get("time_utc"), 32),
        "event_id": clean_audit_text(record.get("event_id"), 64),
        "action": clean_audit_text(record.get("action"), 80),
        "result": result,
        "hash": clean_audit_hash(record.get("hash")),
        "previous_hash": clean_audit_hash(record.get("previous_hash")),
    }


def clean_audit_section(section, remaining_events):
    if not isinstance(section, dict):
        section = {}
    events = section.get("events", [])
    if not isinstance(events, list):
        raise ValueError("Audit report events must be a JSON array.")
    if len(events) > remaining_events:
        raise ValueError(f"Audit report exceeds the {MAX_AUDIT_EVENTS} event limit.")
    safe_events = [clean_audit_event(record) for record in events]
    return {
        "valid": bool(section.get("valid")),
        "event_count": len(safe_events),
        "verification": clean_audit_text(section.get("verification"), 300),
        "events": safe_events,
    }


def clean_defender_status(status):
    if not isinstance(status, dict):
        return {"available": False}
    safe = {"available": bool(status.get("available"))}
    for name in (
        "AntivirusEnabled",
        "RealTimeProtectionEnabled",
        "BehaviorMonitorEnabled",
        "IoavProtectionEnabled",
        "ProtectedNow",
    ):
        if name in status:
            safe[name] = bool(status.get(name))
    for name in (
        "AntivirusSignatureLastUpdated",
        "QuickScanAge",
        "FullScanAge",
        "LastQuickScanSource",
        "LastFullScanSource",
    ):
        if name in status:
            safe[name] = clean_audit_text(status.get(name), 80)
    return safe


def clean_audit_report(report):
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object.")
    usb_section = clean_audit_section(report.get("usb_file_locker_audit"), MAX_AUDIT_EVENTS)
    remaining = MAX_AUDIT_EVENTS - len(usb_section["events"])
    safety_section = clean_audit_section(report.get("pc_safety_check_audit"), remaining)
    limitations = report.get("limitations", [])
    if not isinstance(limitations, list):
        limitations = []
    return {
        "report_type": "Privacy Safety Audit Report",
        "exported_at_utc": clean_audit_text(report.get("exported_at_utc"), 32),
        "privacy_notice": (
            "This report contains no keystrokes, passwords, PINs, USB secrets, "
            "file contents, client names, or full file paths."
        ),
        "defender_status": clean_defender_status(report.get("defender_status")),
        "usb_file_locker_audit": usb_section,
        "pc_safety_check_audit": safety_section,
        "limitations": [clean_audit_text(item, 240) for item in limitations[:10]],
    }


def require_active_audit_license(payload):
    try:
        verification = verify_license(payload)
    except ValueError as exc:
        raise PermissionError(f"License verification failed: {exc}") from exc
    if not verification.get("active"):
        message = verification.get("message") or "An active machine license is required."
        raise PermissionError(message)
    entitlements = set((verification.get("plan") or {}).get("entitlements", []))
    if "audit-log-viewer" not in entitlements:
        raise PermissionError("This license plan does not include API audit exports.")
    return verification


def audit_storage_is_persistent():
    return bool(os.getenv("AUDIT_EXPORT_DIR", "").strip())


def valid_audit_export_id(export_id):
    text = str(export_id or "").strip()
    return (
        text.startswith("AUD-")
        and 8 <= len(text) <= 64
        and all(character.isalnum() or character in {"-", "_"} for character in text)
    )


def audit_export_path(export_id):
    if not valid_audit_export_id(export_id):
        raise ValueError("Invalid audit export id.")
    return AUDIT_EXPORT_DIR / f"{export_id}.json"


def cleanup_expired_audit_exports():
    if not AUDIT_EXPORT_DIR.exists():
        return
    cutoff = datetime.now(timezone.utc).timestamp() - (AUDIT_EXPORT_RETENTION_HOURS + 1) * 3600
    for path in AUDIT_EXPORT_DIR.glob("AUD-*.json"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
        except OSError:
            continue


def write_private_audit_export(path, payload):
    AUDIT_EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(AUDIT_EXPORT_DIR, 0o700)
    except OSError:
        pass
    body = json_bytes(payload)
    if len(body) > MAX_AUDIT_REPORT_BYTES:
        raise ValueError("The privacy-safe audit report is too large to store.")
    temp_path = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        with temp_path.open("xb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp_path, 0o600)
        except OSError:
            pass
        os.replace(temp_path, path)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
    return body


def create_audit_export(payload):
    verification = require_active_audit_license(payload)
    report = clean_audit_report(payload.get("report"))
    cleanup_expired_audit_exports()
    export_id = f"AUD-{secrets.token_hex(12).upper()}"
    uploaded_at = datetime.now(timezone.utc)
    expires_at = uploaded_at + timedelta(hours=AUDIT_EXPORT_RETENTION_HOURS)
    machine_id = str(payload.get("machine_id", "")).strip()
    machine_hash = hashlib.sha256(machine_id.encode("utf-8")).hexdigest()[:16]
    license_view = verification.get("license") or {}
    plan = verification.get("plan") or {}
    stored = {
        "schema_version": 1,
        "export_id": export_id,
        "uploaded_at_utc": format_utc(uploaded_at),
        "expires_at_utc": format_utc(expires_at),
        "source": {
            "license_id": clean_audit_text(license_view.get("license_id"), 80),
            "plan_id": clean_audit_text(plan.get("id"), 40),
            "machine_hash": machine_hash,
            "app_version": clean_audit_text(payload.get("app_version"), 40),
        },
        "report": report,
    }
    path = audit_export_path(export_id)
    body = write_private_audit_export(path, stored)
    token = sign_token(
        AUDIT_DOWNLOAD_PREFIX,
        {
            "export_id": export_id,
            "machine_hash": machine_hash,
            "expires_at_utc": format_utc(expires_at),
        },
    )
    filename = f"vaultlink-audit-{export_id}.json"
    return {
        "ok": True,
        "created": True,
        "export_id": export_id,
        "filename": filename,
        "download_path": f"/api/v1/audit-exports/{export_id}/download",
        "download_token": token,
        "expires_at_utc": format_utc(expires_at),
        "retention_hours": AUDIT_EXPORT_RETENTION_HOURS,
        "storage": "persistent_configured" if audit_storage_is_persistent() else "local_ephemeral",
        "size_bytes": len(body),
        "event_count": (
            report["usb_file_locker_audit"]["event_count"]
            + report["pc_safety_check_audit"]["event_count"]
        ),
        "server_time_utc": utc_now(),
    }


def load_audit_export_download(export_id, token):
    if not token:
        raise PermissionError("The signed audit download token is required.")
    try:
        token_payload = verify_token(token, AUDIT_DOWNLOAD_PREFIX)
    except ValueError as exc:
        raise PermissionError(f"Audit download token did not verify: {exc}") from exc
    if token_payload.get("export_id") != export_id:
        raise PermissionError("Audit download token does not match this export.")
    expires_at = parse_utc(token_payload.get("expires_at_utc"))
    if not expires_at or expires_at <= datetime.now(timezone.utc):
        try:
            audit_export_path(export_id).unlink(missing_ok=True)
        except OSError:
            pass
        raise PermissionError("This audit download link has expired.")
    path = audit_export_path(export_id)
    if not path.exists():
        raise FileNotFoundError("The audit export was not found or the server restarted.")
    body = path.read_bytes()
    if len(body) > MAX_AUDIT_REPORT_BYTES:
        raise ValueError("Stored audit export is too large.")
    return body, f"vaultlink-audit-{export_id}.json"


class ApiHandler(BaseHTTPRequestHandler):
    def send_json(self, payload, status=HTTPStatus.OK):
        body = json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html, status=HTTPStatus.OK):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_download(self, body, filename):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length < 0 or length > MAX_JSON_BODY_BYTES:
            raise ValueError("Request body is too large.")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return require_json_object(json.loads(raw.decode("utf-8")))
        except UnicodeDecodeError as exc:
            raise ValueError("Body must be valid UTF-8 JSON.") from exc
        except json.JSONDecodeError as exc:
            raise ValueError("Body must be valid JSON.") from exc

    def require_admin_token(self, payload):
        configured = os.getenv("LICENSE_ADMIN_TOKEN", "").strip()
        if not configured:
            raise PermissionError("LICENSE_ADMIN_TOKEN is not configured on this server.")
        provided = (
            self.headers.get("X-License-Admin-Token", "").strip()
            or str(payload.get("admin_token", "")).strip()
        )
        if not provided or not hmac.compare_digest(provided, configured):
            raise PermissionError("Admin token was missing or incorrect.")

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
            self.send_json(
                {
                    "ok": True,
                    "service": API_NAME,
                    "version": API_VERSION,
                    "time_utc": utc_now(),
                    "license_admin_configured": admin_token_configured(),
                    "using_default_signing_secret": using_default_signing_secret(),
                    "audit_exports_enabled": True,
                    "audit_export_storage": (
                        "persistent_configured" if audit_storage_is_persistent() else "local_ephemeral"
                    ),
                    "audit_export_retention_hours": AUDIT_EXPORT_RETENTION_HOURS,
                }
            )
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
            self.send_json({"items": public_plans(), "count": len(PLAN_TIERS)})
            return
        if path == "/api/v1/security":
            self.send_json(
                {
                    "license_mode": "signed_stateless_tokens",
                    "notes": SECURITY_NOTES,
                    "remote_actions_allowed": [
                        "admin license issue",
                        "license activate",
                        "license verify",
                        "license-authenticated privacy-safe audit export upload",
                        "signed short-lived audit export download",
                    ],
                    "banned_remote_actions": [
                        "remote unlock",
                        "remote key creation",
                        "remote PIN capture",
                        "remote file reads",
                        "remote vault secret retrieval",
                    ],
                    "license_limitations": [
                        "Receipt signing works without a database.",
                        "Strict seat counting and revocation lists need persistent storage later.",
                    ],
                    "audit_export_controls": [
                        "Only approved privacy-safe fields are retained.",
                        "Upload requires an active machine-bound license with Audit Log Viewer access.",
                        "Downloads require a signed expiring bearer link.",
                        "Configure AUDIT_EXPORT_DIR on a Railway Volume for restart-safe retention.",
                    ],
                }
            )
            return
        if path == "/api/v1/deploy":
            self.send_json(
                {
                    "provider": "Railway",
                    "root_directory": "/",
                    "start_command": "python main.py",
                    "port_env": os.getenv("PORT", "8000"),
                    "recommended_env": [
                        "LICENSE_SIGNING_SECRET",
                        "LICENSE_ADMIN_TOKEN",
                        "AUDIT_EXPORT_DIR",
                        "AUDIT_EXPORT_RETENTION_HOURS",
                    ],
                }
            )
            return
        parts = path.strip("/").split("/")
        if (
            len(parts) == 5
            and parts[:3] == ["api", "v1", "audit-exports"]
            and parts[4] == "download"
        ):
            try:
                authorization = self.headers.get("Authorization", "").strip()
                token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
                if not token:
                    token = self.headers.get("X-Audit-Download-Token", "").strip()
                body, filename = load_audit_export_download(parts[3], token)
                self.send_download(body, filename)
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except FileNotFoundError as exc:
                self.send_json(
                    {"ok": False, "error": "not_found", "message": str(exc)},
                    status=HTTPStatus.NOT_FOUND,
                )
            except ValueError as exc:
                self.send_json(
                    {"ok": False, "error": "bad_request", "message": str(exc)},
                    status=HTTPStatus.BAD_REQUEST,
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

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        try:
            payload = self.read_json()
            if path == "/api/v1/licenses/issue":
                self.require_admin_token(payload)
                self.send_json(issue_license(payload), status=HTTPStatus.CREATED)
                return
            if path == "/api/v1/licenses/activate":
                self.send_json(activate_license(payload))
                return
            if path == "/api/v1/licenses/verify":
                self.send_json(verify_license(payload))
                return
            if path == "/api/v1/audit-exports":
                self.send_json(create_audit_export(payload), status=HTTPStatus.CREATED)
                return
            self.send_json(
                {
                    "error": "not_found",
                    "message": "Route not found.",
                    "docs": "/docs",
                },
                status=HTTPStatus.NOT_FOUND,
            )
        except PermissionError as exc:
            self.send_json(
                {
                    "ok": False,
                    "error": "forbidden",
                    "message": str(exc),
                },
                status=HTTPStatus.FORBIDDEN,
            )
        except ValueError as exc:
            self.send_json(
                {
                    "ok": False,
                    "error": "bad_request",
                    "message": str(exc),
                },
                status=HTTPStatus.BAD_REQUEST,
            )
        except Exception as exc:
            self.send_json(
                {
                    "ok": False,
                    "error": "server_error",
                    "message": str(exc),
                },
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
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
