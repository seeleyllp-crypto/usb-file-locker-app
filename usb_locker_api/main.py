import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from html import escape as html_escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


API_NAME = "VaultLink API"
API_VERSION = "0.10.0"
ROOT_DIR = Path(__file__).resolve().parent
LICENSE_KEY_PREFIX = "vlk1"
LICENSE_RECEIPT_PREFIX = "vlr1"
AUDIT_DOWNLOAD_PREFIX = "vla1"
DEFAULT_SIGNING_SECRET = "vaultlink-dev-signing-secret-change-me"
UPDATE_DIR = ROOT_DIR / "updates"
UPDATE_MANIFEST_PATH = UPDATE_DIR / "windows-manifest.json"
UPDATE_SIGNING_KEY_ID = "4f8fb9b8dbffd4c0"
MAX_UPDATE_MANIFEST_BYTES = 64 * 1024
MAX_UPDATE_PACKAGE_BYTES = 50 * 1024 * 1024
MAX_LICENSE_JSON_BODY_BYTES = 64 * 1024
MAX_SUPPORT_JSON_BODY_BYTES = 32 * 1024
LICENSE_SYNC_INTERVAL_SECONDS = 60
DEVICE_LAST_SEEN_WRITE_SECONDS = 300
MAX_AUDIT_JSON_BODY_BYTES = 4 * 1024 * 1024
MAX_AUDIT_REPORT_BYTES = 3 * 1024 * 1024
MAX_AUDIT_EVENTS = 20000
MAX_AUDIT_LIST_ITEMS = 500
MAX_SIGNED_TOKEN_CHARS = 32 * 1024
ALLOWED_AUDIT_ACTIONS = frozenset(
    {
        "add_perm_unlock_items",
        "api_audit_download",
        "api_audit_list",
        "application_update",
        "audit_api_export",
        "audit_api_auto_upload",
        "audit_log_export",
        "audit_log_view",
        "audit_viewer_export_locked",
        "audit_viewer_export_raw",
        "audit_viewer_open",
        "backup_app_data",
        "backup_master_key",
        "check_lock_format",
        "compare_backup_key",
        "configuration_change",
        "create_key",
        "delete_unlocked_temp",
        "delete_unlocked_temp_after_view",
        "delete_unlocked_temp_retry",
        "delete_unlocked_temp_window",
        "export_locked_audit_report",
        "failed_access",
        "find_locked_files",
        "license_issue",
        "license_deactivate",
        "license_device_reset",
        "license_local_clear",
        "license_note_update",
        "license_restore",
        "license_revoke",
        "license_sync",
        "load_key",
        "load_recent_key",
        "lock",
        "lock_note",
        "lock_remove_original",
        "locked_file_browser_scan",
        "login",
        "open_temp_unlocked_file",
        "open_temp_unlocked_text",
        "owner_usb_removed",
        "owner_announcement_view",
        "panic_lock",
        "perm_unlock_workbench_relock",
        "perm_unlock_workbench_relock_copy",
        "perm_unlock_workbench_relock_remove",
        "quick_lock_note",
        "recovery_self_test",
        "restore_app_data",
        "save_personal_vault",
        "scan_personal_files",
        "support_ticket_submit",
        "support_ticket_view",
        "shop_open",
        "unlock",
        "unlock_double_click",
        "upgrade_legacy_lock",
        "usb_key_removed",
        "vault_delete_item",
        "vault_duplicate_item",
        "vault_export_locked",
        "vault_import_text",
        "vault_open",
        "vault_pad_delete",
        "vault_pad_duplicate",
        "vault_pad_export_locked",
        "vault_pad_import_text",
        "vault_pad_open",
        "vault_pad_save",
        "verify_locked_health",
    }
)
try:
    AUDIT_EXPORT_RETENTION_HOURS = min(
        max(int(os.getenv("AUDIT_EXPORT_RETENTION_HOURS", "168")), 1),
        2160,
    )
except ValueError:
    AUDIT_EXPORT_RETENTION_HOURS = 168
AUDIT_EXPORT_DIR = Path(
    os.getenv("AUDIT_EXPORT_DIR", str(ROOT_DIR / "data" / "audit_exports"))
).expanduser()
LICENSE_STATE_DIR = Path(
    os.getenv("LICENSE_STATE_DIR", str(ROOT_DIR / "data" / "license_state"))
).expanduser()
MAX_LICENSE_NOTE_CHARS = 2000
MAX_LICENSE_RECORDS = 500
LICENSE_RECORD_AAD = b"VaultLinkLicenseRecordV1"
SUPPORT_TICKET_AAD = b"VaultLinkSupportTicketV1"
MAX_SUPPORT_TICKETS = 1000
MAX_SUPPORT_TICKETS_PER_DAY = 10
SUPPORT_TICKET_STATUSES = frozenset({"open", "acknowledged", "in_progress", "resolved", "closed"})
SUPPORT_TICKET_CATEGORIES = frozenset({"bug", "crash", "licensing", "update", "security", "idea", "other"})
ANNOUNCEMENT_SEVERITIES = frozenset({"info", "update", "maintenance", "security"})
MAX_ANNOUNCEMENTS = 250
LICENSE_STATE_LOCK = threading.RLock()


class RequestTooLarge(ValueError):
    pass


class UnsupportedMediaType(ValueError):
    pass


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
        "id": "home-guides",
        "title": "Home safety guides",
        "summary": "Use the home safety checklist, key-custody plan, recovery plan, and fuller home instructions.",
        "category": "home",
    },
    {
        "id": "personal-vault",
        "title": "Personal vault",
        "summary": "Store passcodes, recovery codes, account notes, and private records inside a separate encrypted vault.",
        "category": "personal-plus",
    },
    {
        "id": "locked-file-browser",
        "title": "Locked File Browser",
        "summary": "Browse and launch .locked files from a dedicated companion app.",
        "category": "personal-plus",
    },
    {
        "id": "audit-log-viewer",
        "title": "Audit Log Viewer",
        "summary": "Read, export, and verify the privacy-safe audit trail from the richer companion app.",
        "category": "personal-plus",
    },
    {
        "id": "perm-unlock",
        "title": "PERM UNLOCK workflow",
        "summary": "Edit readable working copies and relock them safely with the dedicated workflow.",
        "category": "personal-plus",
    },
    {
        "id": "personal-safety-report",
        "title": "Personal Safety Report",
        "summary": "Create an anonymous personal report covering Defender, firewall, BitLocker, and update-recency checks.",
        "category": "personal-plus",
    },
    {
        "id": "privacy-safety-hub",
        "title": "Privacy Safety Hub",
        "summary": "Open the dashboard that ties the locker toolkit together.",
        "category": "family-safety",
    },
    {
        "id": "global-breach-guard",
        "title": "Global Breach Guard",
        "summary": "Run the topmost watcher that checks the signed audit trail and raises alerts.",
        "category": "family-safety",
    },
    {
        "id": "text-log-processor",
        "title": "Text Log Processor",
        "summary": "Turn pasted audit-style text logs into cleaner summaries and counts.",
        "category": "family-safety",
    },
    {
        "id": "owner-usb-mode",
        "title": "Owner USB mode",
        "summary": "Tie a PC session to one registered owner USB and relock if that drive disappears.",
        "category": "family-safety",
    },
    {
        "id": "family-device-reports",
        "title": "Family device reports",
        "summary": "Create anonymous family device reports and a family report index without storing account names.",
        "category": "family-safety",
    },
    {
        "id": "office-readiness",
        "title": "Small Office readiness pack",
        "summary": "Build an office readiness report, evidence manifest, policy templates, and operational checklists.",
        "category": "small-office",
    },
    {
        "id": "family-office-bundle",
        "title": "Family Office evidence bundle",
        "summary": "Create multi-PC indexes, anonymous device reports, policy packs, and operational record templates.",
        "category": "family-office",
    },
    {
        "id": "signature-bundle",
        "title": "Owner-signed release bundle",
        "summary": "Verify the complete release manifest and integrity records for a professionally reviewed deployment.",
        "category": "pro-baseline",
    },
    {
        "id": "pro-baseline-pack",
        "title": "Pro Baseline review pack",
        "summary": "Use security templates, a HIPAA-readiness workspace, and professional review materials without claiming certification.",
        "category": "pro-baseline",
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
    {"name": "VaultLink License Issuer", "script": "license_issuer.py", "purpose": "Issue customer licenses through the admin-protected API."},
    {"name": "Text Log Processor", "script": "text_log_processor.py", "purpose": "Parse table-style text logs into a cleaner summary."},
    {"name": "Global Breach Guard", "script": "global_breach_guard.py", "purpose": "Run a topmost global breach watcher."},
]


SECURITY_NOTES = [
    "The public API never unlocks files, never receives USB secrets, and never stores PINs or vault contents.",
    "Desktop encryption and USB-key logic stay in the Windows app instead of moving onto the internet-facing service.",
    "Signed keys and receipts are checked against persistent revocation and anonymous device-seat ledgers.",
    "Owner license keys and private notes are encrypted at rest and available only through admin-token routes.",
    "Audit exports are reduced to privacy-safe fields, require an active licensed machine, and use short-lived signed download links.",
    "Ranks are software and service package descriptions, not HIPAA certification, legal approval, guaranteed protection, or proof of professional review.",
]


PLAN_TIERS = [
    {
        "id": "starter",
        "name": "$5 Starter",
        "price_label": "$5",
        "price_min_usd": 5,
        "price_max_usd": 5,
        "best_for": "One Windows PC and basic locking instructions",
        "rank": 1,
        "includes": [
            "Portable locking tools",
            "Quick lock notes",
            "Microsoft Defender package scan",
            "Signed purchase verification",
            "Core PIN, recovery, and audit tools",
        ],
        "features": [
            "portable-locking",
            "quick-lock-note",
        ],
    },
    {
        "id": "home",
        "name": "$10-$25 Home",
        "price_label": "$10-$25",
        "price_min_usd": 10,
        "price_max_usd": 25,
        "best_for": "A home that needs clearer setup, custody, and recovery guidance",
        "rank": 2,
        "includes": [
            "Everything in Starter",
            "Home safety checklist",
            "Home key-custody plan",
            "Home recovery plan",
            "Fuller home instructions",
        ],
        "features": [
            "home-guides",
        ],
    },
    {
        "id": "personal-plus",
        "name": "$50 Personal Plus",
        "price_label": "$50",
        "price_min_usd": 50,
        "price_max_usd": 50,
        "best_for": "Personal records plus anonymous Windows safety reporting",
        "rank": 3,
        "includes": [
            "Everything in Home",
            "Personal Vault tools",
            "Audit Log Viewer",
            "Locked File Browser",
            "PERM UNLOCK workflow",
            "Anonymous Personal Safety Report",
        ],
        "features": [
            "personal-vault",
            "audit-log-viewer",
            "locked-file-browser",
            "perm-unlock",
            "personal-safety-report",
        ],
    },
    {
        "id": "family-safety",
        "name": "$100 Family Safety",
        "price_label": "$100",
        "price_min_usd": 100,
        "price_max_usd": 100,
        "best_for": "Families managing anonymous safety records across devices",
        "rank": 4,
        "includes": [
            "Everything in Personal Plus",
            "Anonymous Family Device Reports",
            "Family Report Index",
            "Family backup and weekly procedures",
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
            "family-device-reports",
        ],
    },
    {
        "id": "small-office",
        "name": "$200 Small Office",
        "price_label": "$200",
        "price_min_usd": 200,
        "price_max_usd": 200,
        "best_for": "Small offices that need repeatable readiness and evidence workflows",
        "rank": 5,
        "includes": [
            "Everything in Family Safety",
            "Office Readiness Report",
            "SHA-256 evidence manifest",
            "Seven office policy templates",
            "Onboarding, backup, audit, and incident docs",
        ],
        "features": [
            "office-readiness",
        ],
    },
    {
        "id": "family-office",
        "name": "$500-$3,000 Family Office",
        "price_label": "$500-$3,000",
        "price_min_usd": 500,
        "price_max_usd": 3000,
        "best_for": "Multi-PC family offices needing guided setup and records",
        "rank": 6,
        "includes": [
            "Everything in Small Office",
            "Anonymous Office Device Reports",
            "Multi-PC Office Index",
            "Family Office Evidence Bundle",
            "Policy and operational record templates",
            "Adult-led setup and testing as agreed",
        ],
        "features": [
            "family-office-bundle",
        ],
    },
    {
        "id": "pro-baseline",
        "name": "$20,000+ Pro Baseline",
        "price_label": "$20,000+",
        "price_min_usd": 20000,
        "price_max_usd": None,
        "best_for": "A professionally reviewed baseline with formal evidence and policy materials",
        "rank": 7,
        "includes": [
            "Everything in Family Office",
            "Pro security and evidence reports",
            "Owner-signed release manifest",
            "Optional physical USB-bound licensing",
            "HIPAA-readiness workspace, not certification",
            "Professional and legal review materials",
        ],
        "features": [
            "signature-bundle",
            "pro-baseline-pack",
        ],
    },
]


PLAN_INDEX = {item["id"]: item for item in PLAN_TIERS}
SHOP_CHECKOUT_ENV_BY_PLAN = {
    "starter": "SHOP_CHECKOUT_STARTER_URL",
    "home": "SHOP_CHECKOUT_HOME_URL",
    "personal-plus": "SHOP_CHECKOUT_PERSONAL_PLUS_URL",
    "family-safety": "SHOP_CHECKOUT_FAMILY_SAFETY_URL",
    "small-office": "SHOP_CHECKOUT_SMALL_OFFICE_URL",
    "family-office": "SHOP_CHECKOUT_FAMILY_OFFICE_URL",
    "pro-baseline": "SHOP_CHECKOUT_PRO_BASELINE_URL",
}
DEFAULT_SHOP_CHECKOUT_HOSTS = frozenset({"buy.stripe.com", "checkout.stripe.com"})
LEGACY_PLAN_ALIASES = {
    "plus": "personal-plus",
    "pro": "family-safety",
    "signature": "small-office",
}


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


def canonical_plan_id(plan_id):
    normalized = str(plan_id or "").strip().lower()
    return LEGACY_PLAN_ALIASES.get(normalized, normalized)


def plan_entitlements(plan_id):
    plan = PLAN_INDEX.get(canonical_plan_id(plan_id))
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
        "price_label": plan["price_label"],
        "price_min_usd": plan["price_min_usd"],
        "price_max_usd": plan["price_max_usd"],
        "rank_label": f"Rank {plan['rank']}",
        "best_for": plan["best_for"],
        "rank": plan["rank"],
        "includes": list(plan["includes"]),
        "entitlements": plan_entitlements(plan["id"]),
    }


def shop_checkout_allowed_hosts():
    configured = os.getenv("SHOP_CHECKOUT_ALLOWED_HOSTS", "").strip()
    if not configured:
        return set(DEFAULT_SHOP_CHECKOUT_HOSTS)
    hosts = set()
    for item in configured.split(","):
        host = item.strip().lower().rstrip(".")
        if host and len(host) <= 253 and all(character.isalnum() or character in ".-" for character in host):
            hosts.add(host)
    return hosts or set(DEFAULT_SHOP_CHECKOUT_HOSTS)


def validated_shop_checkout_url(plan_id):
    env_name = SHOP_CHECKOUT_ENV_BY_PLAN.get(canonical_plan_id(plan_id), "")
    raw_url = os.getenv(env_name, "").strip() if env_name else ""
    if not raw_url or len(raw_url) > 2048:
        return ""
    if any(character.isspace() or ord(character) < 32 for character in raw_url):
        return ""
    try:
        parsed = urlparse(raw_url)
        port = parsed.port
    except ValueError:
        return ""
    host = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme.lower() != "https"
        or not host
        or host not in shop_checkout_allowed_hosts()
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in (None, 443)
        or parsed.path in ("", "/")
    ):
        return ""
    return raw_url


def shop_plan_payload(plan):
    payload = public_plan_payload(plan)
    checkout_url = validated_shop_checkout_url(plan["id"])
    payload.update(
        {
            "checkout_available": bool(checkout_url),
            "checkout_url": checkout_url,
            "checkout_provider": "hosted checkout",
            "fulfillment": "owner_issues_license_after_payment_confirmation",
        }
    )
    return payload


def shop_payload():
    items = [shop_plan_payload(item) for item in sorted(PLAN_TIERS, key=lambda item: item["rank"])]
    configured_count = sum(bool(item["checkout_available"]) for item in items)
    return {
        "ok": True,
        "name": "VaultLink Shop",
        "items": items,
        "count": len(items),
        "configured_count": configured_count,
        "ready": configured_count > 0,
        "payment_handling": "provider_hosted_checkout_only",
        "card_data_collected_by_vaultlink": False,
        "license_fulfillment": "manual_owner_confirmation",
        "server_time_utc": utc_now(),
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
    token_text = str(token or "").strip()
    if len(token_text) > MAX_SIGNED_TOKEN_CHARS:
        raise ValueError("Token is too large.")
    parts = token_text.split(".")
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
    plan_id = canonical_plan_id(license_payload.get("plan_id", ""))
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


def license_state_storage_is_persistent():
    return bool(os.getenv("LICENSE_STATE_DIR", "").strip())


def license_records_secret():
    return os.getenv("LICENSE_RECORDS_SECRET", "").strip() or signing_secret()


def license_record_encryption_key():
    material = ("vaultlink-license-records-v1\0" + license_records_secret()).encode("utf-8")
    return hashlib.sha256(material).digest()


def clean_license_note(value):
    text = "".join(
        character if ord(character) >= 32 and ord(character) != 127 else " "
        for character in str(value or "")
    ).strip()
    text = " ".join(text.split())
    if len(text) > MAX_LICENSE_NOTE_CHARS:
        raise ValueError(f"license_note must be {MAX_LICENSE_NOTE_CHARS} characters or fewer.")
    return text


def validated_license_id(value):
    text = str(value or "").strip()
    if not text or len(text) > 80:
        raise ValueError("license_id must be between 1 and 80 characters.")
    if any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in text):
        raise ValueError("license_id may contain only letters, numbers, hyphens, and underscores.")
    return text


def private_record_path(folder, identity):
    digest = hashlib.sha256(str(identity).encode("utf-8")).hexdigest()
    return LICENSE_STATE_DIR / folder / f"{digest}.json"


def write_private_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(LICENSE_STATE_DIR, 0o700)
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def encrypt_license_private_fields(payload):
    nonce = os.urandom(12)
    encrypted = AESGCM(license_record_encryption_key()).encrypt(
        nonce,
        canonical_json_bytes(payload),
        LICENSE_RECORD_AAD,
    )
    return b64url_encode(nonce + encrypted)


def decrypt_license_private_fields(record):
    encoded = str(record.get("private_blob", "")).strip()
    if not encoded:
        return {}
    packed = b64url_decode(encoded)
    if len(packed) < 29:
        raise ValueError("Stored private license data is damaged.")
    plain = AESGCM(license_record_encryption_key()).decrypt(
        packed[:12],
        packed[12:],
        LICENSE_RECORD_AAD,
    )
    payload = json.loads(plain.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Stored private license data is invalid.")
    return payload


def support_ticket_encryption_key():
    material = ("vaultlink-support-tickets-v1\0" + license_records_secret()).encode("utf-8")
    return hashlib.sha256(material).digest()


def encrypt_support_private_fields(payload):
    nonce = os.urandom(12)
    encrypted = AESGCM(support_ticket_encryption_key()).encrypt(
        nonce,
        canonical_json_bytes(payload),
        SUPPORT_TICKET_AAD,
    )
    return b64url_encode(nonce + encrypted)


def decrypt_support_private_fields(record):
    encoded = str(record.get("private_blob", "")).strip()
    if not encoded:
        return {}
    packed = b64url_decode(encoded)
    if len(packed) < 29:
        raise ValueError("Stored support ticket data is damaged.")
    plain = AESGCM(support_ticket_encryption_key()).decrypt(
        packed[:12],
        packed[12:],
        SUPPORT_TICKET_AAD,
    )
    payload = json.loads(plain.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Stored support ticket data is invalid.")
    return payload


def license_record_path(license_id):
    return private_record_path("licenses", license_id)


def read_license_record(license_id):
    path = license_record_path(license_id)
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("license_id") != license_id:
        raise ValueError("Stored license record identity did not verify.")
    return payload


def stored_license_private_fields(record):
    try:
        return decrypt_license_private_fields(record)
    except Exception:
        return {}


def write_license_record(license_payload, license_key, license_note="", status=None, revocation_note=None):
    license_id = validated_license_id(license_payload.get("license_id"))
    plan = current_plan_for_license(license_payload)
    existing = read_license_record(license_id) or {}
    private_fields = stored_license_private_fields(existing)
    private_fields.update(
        {
            "license_key": str(license_key or private_fields.get("license_key", "")).strip(),
            "license_note": clean_license_note(
                license_note if license_note is not None else private_fields.get("license_note", "")
            ),
            "customer_label": str(license_payload.get("customer_label", "")).strip()[:160],
            "customer_email": str(license_payload.get("customer_email", "")).strip()[:254],
        }
    )
    if revocation_note is not None:
        private_fields["revocation_note"] = clean_license_note(revocation_note)
    now = utc_now()
    selected_status = status or existing.get("status") or "active"
    record = {
        "schema_version": 1,
        "license_id": license_id,
        "plan_id": plan["id"],
        "plan_name": plan["name"],
        "issued_at_utc": str(license_payload.get("issued_at_utc", "")),
        "expires_at_utc": str(license_payload.get("expires_at_utc", "")),
        "max_devices": int(license_payload.get("max_devices", 1) or 1),
        "status": selected_status,
        "revoked_at_utc": existing.get("revoked_at_utc", ""),
        "restored_at_utc": existing.get("restored_at_utc", ""),
        "updated_at_utc": now,
        "private_blob": encrypt_license_private_fields(private_fields),
    }
    if selected_status == "revoked":
        record["revoked_at_utc"] = existing.get("revoked_at_utc") or now
    elif status == "active":
        record["restored_at_utc"] = now if existing else ""
        record["revoked_at_utc"] = ""
    write_private_json(license_record_path(license_id), record)
    return record


def license_is_revoked(license_payload):
    license_id = str(license_payload.get("license_id", "")).strip()
    if not license_id:
        return False
    record = read_license_record(license_id)
    return bool(record and record.get("status") == "revoked")


def receipt_deactivation_path(receipt):
    return private_record_path("deactivations", receipt)


def receipt_is_deactivated(receipt):
    return bool(receipt and receipt_deactivation_path(receipt).is_file())


def mark_receipt_deactivated(receipt, receipt_payload, app_version=""):
    record = {
        "schema_version": 1,
        "receipt_hash": hashlib.sha256(receipt.encode("utf-8")).hexdigest(),
        "receipt_id": str(receipt_payload.get("receipt_id", ""))[:80],
        "license_id": str(receipt_payload.get("license_id", ""))[:80],
        "machine_hash": hashlib.sha256(str(receipt_payload.get("machine_id", "")).encode("utf-8")).hexdigest()[:16],
        "deactivated_at_utc": utc_now(),
        "app_version": str(app_version or "").strip()[:80],
    }
    write_private_json(receipt_deactivation_path(receipt), record)
    return record


def anonymous_machine_hash(machine_id):
    return hashlib.sha256(str(machine_id or "").encode("utf-8")).hexdigest()[:24]


def activation_folder(license_id):
    license_digest = hashlib.sha256(str(license_id or "").encode("utf-8")).hexdigest()
    return LICENSE_STATE_DIR / "activations" / license_digest


def activation_path(license_id, machine_id):
    return activation_folder(license_id) / f"{anonymous_machine_hash(machine_id)}.json"


def read_activation_record(license_id, machine_id):
    path = activation_path(license_id, machine_id)
    if not path.is_file():
        return None
    record = json.loads(path.read_text(encoding="utf-8"))
    expected_machine_hash = anonymous_machine_hash(machine_id)
    if (
        not isinstance(record, dict)
        or record.get("license_id") != license_id
        or record.get("machine_hash") != expected_machine_hash
    ):
        raise ValueError("Stored activation record identity did not verify.")
    return record


def activation_record_is_active(record):
    if not isinstance(record, dict) or record.get("status") != "active":
        return False
    valid_until = parse_utc(record.get("valid_until_utc"))
    return valid_until is None or valid_until >= datetime.now(timezone.utc)


def activation_records(license_id):
    records = []
    folder = activation_folder(license_id)
    if not folder.is_dir():
        return records
    for path in folder.glob("*.json"):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            machine_hash = str(record.get("machine_hash", "")) if isinstance(record, dict) else ""
            if (
                isinstance(record, dict)
                and record.get("license_id") == license_id
                and machine_hash == path.stem
                and len(machine_hash) == 24
                and all(character in "0123456789abcdef" for character in machine_hash)
            ):
                records.append(record)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return records


def active_device_count(license_id):
    return sum(activation_record_is_active(record) for record in activation_records(license_id))


def validated_machine_hash(value):
    text = str(value or "").strip().lower()
    if len(text) != 24 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError("machine_hash must be a 24-character anonymous device id.")
    return text


def admin_license_devices(license_id):
    clean_license_id = validated_license_id(license_id)
    if not read_license_record(clean_license_id):
        raise FileNotFoundError("License record was not found.")
    items = []
    for record in activation_records(clean_license_id):
        items.append(
            {
                "machine_hash": str(record.get("machine_hash", "")),
                "status": str(record.get("status", "unknown")),
                "active": activation_record_is_active(record),
                "activated_at_utc": str(record.get("activated_at_utc", "")),
                "valid_until_utc": str(record.get("valid_until_utc", "")),
                "updated_at_utc": str(record.get("updated_at_utc", "")),
                "last_seen_at_utc": str(record.get("last_seen_at_utc", "")),
                "app_version": str(record.get("app_version", "")),
            }
        )
    items.sort(key=lambda item: item.get("updated_at_utc", ""), reverse=True)
    return {
        "ok": True,
        "license_id": clean_license_id,
        "count": len(items),
        "active_count": sum(bool(item.get("active")) for item in items),
        "items": items,
        "privacy": "Device ids are one-way anonymous hashes; PC names and hardware ids are not returned.",
        "server_time_utc": utc_now(),
    }


def write_activation_record(receipt, receipt_payload, status="active", status_time_field=""):
    license_id = validated_license_id(receipt_payload.get("license_id"))
    machine_id = str(receipt_payload.get("machine_id", "")).strip()
    if not machine_id:
        raise ValueError("Activation receipt is missing its machine identity.")
    now = utc_now()
    record = {
        "schema_version": 1,
        "license_id": license_id,
        "machine_hash": anonymous_machine_hash(machine_id),
        "receipt_id": str(receipt_payload.get("receipt_id", ""))[:80],
        "receipt_hash": hashlib.sha256(str(receipt or "").encode("utf-8")).hexdigest(),
        "status": status,
        "activated_at_utc": str(receipt_payload.get("activated_at_utc", "")),
        "valid_until_utc": str(receipt_payload.get("valid_until_utc", "")),
        "app_version": str(receipt_payload.get("app_version", ""))[:80],
        "updated_at_utc": now,
    }
    if status_time_field:
        record[status_time_field] = now
    write_private_json(activation_path(license_id, machine_id), record)
    return record


def register_activation_receipt(license_payload, receipt, receipt_payload):
    license_id = validated_license_id(license_payload.get("license_id"))
    machine_id = str(receipt_payload.get("machine_id", "")).strip()
    max_devices = int(license_payload.get("max_devices", 1) or 1)
    with LICENSE_STATE_LOCK:
        current = read_activation_record(license_id, machine_id)
        current_uses_seat = activation_record_is_active(current)
        used_devices = active_device_count(license_id)
        if not current_uses_seat and used_devices >= max_devices:
            return False, used_devices
        write_activation_record(receipt, receipt_payload, status="active")
        return True, used_devices if current_uses_seat else used_devices + 1


def verify_activation_receipt(license_payload, receipt, receipt_payload, app_version=""):
    license_id = validated_license_id(license_payload.get("license_id"))
    machine_id = str(receipt_payload.get("machine_id", "")).strip()
    with LICENSE_STATE_LOCK:
        record = read_activation_record(license_id, machine_id)
        if record is None:
            registered, used_devices = register_activation_receipt(
                license_payload,
                receipt,
                receipt_payload,
            )
            if not registered:
                return False, "device_limit", used_devices
            return True, "active", used_devices
        if not activation_record_is_active(record):
            return False, str(record.get("status") or "inactive"), active_device_count(license_id)
        receipt_hash = hashlib.sha256(receipt.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(str(record.get("receipt_hash", "")), receipt_hash):
            return False, "receipt_replaced", active_device_count(license_id)
        last_seen = parse_utc(record.get("last_seen_at_utc"))
        now = datetime.now(timezone.utc)
        if last_seen is None or (now - last_seen).total_seconds() >= DEVICE_LAST_SEEN_WRITE_SECONDS:
            record["last_seen_at_utc"] = format_utc(now)
            current_version = str(app_version or "").strip()[:80]
            if current_version:
                record["app_version"] = current_version
            write_private_json(activation_path(license_id, machine_id), record)
        return True, "active", active_device_count(license_id)


def deactivate_activation_record(receipt_payload):
    license_id = validated_license_id(receipt_payload.get("license_id"))
    machine_id = str(receipt_payload.get("machine_id", "")).strip()
    with LICENSE_STATE_LOCK:
        existing = read_activation_record(license_id, machine_id)
        receipt = ""
        if existing:
            receipt = str(existing.get("receipt_hash", ""))
        record = write_activation_record(receipt, receipt_payload, status="deactivated", status_time_field="deactivated_at_utc")
        if existing and existing.get("receipt_hash"):
            record["receipt_hash"] = str(existing.get("receipt_hash"))
            write_private_json(activation_path(license_id, machine_id), record)
        return record


def reset_license_devices(license_payload):
    license_id = validated_license_id(license_payload.get("license_id"))
    reset_count = 0
    with LICENSE_STATE_LOCK:
        for record in activation_records(license_id):
            if not activation_record_is_active(record):
                continue
            record["status"] = "reset"
            record["reset_at_utc"] = utc_now()
            record["updated_at_utc"] = record["reset_at_utc"]
            path = activation_folder(license_id) / f"{record.get('machine_hash', '')}.json"
            write_private_json(path, record)
            reset_count += 1
    return reset_count


def masked_license_key(value):
    text = str(value or "").strip()
    if len(text) < 18:
        return text
    return f"{text[:8]}...{text[-6:]}"


def admin_license_record_view(record, include_private=True):
    private_fields = stored_license_private_fields(record) if include_private else {}
    license_key = str(private_fields.get("license_key", ""))
    license_id = str(record.get("license_id", ""))
    return {
        "license_id": license_id,
        "plan_id": str(record.get("plan_id", "")),
        "plan_name": str(record.get("plan_name", "")),
        "status": str(record.get("status", "active")),
        "issued_at_utc": str(record.get("issued_at_utc", "")),
        "expires_at_utc": str(record.get("expires_at_utc", "")),
        "max_devices": int(record.get("max_devices", 1) or 1),
        "active_devices": active_device_count(license_id),
        "revoked_at_utc": str(record.get("revoked_at_utc", "")),
        "restored_at_utc": str(record.get("restored_at_utc", "")),
        "updated_at_utc": str(record.get("updated_at_utc", "")),
        "license_key": license_key,
        "masked_license_key": masked_license_key(license_key),
        "license_note": str(private_fields.get("license_note", "")),
        "revocation_note": str(private_fields.get("revocation_note", "")),
        "customer_label": str(private_fields.get("customer_label", "")),
        "customer_email": str(private_fields.get("customer_email", "")),
        "private_data_available": bool(private_fields),
    }


def list_admin_license_records():
    folder = LICENSE_STATE_DIR / "licenses"
    records = []
    if folder.is_dir():
        for path in sorted(folder.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(record, dict) and record.get("license_id"):
                    records.append(admin_license_record_view(record))
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if len(records) >= MAX_LICENSE_RECORDS:
                break
    return {
        "ok": True,
        "count": len(records),
        "items": records,
        "storage": "persistent_configured" if license_state_storage_is_persistent() else "local_ephemeral",
        "private_fields_encrypted": True,
        "server_time_utc": utc_now(),
    }


def product_payload():
    companion_scripts = sorted(
        {
            "usb_file_locker.py",
            "privacy_safety_hub.py",
            "personal_vault_pad.py",
            "audit_log_viewer.py",
            "license_issuer.py",
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
        "license_mode": "signed_tokens_with_revocation_ledger",
        "routes": [
            {"method": "GET", "path": "/", "purpose": "HTML homepage"},
            {"method": "GET", "path": "/shop", "purpose": "Public seven-tier shop with provider-hosted checkout"},
            {"method": "GET", "path": "/owner", "purpose": "Owner-only key and note web console"},
            {"method": "GET", "path": "/docs", "purpose": "JSON route index"},
            {"method": "GET", "path": "/health", "purpose": "Health check"},
            {"method": "GET", "path": "/api/v1/product", "purpose": "Product metadata"},
            {"method": "GET", "path": "/api/v1/features", "purpose": "Feature catalog"},
            {"method": "GET", "path": "/api/v1/companions", "purpose": "Companion app catalog"},
            {"method": "GET", "path": "/api/v1/plans", "purpose": "Plan and entitlement catalog"},
            {"method": "GET", "path": "/api/v1/ranks", "purpose": "Complete ordered license-rank comparison"},
            {"method": "GET", "path": "/api/v1/shop", "purpose": "Public shop readiness and validated checkout links"},
            {"method": "GET", "path": "/api/v1/security", "purpose": "Public security and licensing notes"},
            {"method": "GET", "path": "/api/v1/deploy", "purpose": "Railway deploy hints"},
            {"method": "POST", "path": "/api/v1/licenses/issue", "purpose": "Admin-only license issuance"},
            {"method": "POST", "path": "/api/v1/licenses/activate", "purpose": "Machine-bound license activation"},
            {"method": "POST", "path": "/api/v1/licenses/verify", "purpose": "License and receipt verification"},
            {"method": "POST", "path": "/api/v1/licenses/sync", "purpose": "Automatic client heartbeat with revocation, seat, release, and sync policy"},
            {"method": "POST", "path": "/api/v1/licenses/deactivate", "purpose": "Remove the current machine activation"},
            {"method": "POST", "path": "/api/v1/licenses/revoke", "purpose": "Admin-only license revocation"},
            {"method": "POST", "path": "/api/v1/licenses/restore", "purpose": "Admin-only license restoration"},
            {"method": "POST", "path": "/api/v1/licenses/note", "purpose": "Admin-only private note update"},
            {"method": "POST", "path": "/api/v1/licenses/reset-devices", "purpose": "Admin-only reset of active device seats"},
            {"method": "POST", "path": "/api/v1/licenses/remove-device", "purpose": "Admin-only removal of one anonymous device seat"},
            {"method": "GET", "path": "/api/v1/admin/licenses", "purpose": "Admin-only encrypted key and note inventory"},
            {"method": "GET", "path": "/api/v1/admin/licenses/{license_id}/devices", "purpose": "Admin-only anonymous device-seat inventory"},
            {"method": "GET", "path": "/api/v1/admin/dashboard", "purpose": "Admin-only license, device, audit, breach, and release totals"},
            {"method": "POST", "path": "/api/v1/support-tickets", "purpose": "Licensed privacy-safe customer bug report submission"},
            {"method": "POST", "path": "/api/v1/support-tickets/mine", "purpose": "Licensed customer ticket status and owner replies"},
            {"method": "GET", "path": "/api/v1/admin/support-tickets", "purpose": "Admin-only encrypted support inbox"},
            {"method": "POST", "path": "/api/v1/admin/support-tickets/action", "purpose": "Admin-only acknowledge, resolve, close, note, and reply action"},
            {"method": "POST", "path": "/api/v1/admin/support-tickets/delete", "purpose": "Admin-only permanent support-ticket deletion"},
            {"method": "POST", "path": "/api/v1/announcements/mine", "purpose": "Licensed read-only owner announcements for this plan rank"},
            {"method": "GET", "path": "/api/v1/admin/announcements", "purpose": "Admin-only announcement inventory"},
            {"method": "POST", "path": "/api/v1/admin/announcements/create", "purpose": "Admin-only rank-targeted announcement publishing"},
            {"method": "POST", "path": "/api/v1/admin/announcements/delete", "purpose": "Admin-only announcement deletion"},
            {"method": "POST", "path": "/api/v1/audit-exports", "purpose": "Upload a privacy-safe audit report from a licensed machine"},
            {"method": "GET", "path": "/api/v1/audit-exports/{export_id}/download", "purpose": "Download an audit export with a short-lived bearer token"},
            {"method": "GET", "path": "/api/v1/admin/audit-exports", "purpose": "Admin-only list of stored audit reports and breach levels"},
            {"method": "GET", "path": "/api/v1/admin/audit-exports/{export_id}/download", "purpose": "Admin-only stored audit report download"},
            {"method": "POST", "path": "/api/v1/admin/audit-exports/download-link", "purpose": "Admin-only two-minute report-scoped browser download link"},
            {"method": "GET", "path": "/api/v1/updates/windows", "purpose": "Signed Windows desktop update manifest and compatibility data"},
            {"method": "GET", "path": "/api/v1/updates/windows/download", "purpose": "SHA-256-pinned Windows desktop update package"},
        ],
        "required_env": [
            {"name": "PORT", "required": False, "purpose": "HTTP bind port on Railway or local runs"},
            {"name": "LICENSE_SIGNING_SECRET", "required": True, "purpose": "HMAC secret for license keys and activation receipts"},
            {"name": "LICENSE_ADMIN_TOKEN", "required": True, "purpose": "Admin-only token required for issuing new licenses"},
            {"name": "LICENSE_STATE_DIR", "required": False, "purpose": "Persistent revocation and encrypted license-record folder; mount a Railway Volume here"},
            {"name": "LICENSE_RECORDS_SECRET", "required": False, "purpose": "Separate encryption secret for saved owner keys and private notes; defaults to the signing secret"},
            {"name": "AUDIT_EXPORT_DIR", "required": False, "purpose": "Persistent audit-export folder; mount a Railway Volume here for durable retention"},
            {"name": "AUDIT_EXPORT_RETENTION_HOURS", "required": False, "purpose": "Stored export lifetime from 1 to 2160 hours; default 168"},
            {"name": "SHOP_CHECKOUT_*_URL", "required": False, "purpose": "Provider-hosted HTTPS checkout URL for each plan; missing tiers stay unavailable"},
            {"name": "SHOP_CHECKOUT_ALLOWED_HOSTS", "required": False, "purpose": "Comma-separated checkout host allowlist; defaults to Stripe hosted-checkout domains"},
        ],
        "request_limits": {
            "license_routes_bytes": MAX_LICENSE_JSON_BODY_BYTES,
            "audit_export_route_bytes": MAX_AUDIT_JSON_BODY_BYTES,
            "audit_events": MAX_AUDIT_EVENTS,
        },
    }


def update_file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def load_windows_update_release():
    if not UPDATE_MANIFEST_PATH.exists():
        raise FileNotFoundError("No Windows update release is published.")
    raw = UPDATE_MANIFEST_PATH.read_bytes()
    if len(raw) > MAX_UPDATE_MANIFEST_BYTES:
        raise ValueError("The update manifest is too large.")
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("The update manifest is invalid.") from exc
    if not isinstance(manifest, dict):
        raise ValueError("The update manifest must be a JSON object.")
    allowed_fields = {
        "schema_version",
        "product",
        "platform",
        "version",
        "minimum_supported_version",
        "published_at_utc",
        "package_filename",
        "download_path",
        "sha256",
        "size_bytes",
        "signing_key_id",
        "notes",
        "preserves_local_app_data",
        "signature",
    }
    if set(manifest) != allowed_fields:
        raise ValueError("The update manifest field set is invalid.")
    if manifest.get("schema_version") != 1:
        raise ValueError("The update manifest schema is not supported.")
    if manifest.get("product") != "USB File Locker" or manifest.get("platform") != "windows-source":
        raise ValueError("The update manifest is for a different product or platform.")
    for field in ("version", "minimum_supported_version"):
        value = str(manifest.get(field, ""))
        if not value or len(value) > 40 or any(part == "" or not part.isdigit() for part in value.split(".")):
            raise ValueError(f"The update manifest {field} is invalid.")
    if clean_audit_time(manifest.get("published_at_utc")) != manifest.get("published_at_utc"):
        raise ValueError("The update manifest timestamp is invalid.")
    filename = str(manifest.get("package_filename", ""))
    if not filename.endswith(".zip") or Path(filename).name != filename or len(filename) > 120:
        raise ValueError("The update package filename is invalid.")
    if manifest.get("download_path") != "/api/v1/updates/windows/download":
        raise ValueError("The update download path is invalid.")
    expected_hash = str(manifest.get("sha256", "")).lower()
    if len(expected_hash) != 64 or any(character not in "0123456789abcdef" for character in expected_hash):
        raise ValueError("The update package SHA-256 is invalid.")
    package_path = UPDATE_DIR / filename
    if not package_path.exists() or not package_path.is_file():
        raise FileNotFoundError("The published update package is missing.")
    size_bytes = package_path.stat().st_size
    if not 0 < size_bytes <= MAX_UPDATE_PACKAGE_BYTES or int(manifest.get("size_bytes", 0)) != size_bytes:
        raise ValueError("The update package size does not match its manifest.")
    if not hmac.compare_digest(update_file_sha256(package_path), expected_hash):
        raise ValueError("The update package hash does not match its manifest.")
    notes = manifest.get("notes")
    if not isinstance(notes, list) or len(notes) > 12 or any(not isinstance(note, str) or len(note) > 240 for note in notes):
        raise ValueError("The update release notes are invalid.")
    if not manifest.get("preserves_local_app_data"):
        raise ValueError("The update package does not declare app-data preservation.")
    signature = str(manifest.get("signature", ""))
    if manifest.get("signing_key_id") != UPDATE_SIGNING_KEY_ID:
        raise ValueError("The update manifest signing key is not recognized.")
    if not 40 <= len(signature) <= 160 or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in signature):
        raise ValueError("The update manifest signature format is invalid.")
    return manifest, package_path


def windows_update_payload():
    manifest, _package_path = load_windows_update_release()
    return {
        "ok": True,
        "api_version": API_VERSION,
        "update": manifest,
        "security": {
            "manifest_signature": "Ed25519",
            "package_integrity": "SHA-256",
            "automatic_install_requires_user_confirmation": True,
        },
        "server_time_utc": utc_now(),
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
        (
            f"<article class=\"rank-card rank-{item['rank']}\">"
            f"<div class=\"rank-number\">RANK {item['rank']}</div>"
            f"<h3>{item['name']}</h3>"
            f"<p>{item['best_for']}</p>"
            f"<ul>{''.join(f'<li>{included}</li>' for included in item['includes'])}</ul>"
            f"<div class=\"rank-total\">{len(item['entitlements'])} total entitlements</div>"
            "</article>"
        )
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
      background: var(--bg);
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
      background: #161a20;
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
    .rank-section {{
      margin-top: 24px;
      padding: 22px 0 2px;
    }}
    .rank-section h2 {{
      margin: 0 0 6px;
      font-size: 1.45rem;
    }}
    .rank-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
      margin-top: 16px;
    }}
    .rank-card {{
      min-width: 0;
      background: var(--panel);
      border: 1px solid var(--line);
      border-top: 4px solid var(--accent);
      border-radius: 8px;
      padding: 18px;
    }}
    .rank-card.rank-2 {{ border-top-color: #58b7e8; }}
    .rank-card.rank-3 {{ border-top-color: var(--accent-2); }}
    .rank-card.rank-4 {{ border-top-color: #e58bb8; }}
    .rank-card.rank-5 {{ border-top-color: #ff7b72; }}
    .rank-card.rank-6 {{ border-top-color: #b89cff; }}
    .rank-card.rank-7 {{ border-top-color: #f1f3f5; }}
    .rank-number {{
      color: var(--muted);
      font-size: 0.75rem;
      font-weight: 800;
      margin-bottom: 7px;
    }}
    .rank-card h3 {{
      margin: 0;
      font-size: 1.15rem;
    }}
    .rank-card p {{
      min-height: 76px;
      margin-top: 8px;
      font-size: 0.92rem;
      line-height: 1.45;
    }}
    .rank-card ul {{
      margin-top: 14px;
      font-size: 0.9rem;
    }}
    .rank-total {{
      margin-top: 14px;
      padding-top: 12px;
      border-top: 1px solid var(--line);
      color: var(--text);
      font-size: 0.82rem;
      font-weight: 700;
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
    @media (max-width: 900px) {{
      .rank-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .rank-card p {{ min-height: 0; }}
    }}
    @media (max-width: 560px) {{
      .wrap {{ padding: 20px 14px 40px; }}
      .hero {{ padding: 20px; }}
      .rank-grid {{ grid-template-columns: 1fr; }}
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
        <a class="primary" href="/shop">Open Shop</a>
        <a href="/docs">Open Route Index</a>
        <a href="/owner">Owner Console</a>
        <a href="/api/v1/product">Product JSON</a>
        <a href="/api/v1/ranks">All Ranks JSON</a>
      </div>
      <div class="meta">API version {API_VERSION} - Updated {product['updated_at_utc']}</div>
    </section>
    <section class="rank-section">
      <h2>All License Ranks</h2>
      <p>Every rank is shown below in order, including its price, audience, included tools, and cumulative entitlement count.</p>
      <div class="rank-grid">{plan_html}</div>
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
    </section>
  </div>
</body>
</html>"""


def shop_html():
    shop = shop_payload()
    cards = []
    for item in shop["items"]:
        included = "".join(f"<li>{html_escape(str(value))}</li>" for value in item["includes"])
        if item["checkout_available"]:
            action = (
                f'<a class="buy" href="{html_escape(item["checkout_url"], quote=True)}" '
                'target="_blank" rel="noopener noreferrer">BUY THROUGH SECURE CHECKOUT</a>'
            )
        else:
            action = '<span class="unavailable" aria-disabled="true">NOT ON SALE YET</span>'
        cards.append(
            f'<article class="plan rank-{item["rank"]}">'
            f'<div class="rank">RANK {item["rank"]}</div>'
            f'<h2>{html_escape(item["name"])}</h2>'
            f'<div class="price">{html_escape(item["price_label"])}</div>'
            f'<p>{html_escape(item["best_for"])}</p>'
            f'<ul>{included}</ul>'
            f'<div class="entitlements">{len(item["entitlements"])} cumulative entitlements</div>'
            f'{action}</article>'
        )
    readiness = (
        f'{shop["configured_count"]} of {shop["count"]} checkout links are live.'
        if shop["configured_count"]
        else "Checkout is not open yet. No tier can accept payment until the owner configures its hosted link."
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Shop</title>
  <style>
    :root {{ --bg:#101216; --surface:#191d23; --line:#303741; --text:#f5f6f7; --muted:#b5bec9; --green:#72e184; --blue:#69bce8; --yellow:#ffd166; --red:#ff8278; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--bg); color:var(--text); font-family:"Segoe UI",Arial,sans-serif; }}
    header {{ border-bottom:1px solid var(--line); background:#14171c; }}
    header > div, main, footer > div {{ width:min(1180px,calc(100% - 32px)); margin:0 auto; }}
    header > div {{ display:flex; align-items:center; justify-content:space-between; gap:18px; min-height:72px; }}
    .brand {{ font-size:1.05rem; font-weight:800; }}
    nav {{ display:flex; gap:10px; flex-wrap:wrap; }}
    nav a {{ color:var(--text); text-decoration:none; padding:9px 12px; border:1px solid var(--line); border-radius:6px; }}
    main {{ padding:42px 0 54px; }}
    .intro {{ max-width:800px; margin-bottom:26px; }}
    h1 {{ margin:0; font-size:clamp(2.1rem,5vw,4rem); line-height:1; letter-spacing:0; }}
    .intro p {{ color:var(--muted); line-height:1.6; margin:14px 0 0; }}
    .ready {{ display:inline-block; margin-top:16px; padding:8px 10px; border-left:4px solid var(--yellow); background:#212026; color:var(--text); }}
    .plans {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:16px; }}
    .plan {{ display:flex; min-width:0; flex-direction:column; padding:20px; background:var(--surface); border:1px solid var(--line); border-top:4px solid var(--green); border-radius:8px; }}
    .plan.rank-2 {{ border-top-color:var(--blue); }} .plan.rank-3 {{ border-top-color:var(--yellow); }} .plan.rank-4 {{ border-top-color:#ef98bd; }}
    .plan.rank-5 {{ border-top-color:var(--red); }} .plan.rank-6 {{ border-top-color:#bca3ff; }} .plan.rank-7 {{ border-top-color:#f5f6f7; }}
    .rank {{ color:var(--muted); font-size:.75rem; font-weight:800; }}
    h2 {{ margin:7px 0 0; font-size:1.2rem; letter-spacing:0; }}
    .price {{ margin-top:10px; font-size:1.8rem; font-weight:800; color:var(--green); }}
    .plan p {{ min-height:72px; color:var(--muted); line-height:1.5; }}
    ul {{ flex:1; margin:0; padding-left:19px; color:var(--muted); line-height:1.55; }}
    .entitlements {{ margin:17px 0 12px; padding-top:12px; border-top:1px solid var(--line); font-size:.82rem; font-weight:700; }}
    .buy,.unavailable {{ display:block; width:100%; min-height:44px; padding:12px; border-radius:6px; text-align:center; font-size:.82rem; font-weight:800; }}
    .buy {{ background:var(--green); color:#071109; text-decoration:none; }}
    .buy:hover {{ background:#8aeb96; }}
    .unavailable {{ border:1px solid var(--line); color:var(--muted); background:#12151a; }}
    footer {{ border-top:1px solid var(--line); background:#14171c; }}
    footer > div {{ padding:24px 0 32px; color:var(--muted); line-height:1.6; }}
    footer strong {{ color:var(--text); }}
    @media (max-width:620px) {{ header > div {{ align-items:flex-start; flex-direction:column; padding:16px 0; }} main {{ padding-top:28px; }} .plans {{ grid-template-columns:1fr; }} .plan p {{ min-height:0; }} }}
  </style>
</head>
<body>
  <header><div><div class="brand">VaultLink</div><nav><a href="/">HOME</a><a href="/owner">OWNER</a></nav></div></header>
  <main>
    <section class="intro">
      <h1>VaultLink Shop</h1>
      <p>Choose a Windows USB File Locker rank. Payments open only on the payment provider's hosted checkout page; this site does not collect card numbers.</p>
      <div class="ready">{html_escape(readiness)}</div>
    </section>
    <section class="plans">{''.join(cards)}</section>
  </main>
  <footer><div><strong>How delivery works:</strong> after the payment provider confirms payment, the owner issues the matching VaultLink license. A checkout receipt is not itself a license key. The plans are software packages, not HIPAA certification or a guarantee against data loss, malware, or legal risk.</div></footer>
</body>
</html>"""


def owner_portal_html():
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Owner Console</title>
  <style>
    :root { color-scheme: dark; --bg:#0d0f12; --panel:#161a20; --field:#0a0c0f; --line:#313843; --text:#f4f7fa; --muted:#9ba8b6; --green:#35e878; --blue:#58b7e8; --yellow:#f3c84b; --red:#ff626d; }
    * { box-sizing:border-box; letter-spacing:0; }
    body { margin:0; min-width:320px; background:var(--bg); color:var(--text); font:14px/1.45 "Segoe UI",Arial,sans-serif; }
    header { border-bottom:1px solid var(--line); background:#111419; }
    header > div, main { width:min(1180px,calc(100% - 32px)); margin:0 auto; }
    header > div { min-height:78px; display:flex; align-items:center; justify-content:space-between; gap:20px; }
    h1 { margin:0; font-size:24px; }
    h2 { margin:0 0 14px; font-size:17px; }
    .api-state { color:var(--muted); font-weight:700; }
    main { padding:24px 0 44px; }
    section { padding:20px 0 24px; border-bottom:1px solid var(--line); }
    .auth, .grid, .latest, .record-head, .record-actions, .ticket-actions, .audit-row, .stats { display:grid; gap:10px; align-items:end; }
    .auth { grid-template-columns:minmax(220px,1fr) auto auto; }
    .grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
    .latest { grid-template-columns:minmax(0,1fr) auto; }
    .record-head { grid-template-columns:minmax(180px,1fr) minmax(160px,.7fr) auto; align-items:start; }
    .record-actions { grid-template-columns:minmax(180px,1fr) auto auto auto auto auto; }
    .ticket-actions { grid-template-columns:minmax(130px,.45fr) minmax(200px,1fr) minmax(200px,1fr) auto auto; align-items:start; }
    .audit-row { grid-template-columns:minmax(180px,1fr) minmax(140px,.5fr) auto; align-items:center; }
    .stats { grid-template-columns:repeat(4,minmax(0,1fr)); align-items:stretch; }
    .stat { min-width:0; padding:12px 10px; border-left:3px solid var(--blue); background:var(--panel); }
    .stat strong { display:block; margin-top:3px; font-size:20px; overflow-wrap:anywhere; }
    label { display:block; color:var(--muted); font-size:11px; font-weight:800; text-transform:uppercase; margin-bottom:5px; }
    input, select, textarea { width:100%; border:1px solid var(--line); border-radius:4px; background:var(--field); color:var(--text); padding:10px 11px; font:inherit; }
    textarea { min-height:72px; resize:vertical; }
    button { min-height:40px; border:0; border-radius:4px; padding:0 14px; background:#29303a; color:var(--text); font:700 12px "Segoe UI",Arial,sans-serif; cursor:pointer; }
    button:hover { filter:brightness(1.12); }
    button:disabled { cursor:not-allowed; opacity:.45; }
    .primary { background:var(--green); color:#06120a; }
    .blue { background:var(--blue); color:#061017; }
    .warn { background:var(--yellow); color:#171204; }
    .danger { background:var(--red); color:#190407; }
    .status { min-height:22px; margin-top:10px; color:var(--muted); }
    .status.bad { color:var(--red); }
    .status.good { color:var(--green); }
    .record { margin-top:10px; padding:15px; border:1px solid var(--line); border-radius:6px; background:var(--panel); }
    .record strong { font-size:15px; overflow-wrap:anywhere; }
    .meta { color:var(--muted); font-size:12px; margin-top:4px; }
    .badge { display:inline-block; min-width:72px; padding:4px 8px; border-radius:4px; text-align:center; text-transform:uppercase; font-size:11px; font-weight:800; background:#25302a; color:var(--green); }
    .badge.revoked { background:#392126; color:#ff9aa2; }
    .badge.open { background:#352f1d; color:var(--yellow); }
    .badge.acknowledged, .badge.in_progress { background:#1d3039; color:var(--blue); }
    .badge.resolved, .badge.closed { background:#25302a; color:var(--green); }
    .ticket-copy { margin:10px 0 0; padding:10px; background:var(--field); color:var(--text); white-space:pre-wrap; overflow-wrap:anywhere; }
    .device-list { margin-top:12px; padding-top:12px; border-top:1px solid var(--line); }
    .device-row { display:grid; grid-template-columns:minmax(180px,1fr) minmax(120px,.6fr) auto; gap:10px; align-items:center; padding:8px 0; }
    .empty { padding:26px 0; color:var(--muted); }
    .split { grid-column:1 / -1; }
    @media (max-width:900px) { .stats { grid-template-columns:repeat(3,minmax(0,1fr)); } }
    @media (max-width:760px) { .auth,.grid,.latest,.record-head,.record-actions,.ticket-actions,.audit-row,.device-row { grid-template-columns:1fr; } .stats { grid-template-columns:repeat(2,minmax(0,1fr)); } header > div { align-items:flex-start; flex-direction:column; padding:16px 0; } button { width:100%; } }
  </style>
</head>
<body>
  <header><div><h1>VaultLink Owner Console</h1><div id="apiState" class="api-state">DISCONNECTED</div></div></header>
  <main>
    <section>
      <h2>Owner Access</h2>
      <div class="auth">
        <div><label for="token">License admin token</label><input id="token" type="password" autocomplete="off" spellcheck="false"></div>
        <button id="connect" class="blue">CONNECT</button>
        <button id="clearToken">CLEAR TOKEN</button>
      </div>
      <div id="status" class="status">The token stays in this page memory and is sent only in the admin header.</div>
    </section>

    <section>
      <h2>API Dashboard</h2>
      <div class="stats">
        <div class="stat"><label>Active licenses</label><strong id="statLicenses">-</strong></div>
        <div class="stat"><label>Active devices</label><strong id="statDevices">-</strong></div>
        <div class="stat"><label>Device capacity</label><strong id="statCapacity">-</strong></div>
        <div class="stat"><label>Audit reports</label><strong id="statAudits">-</strong></div>
        <div class="stat"><label>High + critical</label><strong id="statBreaches">-</strong></div>
        <div class="stat"><label>Desktop release</label><strong id="statRelease">-</strong></div>
        <div class="stat"><label>API version</label><strong id="statApi">-</strong></div>
        <div class="stat"><label>Client sync</label><strong id="statSync">-</strong></div>
        <div class="stat"><label>Bugs needing action</label><strong id="statSupport">-</strong></div>
        <div class="stat"><label>Shop links live</label><strong id="statShop">-</strong></div>
        <div class="stat"><label>Active announcements</label><strong id="statAnnouncements">-</strong></div>
      </div>
    </section>

    <section>
      <h2>Issue License</h2>
      <div class="grid">
        <div><label for="rank">Rank</label><select id="rank"></select></div>
        <div><label for="devices">Maximum devices</label><input id="devices" type="number" min="1" max="1000" value="1"></div>
        <div><label for="customer">Customer label</label><input id="customer" maxlength="160"></div>
        <div><label for="email">Customer email</label><input id="email" type="email" maxlength="254"></div>
        <div><label for="expires">Expiration, optional</label><input id="expires" type="datetime-local"></div>
        <div><label for="note">Private owner note</label><input id="note" maxlength="2000"></div>
        <div class="split"><button id="issue" class="primary" disabled>ISSUE LICENSE</button></div>
      </div>
      <div id="latestWrap" hidden>
        <label for="latestKey">Latest key</label>
        <div class="latest"><textarea id="latestKey" readonly></textarea><button id="copyLatest" class="warn">COPY KEY</button></div>
      </div>
    </section>

    <section>
      <h2>Owner Announcements</h2>
      <div class="grid">
        <div><label for="announcementSeverity">Type</label><select id="announcementSeverity"><option value="info">INFO</option><option value="update">UPDATE</option><option value="maintenance">MAINTENANCE</option><option value="security">SECURITY</option></select></div>
        <div><label for="announcementRank">Audience</label><select id="announcementRank"><option value="1">ALL RANKS</option></select></div>
        <div><label for="announcementStarts">Starts, optional</label><input id="announcementStarts" type="datetime-local"></div>
        <div><label for="announcementExpires">Expires, optional</label><input id="announcementExpires" type="datetime-local"></div>
        <div class="split"><label for="announcementTitle">Title</label><input id="announcementTitle" maxlength="120"></div>
        <div class="split"><label for="announcementMessage">Message</label><textarea id="announcementMessage" maxlength="2000"></textarea></div>
        <div class="split"><button id="publishAnnouncement" class="primary" disabled>PUBLISH ANNOUNCEMENT</button></div>
      </div>
      <div class="record-head"><h2>Published Messages</h2><div id="announcementStorage" class="meta"></div><button id="refreshAnnouncements" disabled>REFRESH MESSAGES</button></div>
      <div id="announcementRecords"><div class="empty">Connect to load owner announcements.</div></div>
    </section>

    <section>
      <div class="record-head"><h2>Keys And Notes</h2><div id="storage" class="meta"></div><button id="refresh" disabled>REFRESH</button></div>
      <div id="records"><div class="empty">Connect to load licenses.</div></div>
    </section>

    <section>
      <div class="record-head"><h2>Bug Inbox</h2><div id="supportStorage" class="meta"></div><button id="refreshSupport" disabled>REFRESH BUGS</button></div>
      <div id="supportRecords"><div class="empty">Connect to load customer bug reports.</div></div>
    </section>

    <section>
      <div class="record-head"><h2>Audit Logs</h2><div id="auditStorage" class="meta"></div><button id="refreshLogs" disabled>REFRESH LOGS</button></div>
      <div id="auditRecords"><div class="empty">Connect to load privacy-safe API logs.</div></div>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const state = { token: "", connected: false, busy: false, loading: false, items: [], supportItems: [], auditItems: [], announcementItems: [], dashboard: null };
    const AUTO_REFRESH_MS = 30000;

    function setStatus(message, kind="") {
      $("status").textContent = message;
      $("status").className = `status ${kind}`;
    }

    function setConnected(value) {
      state.connected = value;
      $("apiState").textContent = value ? "CONNECTED" : "DISCONNECTED";
      $("apiState").style.color = value ? "var(--green)" : "var(--muted)";
      $("issue").disabled = !value || state.busy;
      $("refresh").disabled = !value || state.busy;
      $("refreshSupport").disabled = !value || state.busy;
      $("refreshLogs").disabled = !value || state.busy;
      $("publishAnnouncement").disabled = !value || state.busy;
      $("refreshAnnouncements").disabled = !value || state.busy;
    }

    async function api(path, options={}) {
      const headers = { "Accept":"application/json", ...(options.headers || {}) };
      if (state.token) headers["X-License-Admin-Token"] = state.token;
      if (options.body) headers["Content-Type"] = "application/json";
      const response = await fetch(path, { ...options, headers, cache:"no-store", redirect:"error" });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.message || `API request failed (${response.status})`);
      return payload;
    }

    async function loadRanks() {
      const payload = await api("/api/v1/ranks");
      const select = $("rank");
      const audience = $("announcementRank");
      select.replaceChildren();
      audience.replaceChildren();
      for (const plan of payload.items || []) {
        const option = document.createElement("option");
        option.value = plan.id;
        option.textContent = `Rank ${plan.rank}: ${plan.name} (${plan.price_label})`;
        select.append(option);
        const audienceOption = document.createElement("option");
        audienceOption.value = String(plan.rank);
        audienceOption.textContent = plan.rank === 1 ? "ALL RANKS" : `RANK ${plan.rank} AND ABOVE`;
        audience.append(audienceOption);
      }
    }

    async function loadLicenses(silent=false) {
      if (state.loading) return;
      state.loading = true;
      try {
      const [payload, dashboard, support, audits, announcements] = await Promise.all([
        api("/api/v1/admin/licenses"),
        api("/api/v1/admin/dashboard"),
        api("/api/v1/admin/support-tickets"),
        api("/api/v1/admin/audit-exports"),
        api("/api/v1/admin/announcements")
      ]);
      state.items = payload.items || [];
      state.supportItems = support.items || [];
      state.auditItems = audits.items || [];
      state.announcementItems = announcements.items || [];
      state.dashboard = dashboard;
      $("storage").textContent = payload.storage === "persistent_configured" ? "PERSISTENT STORAGE" : "TEMPORARY STORAGE";
      $("supportStorage").textContent = support.storage === "persistent_configured" ? "ENCRYPTED PERSISTENT STORAGE" : "TEMPORARY STORAGE";
      $("auditStorage").textContent = `${audits.storage === "persistent_configured" ? "PERSISTENT STORAGE" : "TEMPORARY STORAGE"} | ${audits.retention_hours || 0}H RETENTION`;
      $("announcementStorage").textContent = announcements.storage === "persistent_configured" ? "PERSISTENT STORAGE" : "TEMPORARY STORAGE";
      renderDashboard(dashboard);
      renderRecords();
      renderSupport();
      renderAudits();
      renderAnnouncements();
      setConnected(true);
      if (!silent) setStatus(`Loaded ${payload.count || 0} license(s), ${support.count || 0} bug report(s), ${audits.count || 0} audit log(s), and ${announcements.count || 0} announcement(s).`, "good");
      } finally {
        state.loading = false;
      }
    }

    function renderDashboard(dashboard) {
      const licenses = dashboard?.licenses || {};
      const devices = dashboard?.devices || {};
      const audits = dashboard?.audit_exports || {};
      const levels = audits.breach_levels || {};
      const support = dashboard?.support_tickets || {};
      const shop = dashboard?.shop || {};
      const announcements = dashboard?.announcements || {};
      $("statLicenses").textContent = dashboard ? String(licenses.active || 0) : "-";
      $("statDevices").textContent = dashboard ? String(devices.active || 0) : "-";
      $("statCapacity").textContent = dashboard ? String(devices.capacity || 0) : "-";
      $("statAudits").textContent = dashboard ? String(audits.total || 0) : "-";
      $("statBreaches").textContent = dashboard ? String((levels.high || 0) + (levels.critical || 0)) : "-";
      $("statRelease").textContent = dashboard ? String((dashboard.release || {}).desktop_version || "none") : "-";
      $("statApi").textContent = dashboard ? String((dashboard.release || {}).api_version || "unknown") : "-";
      $("statSync").textContent = dashboard ? `${String((dashboard.release || {}).license_sync_seconds || 60)}s` : "-";
      $("statSupport").textContent = dashboard ? String(support.needs_action || 0) : "-";
      $("statShop").textContent = dashboard ? `${String(shop.configured || 0)}/${String(shop.total || 0)}` : "-";
      $("statAnnouncements").textContent = dashboard ? String(announcements.active || 0) : "-";
    }

    function actionButton(text, className, action) {
      const button = document.createElement("button");
      button.textContent = text;
      button.className = className;
      button.addEventListener("click", action);
      return button;
    }

    function renderRecords() {
      const host = $("records");
      host.replaceChildren();
      if (!state.items.length) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No license records yet.";
        host.append(empty);
        return;
      }
      for (const item of state.items) {
        const record = document.createElement("article");
        record.className = "record";
        const head = document.createElement("div");
        head.className = "record-head";
        const identity = document.createElement("div");
        const title = document.createElement("strong");
        title.textContent = item.license_id || "Unknown license";
        const meta = document.createElement("div");
        meta.className = "meta";
        meta.textContent = `${item.plan_name || item.plan_id} | devices ${item.active_devices || 0}/${item.max_devices || 1} | issued ${item.issued_at_utc || "unknown"}`;
        identity.append(title, meta);
        const customer = document.createElement("div");
        customer.className = "meta";
        customer.textContent = item.customer_label || item.customer_email || "No customer label";
        const badge = document.createElement("span");
        badge.className = `badge ${item.status === "revoked" ? "revoked" : ""}`;
        badge.textContent = item.status || "active";
        head.append(identity, customer, badge);

        const keyLabel = document.createElement("label");
        keyLabel.textContent = "License key";
        const key = document.createElement("input");
        key.readOnly = true;
        key.value = item.license_key || "Private data unavailable";

        const noteLabel = document.createElement("label");
        noteLabel.textContent = "Private owner note";
        const actions = document.createElement("div");
        actions.className = "record-actions";
        const note = document.createElement("input");
        note.maxLength = 2000;
        note.value = item.license_note || "";
        actions.append(note);
        actions.append(actionButton("SAVE NOTE", "blue", () => saveNote(item, note.value)));
        actions.append(actionButton("COPY KEY", "warn", () => copyText(item.license_key || "")));
        const deviceList = document.createElement("div");
        deviceList.className = "device-list";
        deviceList.hidden = true;
        actions.append(actionButton("DEVICES", "", () => toggleDevices(item, deviceList)));
        actions.append(actionButton("RESET DEVICES", "", () => resetDevices(item)));
        actions.append(item.status === "revoked"
          ? actionButton("RESTORE", "primary", () => changeStatus(item, "restore"))
          : actionButton("REVOKE", "danger", () => changeStatus(item, "revoke")));
        record.append(head, keyLabel, key, noteLabel, actions, deviceList);
        host.append(record);
      }
    }

    function renderSupport() {
      const host = $("supportRecords");
      host.replaceChildren();
      if (!state.supportItems.length) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No customer bug reports yet.";
        host.append(empty);
        return;
      }
      for (const item of state.supportItems) {
        const record = document.createElement("article");
        record.className = "record";
        const head = document.createElement("div");
        head.className = "record-head";
        const identity = document.createElement("div");
        const title = document.createElement("strong");
        title.textContent = item.subject || item.ticket_id || "Bug report";
        const meta = document.createElement("div");
        meta.className = "meta";
        meta.textContent = `${item.ticket_id || "unknown"} | ${item.category || "other"} | ${item.license_id || "unknown license"} | ${item.created_at_utc || "unknown time"}`;
        identity.append(title, meta);
        const source = document.createElement("div");
        source.className = "meta";
        source.textContent = `device ${item.machine_hash || "anonymous"} | app ${item.app_version || "unknown"}`;
        const badge = document.createElement("span");
        badge.className = `badge ${item.status || "open"}`;
        badge.textContent = (item.status || "open").replace("_", " ");
        head.append(identity, source, badge);

        const message = document.createElement("div");
        message.className = "ticket-copy";
        message.textContent = item.message || "No description supplied.";
        record.append(head, message);
        if (item.steps) {
          const stepsLabel = document.createElement("label");
          stepsLabel.textContent = "Steps to reproduce";
          const steps = document.createElement("div");
          steps.className = "ticket-copy";
          steps.textContent = item.steps;
          record.append(stepsLabel, steps);
        }

        const actions = document.createElement("div");
        actions.className = "ticket-actions";
        const status = document.createElement("select");
        for (const value of ["open", "acknowledged", "in_progress", "resolved", "closed"]) {
          const option = document.createElement("option");
          option.value = value;
          option.textContent = value.replace("_", " ").toUpperCase();
          option.selected = value === item.status;
          status.append(option);
        }
        const reply = document.createElement("textarea");
        reply.maxLength = 4000;
        reply.placeholder = "Reply visible to the customer";
        reply.value = item.owner_reply || "";
        const note = document.createElement("textarea");
        note.maxLength = 4000;
        note.placeholder = "Private owner note";
        note.value = item.owner_note || "";
        actions.append(status, reply, note);
        actions.append(actionButton("SAVE ACTION", "blue", () => saveSupport(item, status.value, reply.value, note.value)));
        actions.append(actionButton("DELETE", "danger", () => deleteSupport(item)));
        record.append(actions);
        host.append(record);
      }
    }

    function renderAudits() {
      const host = $("auditRecords");
      host.replaceChildren();
      if (!state.auditItems.length) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No API audit logs are stored right now.";
        host.append(empty);
        return;
      }
      for (const item of state.auditItems) {
        const row = document.createElement("article");
        row.className = "record audit-row";
        const identity = document.createElement("div");
        const title = document.createElement("strong");
        title.textContent = item.export_id || "Audit report";
        const source = item.source || {};
        const meta = document.createElement("div");
        meta.className = "meta";
        meta.textContent = `${item.uploaded_at_utc || "unknown time"} | ${source.license_id || "unknown license"} | ${item.event_count || 0} event(s)`;
        identity.append(title, meta);
        const level = String((item.breach_summary || {}).level || "clear").toLowerCase();
        const badge = document.createElement("span");
        badge.className = `badge ${level === "high" || level === "critical" ? "revoked" : "resolved"}`;
        badge.textContent = level;
        row.append(identity, badge, actionButton("DOWNLOAD JSON", "warn", () => downloadAudit(item)));
        host.append(row);
      }
    }

    function renderAnnouncements() {
      const host = $("announcementRecords");
      host.replaceChildren();
      if (!state.announcementItems.length) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No owner announcements have been published.";
        host.append(empty);
        return;
      }
      for (const item of state.announcementItems) {
        const record = document.createElement("article");
        record.className = "record";
        const head = document.createElement("div");
        head.className = "record-head";
        const identity = document.createElement("div");
        const title = document.createElement("strong");
        title.textContent = item.title || item.announcement_id || "Owner announcement";
        const meta = document.createElement("div");
        meta.className = "meta";
        meta.textContent = `${item.announcement_id || "unknown"} | ${item.audience || "all ranks"} | created ${item.created_at_utc || "unknown"}`;
        identity.append(title, meta);
        const schedule = document.createElement("div");
        schedule.className = "meta";
        schedule.textContent = `starts ${item.starts_at_utc || "now"} | expires ${item.expires_at_utc || "never"}`;
        const badge = document.createElement("span");
        badge.className = `badge ${item.active ? "resolved" : "revoked"}`;
        badge.textContent = item.active ? item.severity || "info" : "inactive";
        head.append(identity, schedule, badge);
        const message = document.createElement("div");
        message.className = "ticket-copy";
        message.textContent = item.message || "No message supplied.";
        const actions = document.createElement("div");
        actions.className = "record-head";
        const spacer = document.createElement("div");
        actions.append(spacer, document.createElement("div"), actionButton("DELETE", "danger", () => deleteAnnouncement(item)));
        record.append(head, message, actions);
        host.append(record);
      }
    }

    async function connect() {
      state.token = $("token").value.trim();
      if (!state.token) return setStatus("Enter the Railway LICENSE_ADMIN_TOKEN.", "bad");
      try { await loadLicenses(); } catch (error) { state.token = ""; setConnected(false); setStatus(error.message, "bad"); }
    }

    async function autoRefresh() {
      if (!state.connected || state.busy || state.loading) return;
      if (document.activeElement && document.activeElement.matches("input, textarea, select")) return;
      try {
        await loadLicenses(true);
        setStatus(`Owner data refreshed automatically at ${new Date().toLocaleTimeString()}.`, "good");
      } catch (error) {
        setStatus(`Automatic refresh failed: ${error.message}`, "bad");
      }
    }

    async function issueLicense() {
      if (!state.connected || state.busy) return;
      state.busy = true; setConnected(true); setStatus("Issuing license...");
      try {
        const expiresValue = $("expires").value;
        const payload = await api("/api/v1/licenses/issue", { method:"POST", body:JSON.stringify({
          plan_id: $("rank").value,
          max_devices: Number($("devices").value || 1),
          customer_label: $("customer").value.trim(),
          customer_email: $("email").value.trim(),
          license_note: $("note").value.trim(),
          expires_at_utc: expiresValue ? new Date(expiresValue).toISOString() : ""
        }) });
        $("latestKey").value = payload.license_key || "";
        $("latestWrap").hidden = false;
        await loadLicenses();
        setStatus("License issued and stored. Copy the key for the customer.", "good");
      } catch (error) { setStatus(error.message, "bad"); }
      finally { state.busy = false; setConnected(state.connected); }
    }

    async function publishAnnouncement() {
      if (!state.connected || state.busy) return;
      const title = $("announcementTitle").value.trim();
      const message = $("announcementMessage").value.trim();
      if (title.length < 3) return setStatus("Announcement title must be at least 3 characters.", "bad");
      if (message.length < 5) return setStatus("Announcement message must be at least 5 characters.", "bad");
      if (!confirm(`PUBLISH \"${title}\" TO THE SELECTED LICENSE RANKS?`)) return;
      state.busy = true; setConnected(true); setStatus("Publishing announcement...");
      try {
        const starts = $("announcementStarts").value;
        const expires = $("announcementExpires").value;
        const result = await api("/api/v1/admin/announcements/create", { method:"POST", body:JSON.stringify({
          severity:$("announcementSeverity").value,
          minimum_rank:Number($("announcementRank").value || 1),
          title,
          message,
          starts_at_utc:starts ? new Date(starts).toISOString() : "",
          expires_at_utc:expires ? new Date(expires).toISOString() : ""
        }) });
        $("announcementTitle").value = "";
        $("announcementMessage").value = "";
        $("announcementStarts").value = "";
        $("announcementExpires").value = "";
        await loadLicenses(true);
        setStatus(result.message || "Announcement published.", "good");
      } catch (error) { setStatus(error.message, "bad"); }
      finally { state.busy = false; setConnected(state.connected); }
    }

    async function deleteAnnouncement(item) {
      if (!confirm(`PERMANENTLY DELETE ${item.announcement_id}?`)) return;
      try {
        const result = await api("/api/v1/admin/announcements/delete", { method:"POST", body:JSON.stringify({ announcement_id:item.announcement_id }) });
        await loadLicenses(true);
        setStatus(result.message || `Deleted ${item.announcement_id}.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function saveNote(item, note) {
      try {
        await api("/api/v1/licenses/note", { method:"POST", body:JSON.stringify({ license_key:item.license_key, license_note:note }) });
        await loadLicenses();
        setStatus(`Saved note for ${item.license_id}.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function changeStatus(item, action) {
      const verb = action === "revoke" ? "revoke" : "restore";
      if (!confirm(`${verb.toUpperCase()} ${item.license_id}?`)) return;
      try {
        await api(`/api/v1/licenses/${action}`, { method:"POST", body:JSON.stringify({ license_key:item.license_key }) });
        await loadLicenses();
        setStatus(`${item.license_id} ${verb}d.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function resetDevices(item) {
      if (!confirm(`RESET ALL DEVICE SEATS FOR ${item.license_id}? Existing receipts will need activation again.`)) return;
      try {
        const result = await api("/api/v1/licenses/reset-devices", { method:"POST", body:JSON.stringify({ license_key:item.license_key }) });
        await loadLicenses();
        setStatus(result.message || `Reset devices for ${item.license_id}.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function toggleDevices(item, host) {
      if (!host.hidden) { host.hidden = true; return; }
      host.hidden = false;
      host.textContent = "Loading anonymous device seats...";
      try {
        const payload = await api(`/api/v1/admin/licenses/${encodeURIComponent(item.license_id)}/devices`);
        host.replaceChildren();
        if (!(payload.items || []).length) {
          host.textContent = "No device seats have been recorded for this license.";
          return;
        }
        for (const device of payload.items) {
          const row = document.createElement("div");
          row.className = "device-row";
          const identity = document.createElement("div");
          identity.textContent = device.machine_hash || "unknown device";
          const meta = document.createElement("div");
          meta.className = "meta";
          const lastSeen = device.last_seen_at_utc ? new Date(device.last_seen_at_utc).toLocaleString() : "not synced yet";
          meta.textContent = `${device.status || "unknown"} | app ${device.app_version || "unknown"} | last sync ${lastSeen}`;
          const remove = actionButton("REMOVE DEVICE", "danger", () => removeDevice(item, device));
          remove.disabled = !device.active;
          row.append(identity, meta, remove);
          host.append(row);
        }
      } catch (error) {
        host.textContent = error.message;
        setStatus(error.message, "bad");
      }
    }

    async function removeDevice(item, device) {
      if (!confirm(`REMOVE DEVICE ${device.machine_hash} FROM ${item.license_id}? Its receipt will stop working at the next sync.`)) return;
      try {
        const result = await api("/api/v1/licenses/remove-device", { method:"POST", body:JSON.stringify({ license_key:item.license_key, machine_hash:device.machine_hash }) });
        await loadLicenses(true);
        setStatus(result.message || `Removed device from ${item.license_id}.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function saveSupport(item, status, ownerReply, ownerNote) {
      try {
        const result = await api("/api/v1/admin/support-tickets/action", { method:"POST", body:JSON.stringify({
          ticket_id:item.ticket_id,
          status,
          owner_reply:ownerReply,
          owner_note:ownerNote
        }) });
        await loadLicenses(true);
        setStatus(result.message || `Updated ${item.ticket_id}.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function deleteSupport(item) {
      if (!confirm(`PERMANENTLY DELETE ${item.ticket_id}? This removes the report and owner reply.`)) return;
      try {
        const result = await api("/api/v1/admin/support-tickets/delete", { method:"POST", body:JSON.stringify({ ticket_id:item.ticket_id }) });
        await loadLicenses(true);
        setStatus(result.message || `Deleted ${item.ticket_id}.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function downloadAudit(item) {
      try {
        const result = await api("/api/v1/admin/audit-exports/download-link", {
          method:"POST",
          body:JSON.stringify({ export_id:item.export_id })
        });
        const link = document.createElement("a");
        link.href = result.download_path;
        link.download = result.filename || `vaultlink-audit-${item.export_id}.json`;
        document.body.append(link);
        link.click();
        window.setTimeout(() => {
          link.remove();
        }, 1500);
        setStatus(`Downloaded ${item.export_id}.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function copyText(text) {
      if (!text) return setStatus("No key is available to copy.", "bad");
      try { await navigator.clipboard.writeText(text); setStatus("License key copied.", "good"); }
      catch (_) { setStatus("Browser clipboard access was blocked.", "bad"); }
    }

    $("connect").addEventListener("click", connect);
    $("clearToken").addEventListener("click", () => { state.token=""; $("token").value=""; state.items=[]; state.supportItems=[]; state.auditItems=[]; state.announcementItems=[]; state.dashboard=null; setConnected(false); renderDashboard(null); renderRecords(); renderSupport(); renderAudits(); renderAnnouncements(); setStatus("Admin token cleared from page memory."); });
    $("issue").addEventListener("click", issueLicense);
    $("refresh").addEventListener("click", () => loadLicenses().catch((error) => setStatus(error.message,"bad")));
    $("refreshSupport").addEventListener("click", () => loadLicenses().catch((error) => setStatus(error.message,"bad")));
    $("refreshLogs").addEventListener("click", () => loadLicenses().catch((error) => setStatus(error.message,"bad")));
    $("publishAnnouncement").addEventListener("click", publishAnnouncement);
    $("refreshAnnouncements").addEventListener("click", () => loadLicenses().catch((error) => setStatus(error.message,"bad")));
    $("copyLatest").addEventListener("click", () => copyText($("latestKey").value));
    $("token").addEventListener("keydown", (event) => { if (event.key === "Enter") connect(); });
    window.setInterval(autoRefresh, AUTO_REFRESH_MS);
    loadRanks().catch((error) => setStatus(error.message,"bad"));
  </script>
</body>
</html>"""


def public_plans():
    return [public_plan_payload(item) for item in sorted(PLAN_TIERS, key=lambda item: item["rank"])]


def require_json_object(payload):
    if not isinstance(payload, dict):
        raise ValueError("Body must be a JSON object.")
    return payload


def issue_license(payload):
    plan_id = canonical_plan_id(payload.get("plan_id", ""))
    if plan_id not in PLAN_INDEX:
        raise ValueError("Choose a valid plan id.")
    expires_at = parse_utc(payload.get("expires_at_utc"))
    if expires_at and expires_at <= datetime.now(timezone.utc):
        raise ValueError("expires_at_utc must be in the future.")
    max_devices = int(payload.get("max_devices", 1) or 1)
    if max_devices < 1 or max_devices > 1000:
        raise ValueError("max_devices must be between 1 and 1000.")
    plan = PLAN_INDEX[plan_id]
    customer_label = str(payload.get("customer_label", "")).strip()
    customer_email = str(payload.get("customer_email", "")).strip()
    if len(customer_label) > 160:
        raise ValueError("customer_label must be 160 characters or fewer.")
    if len(customer_email) > 254:
        raise ValueError("customer_email must be 254 characters or fewer.")
    license_note = clean_license_note(payload.get("license_note", ""))
    license_id = validated_license_id(
        payload.get("license_id") or f"LIC-{secrets.token_hex(8).upper()}"
    )
    if read_license_record(license_id):
        raise ValueError("That license_id already exists.")
    license_payload = {
        "license_id": license_id,
        "product": "USB File Locker",
        "plan_id": plan["id"],
        "plan_name": plan["name"],
        "entitlements": plan_entitlements(plan["id"]),
        "customer_label": customer_label,
        "customer_email": customer_email,
        "issued_at_utc": utc_now(),
        "expires_at_utc": format_utc(expires_at) if expires_at else "",
        "max_devices": max_devices,
        "issuer": API_NAME,
    }
    license_key = sign_token(LICENSE_KEY_PREFIX, license_payload)
    write_license_record(license_payload, license_key, license_note=license_note, status="active")
    return {
        "ok": True,
        "issued": True,
        "license_key": license_key,
        "license": license_payload,
        "plan": public_plan_payload(plan),
        "server_time_utc": utc_now(),
        "limitations": [
            "Signed keys are checked against the server revocation ledger.",
            "Device seats are enforced by the persistent anonymous activation ledger.",
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
    if len(machine_id) > 256:
        raise ValueError("machine_id must be 256 characters or fewer.")
    if len(machine_name) > 160:
        raise ValueError("machine_name must be 160 characters or fewer.")
    license_payload = verify_token(license_key, LICENSE_KEY_PREFIX)
    if license_is_revoked(license_payload):
        plan = current_plan_for_license(license_payload)
        return {
            "ok": True,
            "active": False,
            "status": "revoked",
            "plan": public_plan_payload(plan),
            "license": {
                "license_id": license_payload.get("license_id", ""),
                "plan_id": plan["id"],
                "plan_name": plan["name"],
                "expires_at_utc": license_payload.get("expires_at_utc", ""),
            },
            "message": "This license was revoked by its owner.",
            "server_time_utc": utc_now(),
        }
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
    registered, used_devices = register_activation_receipt(
        license_payload,
        receipt,
        receipt_payload,
    )
    if not registered:
        return {
            "ok": True,
            "active": False,
            "status": "device_limit",
            "plan": public_plan_payload(plan),
            "license": {
                "license_id": license_payload.get("license_id", ""),
                "plan_id": plan["id"],
                "plan_name": plan["name"],
                "expires_at_utc": license_payload.get("expires_at_utc", ""),
            },
            "device_usage": {
                "active": used_devices,
                "maximum": int(license_payload.get("max_devices", 1) or 1),
            },
            "message": "This license has reached its active-device limit. Remove a device or ask the owner to reset device seats.",
            "server_time_utc": utc_now(),
        }
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
        "device_usage": {
            "active": used_devices,
            "maximum": int(license_payload.get("max_devices", 1) or 1),
        },
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
    if len(machine_id) > 256:
        raise ValueError("machine_id must be 256 characters or fewer.")
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
    if license_is_revoked(license_payload):
        return {
            "ok": True,
            "active": False,
            "status": "revoked",
            "plan": public_plan_payload(plan),
            "license": license_view,
            "message": "This license was revoked by its owner.",
            "server_time_utc": utc_now(),
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
    if receipt_is_deactivated(receipt):
        return {
            "ok": True,
            "active": False,
            "status": "deactivated",
            "plan": public_plan_payload(plan),
            "license": license_view,
            "activation": receipt_payload,
            "message": "This activation was removed from this PC. Activate again to create a new receipt.",
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
    activation_allowed, activation_status, used_devices = verify_activation_receipt(
        license_payload,
        receipt,
        receipt_payload,
        app_version=payload.get("app_version", ""),
    )
    if not activation_allowed:
        messages = {
            "device_limit": "This license has reached its active-device limit.",
            "reset": "The owner reset this license's device seats. Activate again on this PC.",
            "deactivated": "This activation was removed from this PC. Activate again to create a new receipt.",
            "receipt_replaced": "A newer activation receipt replaced this one on the same PC.",
            "removed": "The owner removed this device seat. Activate again only if the owner permits it.",
        }
        return {
            "ok": True,
            "active": False,
            "status": activation_status,
            "plan": public_plan_payload(plan),
            "license": license_view,
            "activation": receipt_payload,
            "device_usage": {
                "active": used_devices,
                "maximum": int(license_payload.get("max_devices", 1) or 1),
            },
            "message": messages.get(activation_status, "This activation is no longer active."),
            "server_time_utc": utc_now(),
        }
    return {
        "ok": True,
        "active": True,
        "status": "active",
        "plan": public_plan_payload(plan),
        "license": license_view,
        "activation": receipt_payload,
        "device_usage": {
            "active": used_devices,
            "maximum": int(license_payload.get("max_devices", 1) or 1),
        },
        "server_time_utc": utc_now(),
    }


def sync_license(payload):
    result = dict(verify_license(payload))
    decision = str(result.get("status", "unknown") or "unknown")
    result["api_version"] = API_VERSION
    result["sync"] = {
        "automatic": True,
        "recommended_interval_seconds": LICENSE_SYNC_INTERVAL_SECONDS,
        "decision": decision,
        "decision_id": secrets.token_hex(8),
        "api_version": API_VERSION,
        "revocation_enforced": True,
        "device_seats_enforced": True,
    }
    try:
        manifest, _package_path = load_windows_update_release()
        current_parts = tuple(
            int(part) if part.isdigit() else 0
            for part in str(payload.get("app_version", "")).split(".")
        )
        latest_parts = tuple(
            int(part) if part.isdigit() else 0
            for part in str(manifest.get("version", "")).split(".")
        )
        result["release"] = {
            "latest_version": manifest.get("version", ""),
            "minimum_supported_version": manifest.get("minimum_supported_version", ""),
            "update_available": bool(latest_parts and latest_parts > current_parts),
        }
    except (FileNotFoundError, OSError, ValueError):
        result["release"] = {
            "latest_version": "",
            "minimum_supported_version": "",
            "update_available": False,
        }
    result["server_time_utc"] = utc_now()
    return result


def deactivate_license(payload):
    verification = verify_license(payload)
    receipt = str(payload.get("receipt", "")).strip()
    if verification.get("status") == "deactivated":
        return {
            **verification,
            "deactivated": True,
            "message": "This activation was already removed from this PC.",
        }
    if not verification.get("active"):
        return {
            **verification,
            "deactivated": False,
        }
    receipt_payload = verify_token(receipt, LICENSE_RECEIPT_PREFIX)
    deactivation = mark_receipt_deactivated(
        receipt,
        receipt_payload,
        app_version=payload.get("app_version", ""),
    )
    deactivate_activation_record(receipt_payload)
    used_devices = active_device_count(receipt_payload.get("license_id", ""))
    return {
        "ok": True,
        "active": False,
        "deactivated": True,
        "status": "deactivated",
        "license": verification.get("license", {}),
        "plan": verification.get("plan", {}),
        "deactivation": {
            "receipt_id": deactivation["receipt_id"],
            "deactivated_at_utc": deactivation["deactivated_at_utc"],
        },
        "device_usage": {
            "active": used_devices,
            "maximum": int((verification.get("device_usage") or {}).get("maximum", 1) or 1),
        },
        "message": "This license activation was removed from this PC.",
        "server_time_utc": utc_now(),
    }


def require_admin_license_key(payload):
    license_key = str(payload.get("license_key", "")).strip()
    if not license_key:
        raise ValueError("license_key is required.")
    license_payload = verify_token(license_key, LICENSE_KEY_PREFIX)
    current_plan_for_license(license_payload)
    validated_license_id(license_payload.get("license_id"))
    return license_key, license_payload


def revoke_license(payload):
    license_key, license_payload = require_admin_license_key(payload)
    note = clean_license_note(payload.get("revocation_note", ""))
    record = write_license_record(
        license_payload,
        license_key,
        license_note=None,
        status="revoked",
        revocation_note=note,
    )
    return {
        "ok": True,
        "revoked": True,
        "license": admin_license_record_view(record, include_private=False),
        "message": "The license is revoked. Existing and future activation checks will fail.",
        "server_time_utc": utc_now(),
    }


def restore_license(payload):
    license_key, license_payload = require_admin_license_key(payload)
    record = write_license_record(
        license_payload,
        license_key,
        license_note=None,
        status="active",
        revocation_note="",
    )
    return {
        "ok": True,
        "restored": True,
        "license": admin_license_record_view(record, include_private=False),
        "message": "The license is active again. Individually deactivated receipts remain deactivated.",
        "server_time_utc": utc_now(),
    }


def update_license_note(payload):
    license_key, license_payload = require_admin_license_key(payload)
    note = clean_license_note(payload.get("license_note", ""))
    record = write_license_record(
        license_payload,
        license_key,
        license_note=note,
    )
    return {
        "ok": True,
        "saved": True,
        "license": admin_license_record_view(record),
        "message": "Private owner note saved.",
        "server_time_utc": utc_now(),
    }


def admin_reset_license_devices(payload):
    license_key, license_payload = require_admin_license_key(payload)
    reset_count = reset_license_devices(license_payload)
    license_id = validated_license_id(license_payload.get("license_id"))
    return {
        "ok": True,
        "devices_reset": reset_count,
        "license": {
            "license_id": license_id,
            "active_devices": active_device_count(license_id),
            "max_devices": int(license_payload.get("max_devices", 1) or 1),
        },
        "message": f"Reset {reset_count} active device seat(s). Those PCs must activate again.",
        "server_time_utc": utc_now(),
    }


def admin_remove_license_device(payload):
    _license_key, license_payload = require_admin_license_key(payload)
    license_id = validated_license_id(license_payload.get("license_id"))
    machine_hash = validated_machine_hash(payload.get("machine_hash"))
    with LICENSE_STATE_LOCK:
        path = activation_folder(license_id) / f"{machine_hash}.json"
        if not path.is_file():
            raise FileNotFoundError("That anonymous device seat was not found.")
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("license_id") != license_id or record.get("machine_hash") != machine_hash:
            raise ValueError("Stored activation record identity did not verify.")
        was_active = activation_record_is_active(record)
        record["status"] = "removed"
        record["removed_at_utc"] = utc_now()
        record["updated_at_utc"] = record["removed_at_utc"]
        write_private_json(path, record)
    return {
        "ok": True,
        "removed": True,
        "was_active": was_active,
        "license": {
            "license_id": license_id,
            "active_devices": active_device_count(license_id),
            "max_devices": int(license_payload.get("max_devices", 1) or 1),
        },
        "device": {"machine_hash": machine_hash, "status": "removed"},
        "message": "The anonymous device seat was removed. Its saved receipt will fail at the next automatic sync.",
        "server_time_utc": utc_now(),
    }


def clean_support_text(value, limit, field_name, required=False, minimum=1):
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    text = "".join(
        character if ord(character) >= 32 or character in {"\n", "\t"} else " "
        for character in text
    ).strip()
    if len(text) > limit:
        raise ValueError(f"{field_name} must be {limit} characters or fewer.")
    if required and len(text) < minimum:
        raise ValueError(f"{field_name} must be at least {minimum} characters.")
    return text


def validated_support_ticket_id(value):
    text = str(value or "").strip().upper()
    if (
        not text.startswith("TKT-")
        or not 12 <= len(text) <= 64
        or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in text)
    ):
        raise ValueError("Choose a valid support ticket id.")
    return text


def support_ticket_path(ticket_id):
    return LICENSE_STATE_DIR / "support_tickets" / f"{validated_support_ticket_id(ticket_id)}.json"


def read_support_ticket(ticket_id):
    clean_ticket_id = validated_support_ticket_id(ticket_id)
    path = support_ticket_path(clean_ticket_id)
    if not path.is_file():
        raise FileNotFoundError("Support ticket was not found.")
    record = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(record, dict) or record.get("ticket_id") != clean_ticket_id:
        raise ValueError("Stored support ticket identity did not verify.")
    return record


def support_ticket_private_fields(record):
    return decrypt_support_private_fields(record)


def support_ticket_view(record, audience="admin"):
    private = support_ticket_private_fields(record)
    item = {
        "ticket_id": str(record.get("ticket_id", "")),
        "category": str(record.get("category", "other")),
        "status": str(record.get("status", "open")),
        "created_at_utc": str(record.get("created_at_utc", "")),
        "updated_at_utc": str(record.get("updated_at_utc", "")),
        "acknowledged_at_utc": str(record.get("acknowledged_at_utc", "")),
        "resolved_at_utc": str(record.get("resolved_at_utc", "")),
        "closed_at_utc": str(record.get("closed_at_utc", "")),
        "app_version": str(record.get("app_version", "")),
        "subject": str(private.get("subject", "")),
        "message": str(private.get("message", "")),
        "steps": str(private.get("steps", "")),
        "owner_reply": str(private.get("owner_reply", "")),
        "history": list(record.get("history", []))[-50:],
    }
    if audience == "admin":
        item.update(
            {
                "license_id": str(record.get("license_id", "")),
                "plan_id": str(record.get("plan_id", "")),
                "machine_hash": str(record.get("machine_hash", "")),
                "owner_note": str(private.get("owner_note", "")),
            }
        )
    return item


def support_ticket_records():
    folder = LICENSE_STATE_DIR / "support_tickets"
    if not folder.is_dir():
        return []
    paths = sorted(
        folder.glob("TKT-*.json"),
        key=lambda path: path.stat().st_mtime if path.exists() else 0,
        reverse=True,
    )[:MAX_SUPPORT_TICKETS]
    records = []
    for path in paths:
        try:
            records.append(read_support_ticket(path.stem))
        except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
            continue
    return records


def require_active_support_license(payload):
    try:
        verification = verify_license(payload)
    except ValueError as exc:
        raise PermissionError(f"License verification failed: {exc}") from exc
    if not verification.get("active"):
        raise PermissionError(verification.get("message") or "An active license is required to contact support.")
    return verification


def create_support_ticket(payload):
    verification = require_active_support_license(payload)
    category = str(payload.get("category", "bug") or "bug").strip().lower()
    if category not in SUPPORT_TICKET_CATEGORIES:
        raise ValueError("Choose a valid support category.")
    subject = clean_support_text(payload.get("subject"), 160, "subject", required=True, minimum=3)
    message = clean_support_text(payload.get("message"), 4000, "message", required=True, minimum=10)
    steps = clean_support_text(payload.get("steps"), 6000, "steps")
    app_version = clean_support_text(payload.get("app_version"), 80, "app_version")
    machine_hash = anonymous_machine_hash(payload.get("machine_id", ""))
    license_view = verification.get("license") or {}
    plan = verification.get("plan") or {}
    license_id = validated_license_id(license_view.get("license_id"))
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=1)
    with LICENSE_STATE_LOCK:
        recent_count = sum(
            record.get("machine_hash") == machine_hash
            and (parse_utc(record.get("created_at_utc")) or datetime.min.replace(tzinfo=timezone.utc)) >= cutoff
            for record in support_ticket_records()
        )
        if recent_count >= MAX_SUPPORT_TICKETS_PER_DAY:
            raise PermissionError("This PC has reached the daily support-ticket limit. Try again later.")
        ticket_id = f"TKT-{secrets.token_hex(8).upper()}"
        now_text = format_utc(now)
        private = {
            "subject": subject,
            "message": message,
            "steps": steps,
            "owner_reply": "",
            "owner_note": "",
        }
        record = {
            "schema_version": 1,
            "ticket_id": ticket_id,
            "license_id": license_id,
            "plan_id": str(plan.get("id", ""))[:40],
            "machine_hash": machine_hash,
            "category": category,
            "status": "open",
            "app_version": app_version,
            "created_at_utc": now_text,
            "updated_at_utc": now_text,
            "acknowledged_at_utc": "",
            "resolved_at_utc": "",
            "closed_at_utc": "",
            "history": [{"time_utc": now_text, "action": "created", "status": "open"}],
            "private_blob": encrypt_support_private_fields(private),
        }
        write_private_json(support_ticket_path(ticket_id), record)
    return {
        "ok": True,
        "created": True,
        "ticket": support_ticket_view(record, audience="customer"),
        "message": "Bug report sent to the VaultLink owner.",
        "privacy_notice": "No files or local logs were attached automatically.",
        "server_time_utc": utc_now(),
    }


def list_my_support_tickets(payload):
    verification = require_active_support_license(payload)
    license_id = str((verification.get("license") or {}).get("license_id", ""))
    machine_hash = anonymous_machine_hash(payload.get("machine_id", ""))
    items = []
    for record in support_ticket_records():
        if record.get("license_id") != license_id or record.get("machine_hash") != machine_hash:
            continue
        try:
            items.append(support_ticket_view(record, audience="customer"))
        except (InvalidTag, OSError, ValueError, json.JSONDecodeError):
            continue
        if len(items) >= 50:
            break
    return {
        "ok": True,
        "count": len(items),
        "items": items,
        "server_time_utc": utc_now(),
    }


def list_admin_support_tickets():
    items = []
    damaged_count = 0
    for record in support_ticket_records():
        try:
            items.append(support_ticket_view(record, audience="admin"))
        except (InvalidTag, OSError, ValueError, json.JSONDecodeError):
            damaged_count += 1
    return {
        "ok": True,
        "count": len(items),
        "damaged_count": damaged_count,
        "items": items,
        "storage": "persistent_configured" if license_state_storage_is_persistent() else "local_ephemeral",
        "privacy_notice": "Ticket text is encrypted at rest. Files, logs, secrets, and raw machine ids are never attached automatically.",
        "server_time_utc": utc_now(),
    }


def admin_update_support_ticket(payload):
    ticket_id = validated_support_ticket_id(payload.get("ticket_id"))
    status = str(payload.get("status", "") or "").strip().lower()
    if status not in SUPPORT_TICKET_STATUSES:
        raise ValueError("Choose a valid support ticket status.")
    owner_reply = clean_support_text(payload.get("owner_reply"), 4000, "owner_reply")
    owner_note = clean_support_text(payload.get("owner_note"), 4000, "owner_note")
    with LICENSE_STATE_LOCK:
        record = read_support_ticket(ticket_id)
        private = support_ticket_private_fields(record)
        private["owner_reply"] = owner_reply
        private["owner_note"] = owner_note
        now = utc_now()
        record["status"] = status
        record["updated_at_utc"] = now
        if status != "open" and not record.get("acknowledged_at_utc"):
            record["acknowledged_at_utc"] = now
        if status == "resolved":
            record["resolved_at_utc"] = now
            record["closed_at_utc"] = ""
        elif status == "closed":
            record["closed_at_utc"] = now
        elif status in {"open", "acknowledged", "in_progress"}:
            record["resolved_at_utc"] = ""
            record["closed_at_utc"] = ""
        history = list(record.get("history", []))[-49:]
        history.append({"time_utc": now, "action": "owner_update", "status": status})
        record["history"] = history
        record["private_blob"] = encrypt_support_private_fields(private)
        write_private_json(support_ticket_path(ticket_id), record)
    return {
        "ok": True,
        "saved": True,
        "ticket": support_ticket_view(record, audience="admin"),
        "message": f"Support ticket {ticket_id} updated.",
        "server_time_utc": utc_now(),
    }


def admin_delete_support_ticket(payload):
    ticket_id = validated_support_ticket_id(payload.get("ticket_id"))
    with LICENSE_STATE_LOCK:
        path = support_ticket_path(ticket_id)
        if not path.is_file():
            raise FileNotFoundError("Support ticket was not found.")
        path.unlink()
    return {
        "ok": True,
        "deleted": True,
        "ticket_id": ticket_id,
        "message": f"Support ticket {ticket_id} permanently deleted.",
        "server_time_utc": utc_now(),
    }


def validated_announcement_id(value):
    text = str(value or "").strip().upper()
    if (
        not text.startswith("ANN-")
        or not 12 <= len(text) <= 64
        or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in text)
    ):
        raise ValueError("Choose a valid announcement id.")
    return text


def announcement_path(announcement_id):
    return LICENSE_STATE_DIR / "announcements" / f"{validated_announcement_id(announcement_id)}.json"


def read_announcement(announcement_id):
    clean_id = validated_announcement_id(announcement_id)
    path = announcement_path(clean_id)
    if not path.is_file():
        raise FileNotFoundError("Announcement was not found.")
    record = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(record, dict) or record.get("announcement_id") != clean_id:
        raise ValueError("Stored announcement identity did not verify.")
    return record


def announcement_records():
    folder = LICENSE_STATE_DIR / "announcements"
    if not folder.is_dir():
        return []
    paths = sorted(
        folder.glob("ANN-*.json"),
        key=lambda path: path.stat().st_mtime if path.exists() else 0,
        reverse=True,
    )[:MAX_ANNOUNCEMENTS]
    records = []
    for path in paths:
        try:
            records.append(read_announcement(path.stem))
        except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
            continue
    return records


def announcement_is_active(record, moment=None):
    if not bool(record.get("active", True)):
        return False
    now = moment or datetime.now(timezone.utc)
    starts_at = parse_utc(record.get("starts_at_utc"))
    expires_at = parse_utc(record.get("expires_at_utc"))
    if starts_at and starts_at > now:
        return False
    if expires_at and expires_at <= now:
        return False
    return True


def announcement_view(record):
    minimum_rank = int(record.get("minimum_rank", 1) or 1)
    audience = "All ranks" if minimum_rank == 1 else f"Rank {minimum_rank} and above"
    return {
        "announcement_id": str(record.get("announcement_id", "")),
        "severity": str(record.get("severity", "info")),
        "title": str(record.get("title", "")),
        "message": str(record.get("message", "")),
        "minimum_rank": minimum_rank,
        "audience": audience,
        "starts_at_utc": str(record.get("starts_at_utc", "")),
        "expires_at_utc": str(record.get("expires_at_utc", "")),
        "created_at_utc": str(record.get("created_at_utc", "")),
        "updated_at_utc": str(record.get("updated_at_utc", "")),
        "active": announcement_is_active(record),
    }


def admin_create_announcement(payload):
    severity = str(payload.get("severity", "info") or "info").strip().lower()
    if severity not in ANNOUNCEMENT_SEVERITIES:
        raise ValueError("Choose a valid announcement severity.")
    title = clean_support_text(payload.get("title"), 120, "title", required=True, minimum=3)
    message = clean_support_text(payload.get("message"), 2000, "message", required=True, minimum=5)
    try:
        minimum_rank = int(payload.get("minimum_rank", 1) or 1)
    except (TypeError, ValueError) as exc:
        raise ValueError("minimum_rank must be a whole number from 1 to 7.") from exc
    if not 1 <= minimum_rank <= len(PLAN_TIERS):
        raise ValueError("minimum_rank must be a whole number from 1 to 7.")
    starts_at = parse_utc(payload.get("starts_at_utc"))
    expires_at = parse_utc(payload.get("expires_at_utc"))
    now = datetime.now(timezone.utc)
    if expires_at and expires_at <= now:
        raise ValueError("expires_at_utc must be in the future.")
    if starts_at and expires_at and starts_at >= expires_at:
        raise ValueError("expires_at_utc must be later than starts_at_utc.")
    if expires_at and expires_at > now + timedelta(days=366):
        raise ValueError("expires_at_utc cannot be more than 366 days in the future.")
    announcement_id = f"ANN-{secrets.token_hex(8).upper()}"
    now_text = format_utc(now)
    record = {
        "schema_version": 1,
        "announcement_id": announcement_id,
        "severity": severity,
        "title": title,
        "message": message,
        "minimum_rank": minimum_rank,
        "starts_at_utc": format_utc(starts_at) if starts_at else "",
        "expires_at_utc": format_utc(expires_at) if expires_at else "",
        "created_at_utc": now_text,
        "updated_at_utc": now_text,
        "active": True,
    }
    with LICENSE_STATE_LOCK:
        write_private_json(announcement_path(announcement_id), record)
    return {
        "ok": True,
        "created": True,
        "announcement": announcement_view(record),
        "message": f"Announcement {announcement_id} published.",
        "server_time_utc": utc_now(),
    }


def list_admin_announcements():
    items = []
    damaged_count = 0
    for record in announcement_records():
        try:
            items.append(announcement_view(record))
        except (OSError, TypeError, ValueError):
            damaged_count += 1
    return {
        "ok": True,
        "count": len(items),
        "active_count": sum(bool(item.get("active")) for item in items),
        "damaged_count": damaged_count,
        "items": items,
        "storage": "persistent_configured" if license_state_storage_is_persistent() else "local_ephemeral",
        "server_time_utc": utc_now(),
    }


def list_my_announcements(payload):
    verification = require_active_support_license(payload)
    plan_rank = int((verification.get("plan") or {}).get("rank", 1) or 1)
    items = []
    for record in announcement_records():
        try:
            if announcement_is_active(record) and int(record.get("minimum_rank", 1) or 1) <= plan_rank:
                items.append(announcement_view(record))
        except (OSError, TypeError, ValueError):
            continue
        if len(items) >= 50:
            break
    return {
        "ok": True,
        "count": len(items),
        "items": items,
        "plan_rank": plan_rank,
        "privacy_notice": "Announcements are read-only text and never execute commands or access local files.",
        "server_time_utc": utc_now(),
    }


def admin_delete_announcement(payload):
    announcement_id = validated_announcement_id(payload.get("announcement_id"))
    with LICENSE_STATE_LOCK:
        path = announcement_path(announcement_id)
        if not path.is_file():
            raise FileNotFoundError("Announcement was not found.")
        path.unlink()
    return {
        "ok": True,
        "deleted": True,
        "announcement_id": announcement_id,
        "message": f"Announcement {announcement_id} deleted.",
        "server_time_utc": utc_now(),
    }


def clean_audit_text(value, limit):
    text = "".join(
        character if ord(character) >= 32 and ord(character) != 127 else " "
        for character in str(value or "")
    ).strip()
    return " ".join(text.split())[:limit]


def clean_audit_identifier(value, limit):
    text = clean_audit_text(value, limit)
    return "".join(
        character for character in text
        if character.isalnum() or character in {"-", "_", "."}
    )[:limit]


def clean_audit_time(value):
    text = clean_audit_text(value, 40)
    try:
        parsed = parse_utc(text)
    except (TypeError, ValueError):
        return ""
    return format_utc(parsed) if parsed else ""


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
    event_id = clean_audit_identifier(record.get("event_id"), 64).lower()
    if len(event_id) != 16 or any(character not in "0123456789abcdef" for character in event_id):
        event_id = hashlib.sha256(event_id.encode("utf-8")).hexdigest()[:16] if event_id else ""
    action = clean_audit_identifier(record.get("action"), 80).lower()
    if action not in ALLOWED_AUDIT_ACTIONS:
        action = "unknown_action"
    return {
        "sequence": sequence,
        "time_utc": clean_audit_time(record.get("time_utc")),
        "event_id": event_id,
        "action": action,
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
    valid = bool(section.get("valid"))
    return {
        "valid": valid,
        "event_count": len(safe_events),
        "verification": (
            "Client reported that audit verification passed."
            if valid
            else "Client reported that audit verification failed or was unavailable."
        ),
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
    if "AntivirusSignatureLastUpdated" in status:
        safe["AntivirusSignatureLastUpdated"] = clean_audit_time(
            status.get("AntivirusSignatureLastUpdated")
        )
    for name in ("QuickScanAge", "FullScanAge"):
        if name in status:
            try:
                age = int(status.get(name))
            except (TypeError, ValueError):
                age = -1
            safe[name] = age if 0 <= age <= 100000 else "unknown"
    for name in ("LastQuickScanSource", "LastFullScanSource"):
        if name in status:
            try:
                source = int(status.get(name))
            except (TypeError, ValueError):
                source = -1
            safe[name] = source if 0 <= source <= 20 else "unknown"
    return safe


def clean_audit_report(report):
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object.")
    usb_section = clean_audit_section(report.get("usb_file_locker_audit"), MAX_AUDIT_EVENTS)
    remaining = MAX_AUDIT_EVENTS - len(usb_section["events"])
    safety_section = clean_audit_section(report.get("pc_safety_check_audit"), remaining)
    return {
        "report_type": "Privacy Safety Audit Report",
        "exported_at_utc": clean_audit_time(report.get("exported_at_utc")),
        "privacy_notice": (
            "This report contains no keystrokes, passwords, PINs, USB secrets, "
            "file contents, client names, or full file paths."
        ),
        "defender_status": clean_defender_status(report.get("defender_status")),
        "usb_file_locker_audit": usb_section,
        "pc_safety_check_audit": safety_section,
        "limitations": [
            "A clean audit report does not prove that the computer is malware-free.",
            "Use Microsoft Defender or another trusted antivirus for malware scanning.",
            "This report is not a HIPAA certification or legal-compliance determination.",
        ],
    }


def summarize_audit_breach(report):
    usb_section = report.get("usb_file_locker_audit") or {}
    safety_section = report.get("pc_safety_check_audit") or {}
    usb_events = list(usb_section.get("events") or [])
    safety_events = list(safety_section.get("events") or [])
    events = usb_events + safety_events
    signals = []

    def add_signal(level, title, count, summary):
        signals.append(
            {
                "level": level,
                "title": title,
                "count": int(count),
                "summary": summary,
            }
        )

    usb_valid = bool(usb_section.get("valid"))
    safety_valid = bool(safety_section.get("valid"))
    if not usb_valid:
        add_signal(
            "critical",
            "USB File Locker audit verification failed",
            1,
            "Treat the audit trail as damaged or tampered with until it is reviewed locally.",
        )
    if safety_events and not safety_valid:
        add_signal(
            "critical",
            "PC Safety Check audit verification failed",
            1,
            "The PC Safety Check trail contains events but did not verify.",
        )

    suspicious_actions = {"failed_access", "unlock_double_click", "login", "load_recent_key"}
    suspicious_failures = [
        event
        for event in events
        if event.get("result") == "failure" and event.get("action") in suspicious_actions
    ]
    timed_failures = []
    for event in suspicious_failures:
        try:
            moment = parse_utc(event.get("time_utc"))
        except (TypeError, ValueError):
            moment = None
        if moment is not None:
            timed_failures.append(moment)
    timed_failures.sort()
    strongest_burst = 0
    start = 0
    for end, moment in enumerate(timed_failures):
        while start < end and (moment - timed_failures[start]).total_seconds() > 10 * 60:
            start += 1
        strongest_burst = max(strongest_burst, end - start + 1)
    if strongest_burst >= 3:
        level = "high" if strongest_burst >= 5 else "warning"
        add_signal(
            level,
            "Repeated failed access attempts",
            strongest_burst,
            f"{strongest_burst} failed access or unlock attempts occurred within about 10 minutes.",
        )

    owner_removed = sum(event.get("action") == "owner_usb_removed" for event in events)
    if owner_removed:
        add_signal(
            "high",
            "Owner USB removed or replaced",
            owner_removed,
            f"{owner_removed} owner-USB removal event(s) were reported.",
        )

    key_removed = sum(event.get("action") == "usb_key_removed" for event in events)
    if key_removed:
        add_signal(
            "warning",
            "Loaded USB key disappeared",
            key_removed,
            f"{key_removed} loaded-key removal event(s) were reported.",
        )

    restores = sum(
        event.get("action") == "restore_app_data" and event.get("result") == "success"
        for event in events
    )
    if restores:
        add_signal(
            "warning",
            "App data restored from backup",
            restores,
            f"{restores} successful app-data restore event(s) were reported.",
        )

    configuration_changes = sum(event.get("action") == "configuration_change" for event in events)
    if configuration_changes >= 4:
        add_signal(
            "warning",
            "Many security setting changes",
            configuration_changes,
            f"{configuration_changes} configuration-change events were reported.",
        )

    defender = report.get("defender_status") or {}
    if defender.get("available") and "ProtectedNow" in defender and not defender.get("ProtectedNow"):
        add_signal(
            "warning",
            "Microsoft Defender not fully protected",
            1,
            "At least one reported Defender protection component was off.",
        )

    level_order = {"clear": 0, "warning": 1, "high": 2, "critical": 3}
    level = "clear"
    for signal in signals:
        if level_order[signal["level"]] > level_order[level]:
            level = signal["level"]
    headlines = {
        "clear": "No suspicious breach pattern was found in this uploaded audit snapshot.",
        "warning": "Warning-level activity needs review.",
        "high": "High-risk activity needs prompt review.",
        "critical": "Critical audit problems may indicate tampering or compromise.",
    }
    return {
        "level": level,
        "headline": headlines[level],
        "signal_count": len(signals),
        "signals": signals,
        "event_count": len(events),
        "audit_valid": usb_valid and (safety_valid or not safety_events),
        "defender_protected_now": bool(defender.get("ProtectedNow")),
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
    breach_summary = summarize_audit_breach(report)
    cleanup_expired_audit_exports()
    export_id = f"AUD-{secrets.token_hex(12).upper()}"
    uploaded_at = datetime.now(timezone.utc)
    expires_at = uploaded_at + timedelta(hours=AUDIT_EXPORT_RETENTION_HOURS)
    machine_id = str(payload.get("machine_id", "")).strip()
    machine_hash = hashlib.sha256(machine_id.encode("utf-8")).hexdigest()[:16]
    license_view = verification.get("license") or {}
    plan = verification.get("plan") or {}
    stored = {
        "schema_version": 2,
        "export_id": export_id,
        "uploaded_at_utc": format_utc(uploaded_at),
        "expires_at_utc": format_utc(expires_at),
        "source": {
            "license_id": clean_audit_text(license_view.get("license_id"), 80),
            "plan_id": clean_audit_text(plan.get("id"), 40),
            "machine_hash": machine_hash,
            "app_version": clean_audit_text(payload.get("app_version"), 40),
        },
        "breach_summary": breach_summary,
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
        "breach_summary": breach_summary,
        "server_time_utc": utc_now(),
    }


def read_stored_audit_export(export_id):
    path = audit_export_path(export_id)
    if not path.exists():
        raise FileNotFoundError("The audit export was not found or the server restarted.")
    body = path.read_bytes()
    if len(body) > MAX_AUDIT_REPORT_BYTES:
        raise ValueError("Stored audit export is too large.")
    try:
        stored = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Stored audit export is damaged.") from exc
    if not isinstance(stored, dict) or stored.get("export_id") != export_id:
        raise ValueError("Stored audit export identity did not verify.")
    return stored, body


def audit_export_metadata(stored, size_bytes):
    report = stored.get("report") or {}
    source = stored.get("source") or {}
    breach_summary = summarize_audit_breach(report)
    return {
        "export_id": clean_audit_identifier(stored.get("export_id"), 64),
        "uploaded_at_utc": clean_audit_time(stored.get("uploaded_at_utc")),
        "expires_at_utc": clean_audit_time(stored.get("expires_at_utc")),
        "source": {
            "license_id": clean_audit_text(source.get("license_id"), 80),
            "plan_id": clean_audit_text(source.get("plan_id"), 40),
            "machine_hash": clean_audit_text(source.get("machine_hash"), 16),
            "app_version": clean_audit_text(source.get("app_version"), 40),
        },
        "event_count": int(breach_summary.get("event_count", 0) or 0),
        "breach_summary": breach_summary,
        "size_bytes": int(size_bytes),
        "download_path": f"/api/v1/admin/audit-exports/{stored.get('export_id', '')}/download",
    }


def list_admin_audit_exports():
    cleanup_expired_audit_exports()
    if not AUDIT_EXPORT_DIR.exists():
        paths = []
    else:
        def modified_time(path):
            try:
                return path.stat().st_mtime
            except OSError:
                return 0

        paths = sorted(
            AUDIT_EXPORT_DIR.glob("AUD-*.json"),
            key=modified_time,
            reverse=True,
        )[:MAX_AUDIT_LIST_ITEMS]
    items = []
    damaged_count = 0
    for path in paths:
        try:
            stored, body = read_stored_audit_export(path.stem)
            items.append(audit_export_metadata(stored, len(body)))
        except (FileNotFoundError, OSError, ValueError):
            damaged_count += 1
    return {
        "ok": True,
        "items": items,
        "count": len(items),
        "damaged_count": damaged_count,
        "retention_hours": AUDIT_EXPORT_RETENTION_HOURS,
        "storage": "persistent_configured" if audit_storage_is_persistent() else "local_ephemeral",
        "privacy_notice": (
            "Stored reports contain only approved privacy-safe audit fields and anonymous machine hashes."
        ),
        "server_time_utc": utc_now(),
    }


def admin_dashboard_summary():
    license_inventory = list_admin_license_records()
    audit_inventory = list_admin_audit_exports()
    support_inventory = list_admin_support_tickets()
    announcement_inventory = list_admin_announcements()
    shop = shop_payload()
    now = datetime.now(timezone.utc)
    active_licenses = 0
    revoked_licenses = 0
    expired_licenses = 0
    active_devices = 0
    device_capacity = 0
    notes_saved = 0
    for item in license_inventory.get("items", []):
        if item.get("status") == "revoked":
            revoked_licenses += 1
        else:
            expires_at = parse_utc(item.get("expires_at_utc"))
            if expires_at and expires_at < now:
                expired_licenses += 1
            else:
                active_licenses += 1
                device_capacity += int(item.get("max_devices", 1) or 1)
        active_devices += int(item.get("active_devices", 0) or 0)
        notes_saved += bool(str(item.get("license_note", "")).strip())
    breach_levels = {"clear": 0, "warning": 0, "high": 0, "critical": 0}
    for item in audit_inventory.get("items", []):
        level = str((item.get("breach_summary") or {}).get("level", "clear")).lower()
        if level in breach_levels:
            breach_levels[level] += 1
    support_statuses = {status: 0 for status in SUPPORT_TICKET_STATUSES}
    for item in support_inventory.get("items", []):
        status = str(item.get("status", "open"))
        if status in support_statuses:
            support_statuses[status] += 1
    try:
        update_manifest, _package = load_windows_update_release()
        desktop_release = str(update_manifest.get("version", ""))
    except (FileNotFoundError, OSError, ValueError):
        desktop_release = ""
    return {
        "ok": True,
        "licenses": {
            "total": int(license_inventory.get("count", 0) or 0),
            "active": active_licenses,
            "revoked": revoked_licenses,
            "expired": expired_licenses,
            "notes_saved": notes_saved,
        },
        "devices": {
            "active": active_devices,
            "capacity": device_capacity,
        },
        "audit_exports": {
            "total": int(audit_inventory.get("count", 0) or 0),
            "breach_levels": breach_levels,
        },
        "support_tickets": {
            "total": int(support_inventory.get("count", 0) or 0),
            "statuses": support_statuses,
            "needs_action": support_statuses.get("open", 0) + support_statuses.get("acknowledged", 0),
        },
        "announcements": {
            "total": int(announcement_inventory.get("count", 0) or 0),
            "active": int(announcement_inventory.get("active_count", 0) or 0),
            "damaged": int(announcement_inventory.get("damaged_count", 0) or 0),
        },
        "shop": {
            "configured": int(shop.get("configured_count", 0) or 0),
            "total": int(shop.get("count", 0) or 0),
            "ready": bool(shop.get("ready")),
            "card_data_collected_by_vaultlink": False,
        },
        "storage": {
            "licenses": license_inventory.get("storage", "local_ephemeral"),
            "audit_exports": audit_inventory.get("storage", "local_ephemeral"),
            "support_tickets": support_inventory.get("storage", "local_ephemeral"),
            "announcements": announcement_inventory.get("storage", "local_ephemeral"),
        },
        "release": {
            "api_version": API_VERSION,
            "desktop_version": desktop_release,
            "license_sync_seconds": LICENSE_SYNC_INTERVAL_SECONDS,
        },
        "server_time_utc": utc_now(),
    }


def load_admin_audit_export_download(export_id):
    cleanup_expired_audit_exports()
    _stored, body = read_stored_audit_export(export_id)
    return body, f"vaultlink-audit-{export_id}.json"


def create_admin_audit_download_link(payload):
    export_id = clean_audit_identifier(payload.get("export_id"), 64)
    if not valid_audit_export_id(export_id):
        raise ValueError("Choose a valid audit export id.")
    stored, _body = read_stored_audit_export(export_id)
    machine_hash = str((stored.get("source") or {}).get("machine_hash", ""))
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=2)
    token = sign_token(
        AUDIT_DOWNLOAD_PREFIX,
        {
            "export_id": export_id,
            "machine_hash": machine_hash,
            "expires_at_utc": format_utc(expires_at),
            "scope": "owner_audit_download",
        },
    )
    return {
        "ok": True,
        "export_id": export_id,
        "filename": f"vaultlink-audit-{export_id}.json",
        "download_path": f"/api/v1/audit-exports/{export_id}/download?token={token}",
        "expires_at_utc": format_utc(expires_at),
        "message": "Created a two-minute report-only download link.",
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
    stored, body = read_stored_audit_export(export_id)
    stored_machine_hash = ((stored.get("source") or {}).get("machine_hash", ""))
    if not hmac.compare_digest(
        str(stored_machine_hash),
        str(token_payload.get("machine_hash", "")),
    ):
        raise PermissionError("Audit download token does not match the stored machine receipt.")
    return body, f"vaultlink-audit-{export_id}.json"


class ApiHandler(BaseHTTPRequestHandler):
    def send_json(self, payload, status=HTTPStatus.OK):
        body = json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html, status=HTTPStatus.OK):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def send_download(self, body, filename, content_type="application/json; charset=utf-8"):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self, max_bytes):
        if self.headers.get("Transfer-Encoding", "").strip():
            raise ValueError("Chunked request bodies are not supported.")
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError as exc:
            raise ValueError("Content-Length must be a whole number.") from exc
        if length < 0:
            raise ValueError("Content-Length cannot be negative.")
        if length > max_bytes:
            raise RequestTooLarge(f"Request body exceeds the {max_bytes}-byte limit for this route.")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if length and content_type != "application/json":
            raise UnsupportedMediaType("Content-Type must be application/json.")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return require_json_object(json.loads(raw.decode("utf-8")))
        except UnicodeDecodeError as exc:
            raise ValueError("Body must be valid UTF-8 JSON.") from exc
        except json.JSONDecodeError as exc:
            raise ValueError("Body must be valid JSON.") from exc

    def require_admin_token(self):
        configured = os.getenv("LICENSE_ADMIN_TOKEN", "").strip()
        if not configured:
            raise PermissionError("LICENSE_ADMIN_TOKEN is not configured on this server.")
        provided = self.headers.get("X-License-Admin-Token", "").strip()
        if not provided or not hmac.compare_digest(provided, configured):
            raise PermissionError("Admin token was missing or incorrect.")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/":
            self.send_html(homepage_html())
            return
        if path == "/shop":
            self.send_html(shop_html())
            return
        if path == "/docs":
            self.send_json(docs_payload())
            return
        if path == "/owner":
            self.send_html(owner_portal_html())
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
                    "license_state_storage": (
                        "persistent_configured" if license_state_storage_is_persistent() else "local_ephemeral"
                    ),
                    "license_private_fields_encrypted": True,
                    "device_seat_enforcement": True,
                    "automatic_license_sync": True,
                    "license_sync_interval_seconds": LICENSE_SYNC_INTERVAL_SECONDS,
                    "audit_exports_enabled": True,
                    "audit_export_storage": (
                        "persistent_configured" if audit_storage_is_persistent() else "local_ephemeral"
                    ),
                    "audit_export_retention_hours": AUDIT_EXPORT_RETENTION_HOURS,
                    "support_inbox_enabled": True,
                    "support_ticket_storage": (
                        "persistent_configured" if license_state_storage_is_persistent() else "local_ephemeral"
                    ),
                    "support_ticket_private_fields_encrypted": True,
                    "owner_announcements_enabled": True,
                    "owner_announcement_storage": (
                        "persistent_configured" if license_state_storage_is_persistent() else "local_ephemeral"
                    ),
                    "shop_enabled": True,
                    "shop_checkout_links_configured": shop_payload()["configured_count"],
                    "shop_card_data_collected_by_vaultlink": False,
                    "windows_update_published": UPDATE_MANIFEST_PATH.exists(),
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
        if path == "/api/v1/ranks":
            self.send_json({"items": public_plans(), "count": len(PLAN_TIERS)})
            return
        if path == "/api/v1/shop":
            self.send_json(shop_payload())
            return
        if path == "/api/v1/security":
            self.send_json(
                {
                    "license_mode": "signed_tokens_with_revocation_ledger",
                    "notes": SECURITY_NOTES,
                    "remote_actions_allowed": [
                        "admin license issue",
                        "license activate",
                        "license verify",
                        "automatic license heartbeat and revocation sync",
                        "customer device deactivation",
                        "admin license revoke, restore, note, device reset, individual device removal, inventory, and dashboard",
                        "license-authenticated privacy-safe audit export upload",
                        "signed short-lived audit export download",
                        "admin-protected audit export list and download",
                        "licensed encrypted bug reports and customer-visible owner replies",
                        "admin support-ticket status, reply, private note, and deletion actions",
                        "admin rank-targeted read-only owner announcements",
                        "public shop catalog and validated provider-hosted checkout links",
                    ],
                    "banned_remote_actions": [
                        "remote unlock",
                        "remote key creation",
                        "remote PIN capture",
                        "remote file reads",
                        "remote vault secret retrieval",
                        "automatic file or local-log attachment to support tickets",
                        "card-number collection or payment-secret storage",
                    ],
                    "license_limitations": [
                        "Device seats are enforced through anonymous machine hashes; no hardware names are stored in the activation ledger.",
                        "Configure LICENSE_STATE_DIR on a Railway Volume so revocations, activations, keys, and notes survive restarts.",
                        "LICENSE_RECORDS_SECRET should be configured separately and retained for encrypted-record recovery.",
                        "Support ticket text is encrypted with a key derived separately from LICENSE_RECORDS_SECRET.",
                    ],
                    "admin_authentication": "X-License-Admin-Token header only; never accepted in a JSON body.",
                    "audit_export_controls": [
                        "Only approved privacy-safe fields are retained.",
                        "Upload requires an active machine-bound license with Audit Log Viewer access.",
                        "Client downloads require a signed expiring bearer link.",
                        "Owner listing and downloads require the admin token in a request header.",
                        "Each stored report includes a server-calculated breach summary.",
                        "Configure AUDIT_EXPORT_DIR on a Railway Volume for restart-safe retention.",
                    ],
                    "support_ticket_controls": [
                        "Submission requires an active machine-bound license.",
                        "No files, local logs, secrets, raw machine ids, or PC names are attached automatically.",
                        "A per-device daily submission limit reduces spam.",
                        "Only the admin token can read all tickets, add private notes, reply, change status, or delete tickets.",
                    ],
                    "announcement_controls": [
                        "Only the admin token can publish or delete announcements.",
                        "Customers need an active machine-bound license and receive only notices allowed for their rank.",
                        "Announcements are plain read-only text; they cannot run commands, open files, or change settings.",
                        "Scheduled and expired notices are filtered by the server.",
                    ],
                    "shop_controls": [
                        "VaultLink never collects card numbers; checkout occurs on a separately hosted payment page.",
                        "Only HTTPS links on the configured checkout-host allowlist are published.",
                        "Missing or invalid links leave that tier visibly unavailable.",
                        "License delivery remains an owner action after independent payment confirmation.",
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
                        "LICENSE_STATE_DIR",
                        "LICENSE_RECORDS_SECRET",
                        "AUDIT_EXPORT_DIR",
                        "AUDIT_EXPORT_RETENTION_HOURS",
                        "SHOP_CHECKOUT_STARTER_URL",
                        "SHOP_CHECKOUT_HOME_URL",
                        "SHOP_CHECKOUT_PERSONAL_PLUS_URL",
                        "SHOP_CHECKOUT_FAMILY_SAFETY_URL",
                        "SHOP_CHECKOUT_SMALL_OFFICE_URL",
                        "SHOP_CHECKOUT_FAMILY_OFFICE_URL",
                        "SHOP_CHECKOUT_PRO_BASELINE_URL",
                        "SHOP_CHECKOUT_ALLOWED_HOSTS",
                    ],
                }
            )
            return
        if path == "/api/v1/updates/windows":
            try:
                self.send_json(windows_update_payload())
            except (FileNotFoundError, OSError, ValueError) as exc:
                self.send_json(
                    {"ok": False, "error": "update_unavailable", "message": str(exc)},
                    status=HTTPStatus.SERVICE_UNAVAILABLE,
                )
            return
        if path == "/api/v1/updates/windows/download":
            try:
                manifest, package_path = load_windows_update_release()
                self.send_download(
                    package_path.read_bytes(),
                    manifest["package_filename"],
                    content_type="application/zip",
                )
            except (FileNotFoundError, OSError, ValueError) as exc:
                self.send_json(
                    {"ok": False, "error": "update_unavailable", "message": str(exc)},
                    status=HTTPStatus.SERVICE_UNAVAILABLE,
                )
            return
        parts = path.strip("/").split("/")
        if path == "/api/v1/admin/audit-exports":
            try:
                self.require_admin_token()
                self.send_json(list_admin_audit_exports())
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        if path == "/api/v1/admin/licenses":
            try:
                self.require_admin_token()
                self.send_json(list_admin_license_records())
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        if path == "/api/v1/admin/support-tickets":
            try:
                self.require_admin_token()
                self.send_json(list_admin_support_tickets())
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        if path == "/api/v1/admin/announcements":
            try:
                self.require_admin_token()
                self.send_json(list_admin_announcements())
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        if path == "/api/v1/admin/dashboard":
            try:
                self.require_admin_token()
                self.send_json(admin_dashboard_summary())
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        if (
            len(parts) == 6
            and parts[:4] == ["api", "v1", "admin", "licenses"]
            and parts[5] == "devices"
        ):
            try:
                self.require_admin_token()
                self.send_json(admin_license_devices(parts[4]))
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
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        if (
            len(parts) == 6
            and parts[:4] == ["api", "v1", "admin", "audit-exports"]
            and parts[5] == "download"
        ):
            try:
                self.require_admin_token()
                body, filename = load_admin_audit_export_download(parts[4])
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
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
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
                if not token and parsed.query:
                    query = parse_qs(parsed.query, keep_blank_values=False, max_num_fields=4)
                    token = str((query.get("token") or [""])[0]).strip()
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
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
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
        route_limits = {
            "/api/v1/licenses/issue": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/activate": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/verify": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/sync": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/deactivate": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/revoke": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/restore": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/note": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/reset-devices": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/remove-device": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/support-tickets": MAX_SUPPORT_JSON_BODY_BYTES,
            "/api/v1/support-tickets/mine": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/admin/support-tickets/action": MAX_SUPPORT_JSON_BODY_BYTES,
            "/api/v1/admin/support-tickets/delete": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/announcements/mine": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/admin/announcements/create": MAX_SUPPORT_JSON_BODY_BYTES,
            "/api/v1/admin/announcements/delete": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/admin/audit-exports/download-link": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/audit-exports": MAX_AUDIT_JSON_BODY_BYTES,
        }
        if path not in route_limits:
            self.send_json(
                {
                    "error": "not_found",
                    "message": "Route not found.",
                    "docs": "/docs",
                },
                status=HTTPStatus.NOT_FOUND,
            )
            return
        try:
            payload = self.read_json(route_limits[path])
            if path == "/api/v1/licenses/issue":
                self.require_admin_token()
                self.send_json(issue_license(payload), status=HTTPStatus.CREATED)
                return
            if path == "/api/v1/licenses/activate":
                self.send_json(activate_license(payload))
                return
            if path == "/api/v1/licenses/verify":
                self.send_json(verify_license(payload))
                return
            if path == "/api/v1/licenses/sync":
                self.send_json(sync_license(payload))
                return
            if path == "/api/v1/licenses/deactivate":
                self.send_json(deactivate_license(payload))
                return
            if path == "/api/v1/licenses/revoke":
                self.require_admin_token()
                self.send_json(revoke_license(payload))
                return
            if path == "/api/v1/licenses/restore":
                self.require_admin_token()
                self.send_json(restore_license(payload))
                return
            if path == "/api/v1/licenses/note":
                self.require_admin_token()
                self.send_json(update_license_note(payload))
                return
            if path == "/api/v1/licenses/reset-devices":
                self.require_admin_token()
                self.send_json(admin_reset_license_devices(payload))
                return
            if path == "/api/v1/licenses/remove-device":
                self.require_admin_token()
                self.send_json(admin_remove_license_device(payload))
                return
            if path == "/api/v1/support-tickets":
                self.send_json(create_support_ticket(payload), status=HTTPStatus.CREATED)
                return
            if path == "/api/v1/support-tickets/mine":
                self.send_json(list_my_support_tickets(payload))
                return
            if path == "/api/v1/admin/support-tickets/action":
                self.require_admin_token()
                self.send_json(admin_update_support_ticket(payload))
                return
            if path == "/api/v1/admin/support-tickets/delete":
                self.require_admin_token()
                self.send_json(admin_delete_support_ticket(payload))
                return
            if path == "/api/v1/announcements/mine":
                self.send_json(list_my_announcements(payload))
                return
            if path == "/api/v1/admin/announcements/create":
                self.require_admin_token()
                self.send_json(admin_create_announcement(payload), status=HTTPStatus.CREATED)
                return
            if path == "/api/v1/admin/announcements/delete":
                self.require_admin_token()
                self.send_json(admin_delete_announcement(payload))
                return
            if path == "/api/v1/admin/audit-exports/download-link":
                self.require_admin_token()
                self.send_json(create_admin_audit_download_link(payload))
                return
            if path == "/api/v1/audit-exports":
                self.send_json(create_audit_export(payload), status=HTTPStatus.CREATED)
                return
        except RequestTooLarge as exc:
            self.send_json(
                {
                    "ok": False,
                    "error": "request_too_large",
                    "message": str(exc),
                },
                status=413,
            )
        except UnsupportedMediaType as exc:
            self.send_json(
                {
                    "ok": False,
                    "error": "unsupported_media_type",
                    "message": str(exc),
                },
                status=HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
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
        except FileNotFoundError as exc:
            self.send_json(
                {
                    "ok": False,
                    "error": "not_found",
                    "message": str(exc),
                },
                status=HTTPStatus.NOT_FOUND,
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
        except Exception:
            self.send_json(
                {
                    "ok": False,
                    "error": "server_error",
                    "message": "Internal server error.",
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
