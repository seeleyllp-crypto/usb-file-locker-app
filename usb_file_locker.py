import base64
import ctypes
import hashlib
import hmac
import json
import os
import platform
import queue
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from tkinter import filedialog, messagebox, simpledialog, ttk

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SOURCE_DIR = Path(__file__).resolve().parent
RUNTIME_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else SOURCE_DIR
APP_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "USBFileLocker"
APP_DIR.mkdir(parents=True, exist_ok=True)
BOOTSTRAP_MAX_AUDIT_BACKUPS = 5
MAX_RECENT_KEYS = 8
DESKTOP_APP_VERSION = "2026.07.14.7"
LAB_MODE = os.environ.get("VAULTLINK_LAB_MODE", "").strip() == "1"
DEFAULT_LICENSE_SERVER = "https://enthusiastic-exploration-production-b87d.up.railway.app"
UPDATE_SIGNING_PUBLIC_KEY_B64 = "UhQt7KyhSd6na6ZL5zmvOTKMgQqdY3FUEdoKRX-iGKU"
UPDATE_SIGNING_KEY_ID = "4f8fb9b8dbffd4c0"
MAX_UPDATE_MANIFEST_BYTES = 64 * 1024
MAX_UPDATE_PACKAGE_BYTES = 50 * 1024 * 1024
MAX_UPDATE_ARCHIVE_FILES = 5000
MAX_UPDATE_EXTRACTED_BYTES = 100 * 1024 * 1024
LICENSE_STATE_ENTROPY = b"USBFileLockerLicenseStateV1"
LICENSE_MAX_AGE_DAYS = 30
LICENSE_BACKGROUND_REFRESH_SECONDS = 60
INITIAL_LICENSE_REFRESH_MS = 1000
LICENSE_MIN_REFRESH_SECONDS = 30
LICENSE_MAX_REFRESH_SECONDS = 300
LICENSE_GATE_REFRESH_SECONDS = 75
LICENSE_GATE_HTTP_TIMEOUT_SECONDS = 5
MAX_API_RESPONSE_BYTES = 1024 * 1024
MAX_AUDIT_API_DOWNLOAD_BYTES = 4 * 1024 * 1024
PLAN_FEATURE_TITLES = {
    "recovery-drill-center": "Recovery Drill Center",
    "incident-response-center": "Incident Response Center",
    "diagnostics-center": "Diagnostics Center",
    "trust-recovery-center": "Trust and Recovery Center",
    "portable-locking": "Portable locking tools",
    "quick-lock-note": "Quick lock notes",
    "home-guides": "Home safety guides",
    "personal-vault": "Personal Vault",
    "locked-file-browser": "Locked File Browser",
    "audit-log-viewer": "Audit Log Viewer",
    "perm-unlock": "PERM UNLOCK workflow",
    "personal-safety-report": "Personal Safety Report",
    "privacy-safety-hub": "Privacy Safety Hub",
    "global-breach-guard": "Global Breach Guard",
    "text-log-processor": "Text Log Processor",
    "owner-usb-mode": "Owner USB mode",
    "family-device-reports": "Family device reports",
    "office-readiness": "Small Office readiness pack",
    "family-office-bundle": "Family Office evidence bundle",
    "signature-bundle": "Owner-signed release bundle",
    "pro-baseline-pack": "Pro Baseline review pack",
}
PLAN_FEATURE_REQUIREMENTS = {
    "recovery-drill-center": "$5 Starter",
    "incident-response-center": "$5 Starter",
    "diagnostics-center": "$5 Starter",
    "trust-recovery-center": "$5 Starter",
    "portable-locking": "$5 Starter",
    "quick-lock-note": "$5 Starter",
    "home-guides": "$10-$25 Home",
    "personal-vault": "$50 Personal Plus",
    "locked-file-browser": "$50 Personal Plus",
    "audit-log-viewer": "$50 Personal Plus",
    "perm-unlock": "$50 Personal Plus",
    "personal-safety-report": "$50 Personal Plus",
    "privacy-safety-hub": "$100 Family Safety",
    "global-breach-guard": "$100 Family Safety",
    "text-log-processor": "$100 Family Safety",
    "owner-usb-mode": "$100 Family Safety",
    "family-device-reports": "$100 Family Safety",
    "office-readiness": "$200 Small Office",
    "family-office-bundle": "$500-$3,000 Family Office",
    "signature-bundle": "$20,000+ Pro Baseline",
    "pro-baseline-pack": "$20,000+ Pro Baseline",
}
LICENSE_PLAN_IDS = {
    "starter",
    "home",
    "personal-plus",
    "family-safety",
    "small-office",
    "family-office",
    "pro-baseline",
}
SCRIPT_LICENSE_FEATURES = {
    "recovery_drill_center.py": "recovery-drill-center",
    "incident_response_center.py": "incident-response-center",
    "diagnostics_center.py": "diagnostics-center",
    "trust_recovery_center.py": "trust-recovery-center",
    "privacy_safety_hub.py": "privacy-safety-hub",
    "personal_vault_pad.py": "personal-vault",
    "audit_log_viewer.py": "audit-log-viewer",
    "global_breach_guard.py": "global-breach-guard",
    "text_log_processor.py": "text-log-processor",
    "locked_file_browser.py": "locked-file-browser",
    "vault_health_center.py": "locked-file-browser",
    "perm_unlock_workbench.py": "perm-unlock",
}


def normalize_saved_path(path):
    text = str(path).strip()
    if not text:
        return ""
    try:
        return str(Path(text))
    except Exception:
        return text


def merge_recent_key_paths(*groups):
    cleaned = []
    seen = set()
    for group in groups:
        if group is None:
            continue
        if isinstance(group, (str, Path)):
            group = [group]
        for item in group:
            text = normalize_saved_path(item)
            if not text:
                continue
            marker = os.path.normcase(text)
            if marker in seen:
                continue
            seen.add(marker)
            cleaned.append(text)
            if len(cleaned) >= MAX_RECENT_KEYS:
                return cleaned
    return cleaned


def recent_key_paths_from_settings(settings):
    if not isinstance(settings, dict):
        return []
    return merge_recent_key_paths(settings.get("last_key_path"), settings.get("recent_key_paths", []))


def remember_recent_key_path(settings, path):
    cleaned = merge_recent_key_paths(path, recent_key_paths_from_settings(settings))
    settings["recent_key_paths"] = cleaned
    if cleaned:
        settings["last_key_path"] = cleaned[0]
    return cleaned


def remove_missing_recent_key_paths(settings):
    kept = [path for path in recent_key_paths_from_settings(settings) if Path(path).exists()]
    settings["recent_key_paths"] = kept
    if kept:
        settings["last_key_path"] = kept[0]
    elif settings.get("last_key_path") and not Path(str(settings.get("last_key_path"))).exists():
        settings.pop("last_key_path", None)
    return kept


def normalize_security_profile_name(name):
    lowered = str(name or "").strip().lower()
    aliases = {
        "": "strong",
        "default": "strong",
        "hardened": "strong",
        "max": "maximum",
    }
    lowered = aliases.get(lowered, lowered)
    return lowered if lowered in {"balanced", "strong", "maximum"} else "strong"


def bootstrap_candidate_dirs():
    seen = set()
    ordered = []
    for candidate in (SOURCE_DIR, RUNTIME_DIR):
        try:
            resolved = candidate.resolve()
        except Exception:
            resolved = candidate
        if resolved in seen or resolved == APP_DIR:
            continue
        seen.add(resolved)
        ordered.append(resolved)
    return ordered


def bootstrap_read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


def bootstrap_write_json(path, payload):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def migrate_bootstrap_settings(legacy_dirs):
    destination = APP_DIR / "settings.json"
    merged = bootstrap_read_json(destination)
    if not isinstance(merged, dict):
        merged = {}
    changed = False
    for legacy_dir in legacy_dirs:
        source = legacy_dir / "settings.json"
        if not source.exists():
            continue
        source_settings = bootstrap_read_json(source)
        if not isinstance(source_settings, dict):
            continue
        source_key = source_settings.get("last_key_path")
        current_key = merged.get("last_key_path")
        current_key_exists = bool(current_key) and Path(str(current_key)).exists()
        source_key_exists = bool(source_key) and Path(str(source_key)).exists()
        if source_key and (not current_key or (source_key_exists and not current_key_exists)):
            merged["last_key_path"] = source_key
            changed = True
        source_owner_policy = source_settings.get("owner_usb_policy")
        if source_owner_policy and not merged.get("owner_usb_policy"):
            merged["owner_usb_policy"] = source_owner_policy
            changed = True
        merged_recent = merge_recent_key_paths(
            merged.get("last_key_path"),
            source_settings.get("last_key_path"),
            merged.get("recent_key_paths", []),
            source_settings.get("recent_key_paths", []),
        )
        if merged_recent != merged.get("recent_key_paths", []):
            merged["recent_key_paths"] = merged_recent
            changed = True
        if merged_recent and not merged.get("last_key_path"):
            merged["last_key_path"] = merged_recent[0]
            changed = True
    if changed or (merged and not destination.exists()):
        bootstrap_write_json(destination, merged)
        return ["settings.json"]
    return []


def migrate_bootstrap_files():
    legacy_dirs = bootstrap_candidate_dirs()
    migrated = migrate_bootstrap_settings(legacy_dirs)
    names = [
        "audit_key.dpapi",
        "audit_log.jsonl",
        "personal_vault.usblock",
        "audit_verification.json",
        "locker_log.jsonl",
    ]
    names.extend(f"audit_log.{index}.jsonl" for index in range(1, BOOTSTRAP_MAX_AUDIT_BACKUPS + 1))
    for legacy_dir in legacy_dirs:
        for name in names:
            source = legacy_dir / name
            destination = APP_DIR / name
            if not source.exists() or source.is_dir() or destination.exists():
                continue
            try:
                shutil.copy2(source, destination)
                migrated.append(name)
            except Exception:
                pass
    return migrated


BOOTSTRAP_MIGRATED_FILES = migrate_bootstrap_files()
LOG_FILE = APP_DIR / "audit_log.jsonl"
AUDIT_KEY_FILE = APP_DIR / "audit_key.dpapi"
SETTINGS_FILE = APP_DIR / "settings.json"
VAULT_FILE = APP_DIR / "personal_vault.usblock"
TEMP_DIR = APP_DIR / "temp"
LEGACY_MAGIC = b"USBLOCK1\n"
PORTABLE_MAGIC = b"USBLOCK2\n"
VAULT_MAGIC = b"USBVAULT1\n"
PORTABLE_FORMAT_VERSION = 2
PORTABLE_TAG_SIZE = 16
PORTABLE_CHUNK_SIZE = 1024 * 1024
MAX_LOCKED_HEADER_BYTES = 64 * 1024
DEFAULT_SECURITY_PROFILE = "strong"
SECURITY_PROFILES = {
    "balanced": {
        "label": "Balanced",
        "kdf_n": 2**15,
        "kdf_r": 8,
        "kdf_p": 1,
        "salt_bytes": 16,
        "memory_mb": 32,
    },
    "strong": {
        "label": "Strong",
        "kdf_n": 2**17,
        "kdf_r": 8,
        "kdf_p": 1,
        "salt_bytes": 32,
        "memory_mb": 128,
    },
    "maximum": {
        "label": "Maximum",
        "kdf_n": 2**18,
        "kdf_r": 8,
        "kdf_p": 1,
        "salt_bytes": 32,
        "memory_mb": 256,
    },
}
MIN_KDF_N = 2**14
MAX_KDF_N = 2**20
MIN_KDF_R = 1
MAX_KDF_R = 32
MIN_KDF_P = 1
MAX_KDF_P = 16
PERSONAL_TYPES = [
    "Client record",
    "Session note",
    "Treatment document",
    "Consent form",
    "Passcode",
    "Recovery code",
    "Account",
    "Email",
    "Phone",
    "Address",
    "Private note",
    "Other",
]
PERSONAL_FILE_KEYWORDS = [
    "password",
    "passcode",
    "recovery",
    "backupcode",
    "backup_code",
    "account",
    "login",
    "secret",
    "private",
    "2fa",
    "steam",
    "email",
    "phone",
    "address",
    "wallet",
    "key",
    "note",
    "client",
    "patient",
    "session",
    "therapy",
    "treatment",
    "intake",
    "assessment",
    "progressnote",
    "progress_note",
    "case_note",
    "consent",
    "insurance",
]
PERSONAL_FILE_EXTS = {
    ".txt",
    ".csv",
    ".json",
    ".rtf",
    ".doc",
    ".docx",
    ".pdf",
    ".xls",
    ".xlsx",
}
MAX_SCAN_RESULTS = 300
MAX_SCAN_FILE_SIZE = 25 * 1024 * 1024

BG = "#0f1115"
PANEL = "#171a21"
FIELD = "#0a0c10"
TEXT = "#f4f4f5"
MUTED = "#a7adbb"
GREEN = "#24e66f"
YELLOW = "#ffd166"
RED = "#ff5a66"
BLUE = "#58b7e8"
WHITE = "#ffffff"
BLACK = "#050505"
TEXT_VIEW_EXTS = {".txt", ".log", ".md", ".csv", ".json"}
TEMP_DELETE_SECONDS = 10 * 60
MAX_AUDIT_LOG_BYTES = 1024 * 1024
MAX_AUDIT_BACKUPS = BOOTSTRAP_MAX_AUDIT_BACKUPS
AUDIT_KEY_ENTROPY = hashlib.sha256(b"USBFileLocker-Audit-v1").digest()
PC_SAFETY_AUDIT_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "PCSafetyCheck"
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
_AUDIT_KEY_CACHE = None
OWNER_POLICY_ENTROPY = hashlib.sha256(b"USBFileLocker-OwnerUSB-v1").digest()
DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6
WALK_SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    "appdata",
    "windows",
    "program files",
    "program files (x86)",
}

CRYPTPROTECT_UI_FORBIDDEN = 0x1


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32

crypt32.CryptProtectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    wintypes.LPCWSTR,
    ctypes.POINTER(DATA_BLOB),
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
]
crypt32.CryptProtectData.restype = wintypes.BOOL

crypt32.CryptUnprotectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    ctypes.POINTER(wintypes.LPWSTR),
    ctypes.POINTER(DATA_BLOB),
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
]
crypt32.CryptUnprotectData.restype = wintypes.BOOL

kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
kernel32.LocalFree.restype = wintypes.HLOCAL
kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
kernel32.GetDriveTypeW.restype = wintypes.UINT
kernel32.GetVolumeInformationW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPWSTR,
    wintypes.DWORD,
]
kernel32.GetVolumeInformationW.restype = wintypes.BOOL


def make_blob(data):
    buffer = ctypes.create_string_buffer(data)
    blob = DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    return blob, buffer


def blob_to_bytes(blob):
    return ctypes.string_at(blob.pbData, blob.cbData)


def local_free(ptr):
    if ptr:
        kernel32.LocalFree(ctypes.c_void_p(ctypes.addressof(ptr.contents)))


def dpapi_protect(data, entropy):
    in_blob, in_buffer = make_blob(data)
    entropy_blob, entropy_buffer = make_blob(entropy)
    out_blob = DATA_BLOB()
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "USB File Locker",
        ctypes.byref(entropy_blob),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError()
    try:
        return blob_to_bytes(out_blob)
    finally:
        local_free(out_blob.pbData)


def dpapi_unprotect(data, entropy):
    in_blob, in_buffer = make_blob(data)
    entropy_blob, entropy_buffer = make_blob(entropy)
    out_blob = DATA_BLOB()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(entropy_blob),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError()
    try:
        return blob_to_bytes(out_blob)
    finally:
        local_free(out_blob.pbData)


def protect_app_data_permissions():
    if not getattr(sys, "frozen", False):
        return
    username = os.environ.get("USERNAME")
    if not username:
        return
    try:
        subprocess.run(
            [
                "icacls.exe",
                str(APP_DIR),
                "/inheritance:r",
                "/grant:r",
                f"{username}:(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ],
            capture_output=True,
            creationflags=0x08000000,
            timeout=15,
            check=False,
        )
    except Exception:
        pass


def secure_mkstemp(prefix, suffix=""):
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    if getattr(sys, "frozen", False):
        protect_app_data_permissions()
    return tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=TEMP_DIR)


def secure_mkdtemp(prefix):
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    if getattr(sys, "frozen", False):
        protect_app_data_permissions()
    return Path(tempfile.mkdtemp(prefix=prefix, dir=TEMP_DIR))


def cleanup_stale_secure_temp(max_age_seconds=24 * 60 * 60):
    if not TEMP_DIR.exists():
        return
    cutoff = time.time() - max_age_seconds
    for candidate in TEMP_DIR.iterdir():
        try:
            if candidate.stat().st_mtime > cutoff:
                continue
            if candidate.is_dir():
                shutil.rmtree(candidate)
            else:
                candidate.unlink()
        except OSError:
            pass


def audit_backup_path(index):
    return APP_DIR / f"audit_log.{index}.jsonl"


def get_audit_key():
    global _AUDIT_KEY_CACHE
    if _AUDIT_KEY_CACHE is not None:
        return _AUDIT_KEY_CACHE
    if AUDIT_KEY_FILE.exists():
        _AUDIT_KEY_CACHE = dpapi_unprotect(AUDIT_KEY_FILE.read_bytes(), AUDIT_KEY_ENTROPY)
        if len(_AUDIT_KEY_CACHE) != 32:
            raise ValueError("The protected audit key is invalid.")
        return _AUDIT_KEY_CACHE
    key = secrets.token_bytes(32)
    protected = dpapi_protect(key, AUDIT_KEY_ENTROPY)
    write_bytes_atomic(AUDIT_KEY_FILE, protected)
    _AUDIT_KEY_CACHE = key
    return key


def canonical_audit_record(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def load_audit_records(path):
    records = []
    path = Path(path)
    if not path.exists():
        return records
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def latest_audit_record():
    for path in [LOG_FILE] + [audit_backup_path(index) for index in range(1, MAX_AUDIT_BACKUPS + 1)]:
        try:
            records = load_audit_records(path)
            if records:
                return records[-1]
        except Exception:
            raise ValueError("The audit log cannot be read or may have been altered.")
    return None


def rotate_audit_log_if_needed():
    if not LOG_FILE.exists() or LOG_FILE.stat().st_size < MAX_AUDIT_LOG_BYTES:
        return
    oldest = audit_backup_path(MAX_AUDIT_BACKUPS)
    oldest.unlink(missing_ok=True)
    for index in range(MAX_AUDIT_BACKUPS - 1, 0, -1):
        source = audit_backup_path(index)
        if source.exists():
            os.replace(source, audit_backup_path(index + 1))
    os.replace(LOG_FILE, audit_backup_path(1))


def log_event(action, path, result, detail=""):
    try:
        protect_app_data_permissions()
        rotate_audit_log_if_needed()
        previous = latest_audit_record()
        sequence = int(previous.get("sequence", 0)) + 1 if previous else 1
        previous_hash = previous.get("hash", "0" * 64) if previous else "0" * 64
        normalized_result = "success" if str(result).lower() in {"ok", "success", "passed"} else "failure"
        record = {
            "version": 1,
            "sequence": sequence,
            "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event_id": secrets.token_hex(8),
            "action": str(action)[:80],
            "result": normalized_result,
            "previous_hash": previous_hash,
        }
        record["hash"] = hmac.new(
            get_audit_key(),
            canonical_audit_record(record),
            hashlib.sha256,
        ).hexdigest()
        with LOG_FILE.open("a", encoding="utf-8") as file:
            file.write(json.dumps(record, sort_keys=True) + "\n")
            file.flush()
            os.fsync(file.fileno())
        return True
    except Exception:
        return False


def verify_audit_logs():
    paths = [
        path
        for path in [audit_backup_path(index) for index in range(MAX_AUDIT_BACKUPS, 0, -1)] + [LOG_FILE]
        if path.exists()
    ]
    if not paths:
        return True, 0, "No audit events have been recorded yet."
    key = get_audit_key()
    all_records = []
    for path in paths:
        all_records.extend(load_audit_records(path))
    if not all_records:
        return True, 0, "No audit events have been recorded yet."
    expected_previous = all_records[0].get("previous_hash")
    expected_sequence = int(all_records[0].get("sequence", 0))
    for record in all_records:
        stored_hash = record.get("hash", "")
        unsigned = dict(record)
        unsigned.pop("hash", None)
        calculated = hmac.new(key, canonical_audit_record(unsigned), hashlib.sha256).hexdigest()
        if (
            int(record.get("sequence", -1)) != expected_sequence
            or record.get("previous_hash") != expected_previous
            or not hmac.compare_digest(stored_hash, calculated)
        ):
            return False, len(all_records), f"Verification failed at anonymous event {record.get('event_id', 'unknown')}."
        expected_previous = stored_hash
        expected_sequence += 1
    return True, len(all_records), "Hash chain and event signatures are valid."


def load_all_audit_records(base_dir=None):
    base = Path(base_dir or APP_DIR)
    records = []
    for path in audit_log_paths(base):
        if path.exists():
            records.extend(load_audit_records(path))
    return records


def parse_audit_time(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def format_audit_time(value):
    parsed = parse_audit_time(value) if isinstance(value, str) else value
    if parsed is None:
        return "unknown time"
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def breach_detection_summary(records=None, verification=None):
    records = list(records if records is not None else load_all_audit_records(APP_DIR))
    if verification is None:
        verification = verify_audit_logs()
    valid, count, message = verification
    signals = []

    if not valid:
        signals.append(
            {
                "level": "critical",
                "title": "Audit chain verification failed",
                "summary": message,
            }
        )

    def latest_event_text(matches):
        if not matches:
            return ""
        latest = matches[-1]
        return f" Latest event: seq {latest.get('sequence')} at {format_audit_time(latest.get('time_utc'))}."

    suspicious_failures = [
        record
        for record in records
        if record.get("result") == "failure"
        and record.get("action") in {"failed_access", "unlock_double_click", "login", "load_recent_key"}
    ]
    if suspicious_failures:
        windows = []
        start = 0
        parsed_times = [parse_audit_time(record.get("time_utc")) for record in suspicious_failures]
        for end in range(len(suspicious_failures)):
            end_time = parsed_times[end]
            if end_time is None:
                continue
            while start < end and parsed_times[start] is not None and (end_time - parsed_times[start]).total_seconds() > 10 * 60:
                start += 1
            window_count = end - start + 1
            windows.append((window_count, start, end))
        strongest = max(windows, default=(0, 0, 0), key=lambda item: item[0])
        burst_count = strongest[0]
        if burst_count >= 5:
            level = "high"
        elif burst_count >= 3:
            level = "warning"
        else:
            level = ""
        if level:
            end_record = suspicious_failures[strongest[2]]
            signals.append(
                {
                    "level": level,
                    "title": "Repeated failed access attempts",
                    "summary": (
                        f"{burst_count} failed access or unlock attempts happened within about 10 minutes."
                        f" Latest burst ended at seq {end_record.get('sequence')} on {format_audit_time(end_record.get('time_utc'))}."
                    ),
                }
            )

    owner_removed = [record for record in records if record.get("action") == "owner_usb_removed"]
    if owner_removed:
        signals.append(
            {
                "level": "high",
                "title": "Owner USB was removed or replaced",
                "summary": f"{len(owner_removed)} owner-USB removal event(s) were recorded.{latest_event_text(owner_removed)}",
            }
        )

    key_removed = [record for record in records if record.get("action") == "usb_key_removed"]
    if key_removed:
        signals.append(
            {
                "level": "warning",
                "title": "Loaded USB key disappeared",
                "summary": f"{len(key_removed)} loaded-key removal event(s) were recorded.{latest_event_text(key_removed)}",
            }
        )

    restores = [record for record in records if record.get("action") == "restore_app_data" and record.get("result") == "success"]
    if restores:
        signals.append(
            {
                "level": "warning",
                "title": "App data was restored from backup",
                "summary": f"{len(restores)} app-data restore event(s) were recorded.{latest_event_text(restores)}",
            }
        )

    config_changes = [record for record in records if record.get("action") == "configuration_change"]
    if len(config_changes) >= 4:
        signals.append(
            {
                "level": "warning",
                "title": "Many security setting changes were recorded",
                "summary": f"{len(config_changes)} configuration-change events were logged.{latest_event_text(config_changes)}",
            }
        )

    level_order = {"clear": 0, "warning": 1, "high": 2, "critical": 3}
    highest = "clear"
    for signal in signals:
        if level_order[signal["level"]] > level_order[highest]:
            highest = signal["level"]
    if highest == "clear":
        headline = "No suspicious breach pattern was detected in the signed audit trail."
    elif highest == "warning":
        headline = "Breach detection found warning-level activity worth reviewing."
    elif highest == "high":
        headline = "Breach detection found high-risk activity. Review it now."
    else:
        headline = "Breach detection found critical audit problems. Treat this as tamper or compromise until checked."

    return {
        "level": highest,
        "headline": headline,
        "signals": signals,
        "record_count": count,
        "audit_valid": valid,
        "audit_message": message,
        "latest_time": records[-1].get("time_utc") if records else "",
    }


def breach_detection_text(summary):
    lines = [summary["headline"], f"Audit records checked: {summary['record_count']}. {summary['audit_message']}"]
    if summary["signals"]:
        lines.append("")
        for signal in summary["signals"]:
            lines.append(f"[{signal['level'].upper()}] {signal['title']}: {signal['summary']}")
    else:
        lines.append("")
        lines.append("No repeated failed access bursts, owner-USB removals, restore events, or suspicious config-change bursts were detected.")
    return "\n".join(lines)


def open_breach_detection_window(parent, records=None, verification=None):
    summary = breach_detection_summary(records=records, verification=verification)
    window = tk.Toplevel(parent)
    if hasattr(parent, "register_secondary_window"):
        try:
            parent.register_secondary_window(window)
        except Exception:
            pass
    window.title("Breach Detection")
    window.geometry("860x560")
    window.minsize(760, 480)
    window.configure(bg=BG)

    outer = tk.Frame(window, bg=BG)
    outer.pack(fill="both", expand=True, padx=18, pady=16)

    color = {"clear": GREEN, "warning": YELLOW, "high": RED, "critical": RED}.get(summary["level"], TEXT)
    tk.Label(outer, text="Breach Detection", bg=BG, fg=TEXT, font=("Segoe UI", 24, "bold")).pack(anchor="w")
    tk.Label(outer, text=summary["headline"], bg=BG, fg=color, font=("Segoe UI", 10, "bold"), wraplength=800, justify="left").pack(anchor="w", pady=(4, 12))

    text = tk.Text(outer, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", bd=0, wrap="word", font=("Consolas", 10))
    text.pack(fill="both", expand=True)
    text.insert("1.0", breach_detection_text(summary))
    text.configure(state="disabled")

    row = tk.Frame(outer, bg=BG)
    row.pack(fill="x", pady=(12, 0))
    tk.Button(row, text="COPY REPORT", command=lambda: (parent.clipboard_clear(), parent.clipboard_append(breach_detection_text(summary)), parent.update()), bg=WHITE, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=12, ipady=8)
    tk.Button(row, text="CLOSE", command=window.destroy, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=16, ipady=8)
    return window, summary


def export_audit_logs(destination):
    destination = ensure_directory_destination(destination, "audit export destination")
    copied = 0
    already_present = 0
    for path in [LOG_FILE] + [audit_backup_path(index) for index in range(1, MAX_AUDIT_BACKUPS + 1)]:
        if path.exists():
            target = destination / path.name
            try:
                same_target = path.resolve() == target.resolve()
            except Exception:
                same_target = False
            if same_target:
                already_present += 1
                continue
            shutil.copy2(path, target)
            copied += 1
    valid, count, message = verify_audit_logs()
    summary = {
        "exported_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "valid": valid,
        "event_count": count,
        "verification": message,
        "privacy": "No keystrokes, secrets, client names, file contents, or full paths are recorded.",
        "already_present": already_present,
    }
    write_text_atomic(destination / "audit_verification.json", json.dumps(summary, indent=2))
    return copied, summary


def audit_log_paths(base_dir):
    base_dir = Path(base_dir)
    return [base_dir / f"audit_log.{index}.jsonl" for index in range(MAX_AUDIT_BACKUPS, 0, -1)] + [base_dir / "audit_log.jsonl"]


def public_audit_records(records):
    public = []
    for record in records:
        public.append(
            {
                "sequence": record.get("sequence"),
                "time_utc": record.get("time_utc"),
                "event_id": record.get("event_id"),
                "action": record.get("action"),
                "result": record.get("result"),
                "hash": record.get("hash"),
                "previous_hash": record.get("previous_hash"),
            }
        )
    return public


def verify_plain_hmac_audit_logs(base_dir, key_file):
    base_dir = Path(base_dir)
    key_file = Path(key_file)
    if not base_dir.exists() or not key_file.exists():
        return False, 0, "No PC Safety Check audit log was found for this Windows user.", []
    key = key_file.read_bytes()
    if len(key) != 32:
        return False, 0, "PC Safety Check audit key is invalid.", []
    records = []
    for path in audit_log_paths(base_dir):
        if path.exists():
            records.extend(load_audit_records(path))
    if not records:
        return True, 0, "No PC Safety Check audit events have been recorded yet.", []
    expected_previous = records[0].get("previous_hash")
    expected_sequence = int(records[0].get("sequence", 0))
    for record in records:
        stored_hash = record.get("hash", "")
        unsigned = dict(record)
        unsigned.pop("hash", None)
        calculated = hmac.new(key, canonical_audit_record(unsigned), hashlib.sha256).hexdigest()
        if (
            int(record.get("sequence", -1)) != expected_sequence
            or record.get("previous_hash") != expected_previous
            or not hmac.compare_digest(stored_hash, calculated)
        ):
            return False, len(records), f"PC Safety Check audit verification failed at event {record.get('event_id', 'unknown')}.", records
        expected_previous = stored_hash
        expected_sequence += 1
    return True, len(records), "PC Safety Check audit hash chain is valid.", records


def get_defender_status_report():
    script = r"""
$s = Get-MpComputerStatus
[pscustomobject]@{
    AntivirusEnabled = [bool]$s.AntivirusEnabled
    RealTimeProtectionEnabled = [bool]$s.RealTimeProtectionEnabled
    BehaviorMonitorEnabled = [bool]$s.BehaviorMonitorEnabled
    IoavProtectionEnabled = [bool]$s.IoavProtectionEnabled
    AntivirusSignatureLastUpdated = if ($s.AntivirusSignatureLastUpdated) { $s.AntivirusSignatureLastUpdated.ToString("o") } else { $null }
    QuickScanAge = $s.QuickScanAge
    FullScanAge = $s.FullScanAge
    LastQuickScanSource = $s.LastQuickScanSource
    LastFullScanSource = $s.LastFullScanSource
} | ConvertTo-Json -Compress
"""
    try:
        result = subprocess.run(
            [
                str(POWERSHELL),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            creationflags=0x08000000,
            timeout=30,
        )
        if result.returncode != 0:
            error = result.stderr.strip() or result.stdout.strip() or f"PowerShell exited with code {result.returncode}."
            return {"available": False, "error": error}
        data = json.loads(result.stdout)
        protected = all(
            data.get(name)
            for name in (
                "AntivirusEnabled",
                "RealTimeProtectionEnabled",
                "BehaviorMonitorEnabled",
                "IoavProtectionEnabled",
            )
        )
        data["ProtectedNow"] = protected
        data["available"] = True
        return data
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def build_audit_report():
    usb_valid, usb_count, usb_message = verify_audit_logs()
    usb_records = []
    for path in audit_log_paths(APP_DIR):
        if path.exists():
            usb_records.extend(load_audit_records(path))

    pc_valid, pc_count, pc_message, pc_records = verify_plain_hmac_audit_logs(
        PC_SAFETY_AUDIT_DIR,
        PC_SAFETY_AUDIT_DIR / "audit_key.bin",
    )

    return {
        "report_type": "Privacy Safety Locked Audit Report",
        "exported_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "privacy_notice": "This report never includes keystrokes, passwords, PINs, USB secrets, file contents, client names, or full file paths.",
        "defender_status": get_defender_status_report(),
        "usb_file_locker_audit": {
            "valid": usb_valid,
            "event_count": usb_count,
            "verification": usb_message,
            "events": public_audit_records(usb_records),
        },
        "pc_safety_check_audit": {
            "valid": pc_valid,
            "event_count": pc_count,
            "verification": pc_message,
            "events": public_audit_records(pc_records),
        },
        "limitations": [
            "A clean report does not prove the computer can never have malware.",
            "Use Microsoft Defender or another trusted antivirus for current malware scans.",
            "This app is not HIPAA certified and does not prove legal compliance.",
        ],
    }


def audit_report_snapshot_fingerprint(report):
    ignored_actions = {"audit_api_auto_upload", "audit_api_export"}
    snapshot = {"sections": {}, "defender": {}}
    for section_name in ("usb_file_locker_audit", "pc_safety_check_audit"):
        section = report.get(section_name) or {}
        events = [
            event
            for event in (section.get("events") or [])
            if isinstance(event, dict) and event.get("action") not in ignored_actions
        ]
        latest = events[-1] if events else {}
        snapshot["sections"][section_name] = {
            "valid": bool(section.get("valid")),
            "event_count": len(events),
            "latest_sequence": latest.get("sequence"),
            "latest_action": latest.get("action"),
            "latest_result": latest.get("result"),
            "latest_hash": latest.get("hash"),
        }
    defender = report.get("defender_status") or {}
    for field in (
        "available",
        "AntivirusEnabled",
        "RealTimeProtectionEnabled",
        "BehaviorMonitorEnabled",
        "IoavProtectionEnabled",
        "ProtectedNow",
    ):
        snapshot["defender"][field] = bool(defender.get(field))
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def export_locked_audit_report(destination, key, pin):
    destination = ensure_directory_destination(destination, "locked audit export destination")
    report = build_audit_report()
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    temp_dir = secure_mkdtemp(prefix="usb_locker_audit_")
    plain_path = temp_dir / f"privacy_safety_audit_report_{timestamp}.json"
    locked_temp_path = None
    try:
        plain_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        locked_temp_path = lock_file(plain_path, key, pin)
        final_path = unique_path(destination / locked_temp_path.name)
        shutil.move(str(locked_temp_path), final_path)
        return final_path, report
    finally:
        try:
            plain_path.unlink(missing_ok=True)
        except Exception:
            pass
        if locked_temp_path is not None:
            try:
                Path(locked_temp_path).unlink(missing_ok=True)
            except Exception:
                pass
        try:
            temp_dir.rmdir()
        except Exception:
            pass


def app_data_backup_files():
    files = []
    seen = set()
    candidates = [
        SETTINGS_FILE,
        AUDIT_KEY_FILE,
        VAULT_FILE,
        APP_DIR / "audit_verification.json",
        APP_DIR / "locker_log.jsonl",
    ] + audit_log_paths(APP_DIR)
    for candidate in candidates:
        path = Path(candidate)
        if not path.exists() or path.is_dir():
            continue
        key = os.path.normcase(str(path))
        if key in seen:
            continue
        seen.add(key)
        files.append(path)
    return files


def export_app_data_backup(destination):
    destination = ensure_directory_destination(destination, "app data backup destination")
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    backup_dir = unique_path(destination / f"usb_file_locker_backup_{timestamp}")
    backup_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for source in app_data_backup_files():
        shutil.copy2(source, backup_dir / source.name)
        copied.append(source.name)
    summary = {
        "exported_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_data_folder": str(APP_DIR),
        "copied_files": copied,
        "includes_usb_key_files": False,
        "includes_locked_user_files": False,
        "recent_key_count": len(recent_key_paths_from_settings(load_settings())),
        "note": "This backup includes app settings, audit data, and the personal vault if present. It does not include USB key files.",
    }
    write_text_atomic(backup_dir / "backup_summary.json", json.dumps(summary, indent=2))
    return backup_dir, copied, summary


def restorable_app_data_names():
    names = {
        "settings.json",
        "audit_key.dpapi",
        "audit_log.jsonl",
        "personal_vault.usblock",
        "audit_verification.json",
        "locker_log.jsonl",
    }
    names.update(f"audit_log.{index}.jsonl" for index in range(1, MAX_AUDIT_BACKUPS + 1))
    return names


def app_data_backup_candidates(source_dir):
    source_dir = Path(source_dir)
    if not source_dir.exists() or not source_dir.is_dir():
        raise ValueError("Choose a backup folder, not a file.")
    files = []
    for name in sorted(restorable_app_data_names()):
        candidate = source_dir / name
        if candidate.exists() and candidate.is_file():
            files.append(candidate)
    if not files:
        raise ValueError("No restorable USB File Locker backup files were found in that folder.")
    return files


def restore_app_data_backup(source_dir):
    source_dir = Path(source_dir)
    restore_files = app_data_backup_candidates(source_dir)
    restore_root = APP_DIR / "restore_backups"
    restore_root.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    snapshot_dir = restore_root / f"before_restore_{timestamp}"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    snapshot_files = []
    for current in app_data_backup_files():
        shutil.copy2(current, snapshot_dir / current.name)
        snapshot_files.append(current.name)
    restored_files = []
    for source in restore_files:
        shutil.copy2(source, APP_DIR / source.name)
        restored_files.append(source.name)
    summary = {
        "restored_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "restored_from": str(source_dir),
        "snapshot_dir": str(snapshot_dir),
        "restored_files": restored_files,
        "snapshot_files": snapshot_files,
        "note": "USB key files were not restored because app-data backups never include them.",
    }
    write_text_atomic(snapshot_dir / "restore_summary.json", json.dumps(summary, indent=2))
    return snapshot_dir, restored_files, summary


def load_settings():
    if not SETTINGS_FILE.exists():
        return {}
    try:
        return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_settings(settings):
    normalized = dict(settings)
    recent = merge_recent_key_paths(normalized.get("last_key_path"), normalized.get("recent_key_paths", []))
    if recent:
        normalized["recent_key_paths"] = recent
        normalized["last_key_path"] = recent[0]
    else:
        normalized.pop("recent_key_paths", None)
    normalized["security_profile"] = normalize_security_profile_name(normalized.get("security_profile", DEFAULT_SECURITY_PROFILE))
    write_text_atomic(SETTINGS_FILE, json.dumps(normalized, indent=2))


def write_bytes_atomic(path, data):
    target = Path(path)
    if target.exists() and target.is_dir():
        raise ValueError(f"Choose a file name, not the folder {target}.")
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_path = target.parent / f".{target.name}.{secrets.token_hex(8)}.tmp"
    try:
        with open(temp_path, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, target)
        return target
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass


def write_text_atomic(path, text, encoding="utf-8"):
    return write_bytes_atomic(path, text.encode(encoding))


def runtime_search_dirs():
    seen = set()
    ordered = []
    current = RUNTIME_DIR
    for candidate in (current, current.parent, current.parent.parent):
        try:
            resolved = candidate.resolve()
        except Exception:
            resolved = candidate
        if resolved in seen:
            continue
        seen.add(resolved)
        ordered.append(resolved)
    return ordered


def bundled_key_candidates():
    names = (
        "master_usb_file_locker.key",
        "owner_master_usb_file_locker.key",
    )
    folders = (
        "",
        "Owner Key",
        "OWNER KEY",
        "Owner",
        "OWNER",
    )
    candidates = []
    for base in runtime_search_dirs():
        for folder in folders:
            folder_path = base / folder if folder else base
            for name in names:
                candidate = folder_path / name
                if candidate.exists():
                    candidates.append(candidate)
    return candidates


def bundled_owner_policy_candidates():
    names = (
        "owner_usb_policy.json",
        "portable_owner_policy.json",
    )
    folders = (
        "",
        "Owner Key",
        "OWNER KEY",
        "Owner",
        "OWNER",
    )
    candidates = []
    for base in runtime_search_dirs():
        for folder in folders:
            folder_path = base / folder if folder else base
            for name in names:
                candidate = folder_path / name
                if candidate.exists():
                    candidates.append(candidate)
    return candidates


def drive_type_name(code):
    return {
        DRIVE_UNKNOWN: "unknown",
        DRIVE_NO_ROOT_DIR: "missing",
        DRIVE_REMOVABLE: "removable",
        DRIVE_FIXED: "fixed",
        DRIVE_REMOTE: "network",
        DRIVE_CDROM: "cdrom",
        DRIVE_RAMDISK: "ramdisk",
    }.get(code, f"type_{code}")


def path_drive_root(path):
    resolved = Path(path).resolve()
    root = resolved.anchor or Path(path).anchor
    if not root:
        raise ValueError("That path is not on a normal Windows drive.")
    if not root.endswith("\\"):
        root += "\\"
    return root


def volume_identity(path):
    root = path_drive_root(path)
    drive_type = int(kernel32.GetDriveTypeW(root))
    volume_name = ctypes.create_unicode_buffer(260)
    filesystem_name = ctypes.create_unicode_buffer(260)
    serial = wintypes.DWORD()
    max_component = wintypes.DWORD()
    flags = wintypes.DWORD()
    ok = kernel32.GetVolumeInformationW(
        root,
        volume_name,
        len(volume_name),
        ctypes.byref(serial),
        ctypes.byref(max_component),
        ctypes.byref(flags),
        filesystem_name,
        len(filesystem_name),
    )
    if not ok:
        raise ctypes.WinError()
    return {
        "root": root,
        "serial": f"{serial.value:08X}",
        "label": volume_name.value or "(no label)",
        "filesystem": filesystem_name.value or "",
        "drive_type": drive_type,
        "drive_type_name": drive_type_name(drive_type),
    }


def key_location_summary(key):
    origin = key.get("origin")
    if not origin:
        return key.get("path", "")
    return f"{origin['root']} {origin['label']} [{origin['drive_type_name']}]"


def owner_policy_description(policy):
    return (
        f"{policy.get('volume_root', '?')} {policy.get('volume_label', '(no label)')} "
        f"[{policy.get('drive_type_name', 'unknown')}] key {policy.get('key_id', '?')}"
    )


def load_owner_policy(settings):
    encoded = settings.get("owner_usb_policy")
    if not encoded:
        for candidate in bundled_owner_policy_candidates():
            try:
                policy = json.loads(candidate.read_text(encoding="utf-8"))
                if isinstance(policy, dict):
                    return policy
            except Exception:
                continue
        return None
    try:
        encrypted = base64.b64decode(encoded.encode("ascii"), validate=True)
        plain = dpapi_unprotect(encrypted, OWNER_POLICY_ENTROPY)
        policy = json.loads(plain.decode("utf-8"))
        return policy if isinstance(policy, dict) else None
    except Exception:
        for candidate in bundled_owner_policy_candidates():
            try:
                policy = json.loads(candidate.read_text(encoding="utf-8"))
                if isinstance(policy, dict):
                    return policy
            except Exception:
                continue
        return None


def save_owner_policy(settings, policy):
    if policy:
        plain = json.dumps(policy, sort_keys=True).encode("utf-8")
        settings["owner_usb_policy"] = base64.b64encode(dpapi_protect(plain, OWNER_POLICY_ENTROPY)).decode("ascii")
    else:
        settings.pop("owner_usb_policy", None)
    save_settings(settings)


def utc_now_text():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc_text(value):
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).astimezone(timezone.utc)
    except Exception:
        return None


def license_state_template():
    return {
        "server_url": DEFAULT_LICENSE_SERVER,
        "license_key": "",
        "receipt": "",
        "status": "unlicensed",
        "plan_id": "",
        "plan_name": "",
        "features": [],
        "machine_id": "",
        "machine_name": "",
        "license_id": "",
        "customer_label": "",
        "customer_email": "",
        "license_expires_at": "",
        "receipt_expires_at": "",
        "last_checked_utc": "",
        "api_version": "",
        "sync_interval_seconds": LICENSE_BACKGROUND_REFRESH_SECONDS,
        "last_decision_id": "",
        "last_sync_result": "",
        "device_active": 0,
        "device_maximum": 0,
        "latest_desktop_version": "",
        "minimum_supported_version": "",
        "update_available": False,
        "service_status": {},
        "announcements": [],
        "last_error": "",
    }


def normalize_license_server_url(url):
    text = str(url or "").strip()
    if not text:
        return DEFAULT_LICENSE_SERVER
    return text.rstrip("/")


def validated_license_server_url(url):
    text = normalize_license_server_url(url)
    parsed = urllib.parse.urlparse(text)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("License API URL must be a complete http:// or https:// address.")
    if parsed.username or parsed.password:
        raise ValueError("License API URL cannot contain a username or password.")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ValueError("License API URL must be the server address without a path, query, or fragment.")
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" and hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("License API must use HTTPS. Plain HTTP is allowed only for local testing.")
    return text


def valid_api_license_key(key):
    parts = str(key or "").strip().split(".")
    if len(parts) != 3 or parts[0] != "vlk1":
        return False
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    return all(len(part) >= 16 and all(character in allowed for character in part) for part in parts[1:])


def require_valid_api_license_key(key):
    text = str(key or "").strip()
    if not text:
        raise ValueError("Paste a license key first.")
    if not valid_api_license_key(text):
        raise ValueError("This is not a VaultLink API license key. A valid key starts with vlk1.")
    return text


def license_state_with_key(state, new_key, server_url=None):
    current = normalize_license_state(state)
    key = str(new_key or "").strip()
    selected_server = normalize_license_server_url(server_url or current.get("server_url"))
    if key == current.get("license_key"):
        current["server_url"] = selected_server
        return normalize_license_state(current)
    replacement = license_state_template()
    replacement["server_url"] = selected_server
    replacement["license_key"] = key
    replacement["status"] = "saved" if key else "unlicensed"
    replacement["machine_id"] = current_machine_fingerprint()
    replacement["machine_name"] = current_machine_name()
    return normalize_license_state(replacement)


class NoApiRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


API_URL_OPENER = urllib.request.build_opener(NoApiRedirectHandler())


def current_machine_fingerprint():
    pieces = [
        os.environ.get("COMPUTERNAME", ""),
        os.environ.get("USERNAME", ""),
        os.environ.get("USERDOMAIN", ""),
        platform.node(),
        platform.system(),
        platform.release(),
        os.environ.get("PROCESSOR_ARCHITECTURE", ""),
    ]
    try:
        identity = volume_identity(APP_DIR)
        pieces.extend([identity.get("serial", ""), identity.get("label", "")])
    except Exception:
        pass
    data = "|".join(piece for piece in pieces if piece).encode("utf-8")
    if not data:
        data = b"usb-file-locker-machine"
    return hashlib.sha256(data).hexdigest()[:32].upper()


def current_machine_name():
    return (
        os.environ.get("COMPUTERNAME")
        or platform.node()
        or "This PC"
    )


def normalize_service_status(value):
    raw = value if isinstance(value, dict) else {}
    mode = str(raw.get("mode", "normal") or "normal").strip().lower()
    if mode not in {"normal", "degraded", "maintenance"}:
        mode = "normal"
    message = str(raw.get("message", "") or "").strip()[:240]
    if not message:
        message = "All VaultLink services are operating normally."
    return {
        "mode": mode,
        "message": message,
        "updated_at_utc": str(raw.get("updated_at_utc", "") or "").strip()[:40],
        "expires_at_utc": str(raw.get("expires_at_utc", "") or "").strip()[:40],
    }


def normalize_owner_announcements(value):
    raw_items = value if isinstance(value, list) else []
    items = []
    for raw in raw_items[:5]:
        if not isinstance(raw, dict):
            continue
        announcement_id = str(raw.get("announcement_id", "") or "").strip().upper()
        if (
            not announcement_id.startswith("ANN-")
            or len(announcement_id) > 64
            or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in announcement_id)
        ):
            continue
        severity = str(raw.get("severity", "info") or "info").strip().lower()
        if severity not in {"info", "update", "maintenance", "security"}:
            severity = "info"
        items.append(
            {
                "announcement_id": announcement_id,
                "severity": severity,
                "title": str(raw.get("title", "") or "").strip()[:120],
                "message": str(raw.get("message", "") or "").strip()[:2000],
                "audience": str(raw.get("audience", "") or "").strip()[:80],
                "created_at_utc": str(raw.get("created_at_utc", "") or "").strip()[:40],
                "expires_at_utc": str(raw.get("expires_at_utc", "") or "").strip()[:40],
            }
        )
    return items


def normalize_license_state(data=None):
    state = license_state_template()
    if isinstance(data, dict):
        for key in state:
            if key in data:
                state[key] = data[key]
    state["server_url"] = normalize_license_server_url(state.get("server_url"))
    state["license_key"] = str(state.get("license_key", "") or "").strip()
    state["receipt"] = str(state.get("receipt", "") or "").strip()
    state["status"] = str(state.get("status", "unlicensed") or "unlicensed").strip().lower()
    state["plan_id"] = str(state.get("plan_id", "") or "").strip().lower()
    state["plan_name"] = str(state.get("plan_name", "") or "").strip()
    state["machine_id"] = str(state.get("machine_id", "") or "").strip() or current_machine_fingerprint()
    state["machine_name"] = str(state.get("machine_name", "") or "").strip() or current_machine_name()
    state["license_id"] = str(state.get("license_id", "") or "").strip()
    state["customer_label"] = str(state.get("customer_label", "") or "").strip()
    state["customer_email"] = str(state.get("customer_email", "") or "").strip()
    state["license_expires_at"] = str(state.get("license_expires_at", "") or "").strip()
    state["receipt_expires_at"] = str(state.get("receipt_expires_at", "") or "").strip()
    state["last_checked_utc"] = str(state.get("last_checked_utc", "") or "").strip()
    state["api_version"] = str(state.get("api_version", "") or "").strip()[:80]
    state["last_decision_id"] = str(state.get("last_decision_id", "") or "").strip()[:80]
    state["last_sync_result"] = str(state.get("last_sync_result", "") or "").strip().lower()[:80]
    state["latest_desktop_version"] = str(state.get("latest_desktop_version", "") or "").strip()[:80]
    state["minimum_supported_version"] = str(state.get("minimum_supported_version", "") or "").strip()[:80]
    state["update_available"] = bool(state.get("update_available", False))
    for field, default in (
        ("sync_interval_seconds", LICENSE_BACKGROUND_REFRESH_SECONDS),
        ("device_active", 0),
        ("device_maximum", 0),
    ):
        try:
            state[field] = max(0, int(state.get(field, default) or 0))
        except (TypeError, ValueError):
            state[field] = default
    state["sync_interval_seconds"] = min(
        max(state["sync_interval_seconds"] or LICENSE_BACKGROUND_REFRESH_SECONDS, LICENSE_MIN_REFRESH_SECONDS),
        LICENSE_MAX_REFRESH_SECONDS,
    )
    state["last_error"] = str(state.get("last_error", "") or "").strip()
    state["service_status"] = normalize_service_status(state.get("service_status"))
    state["announcements"] = normalize_owner_announcements(state.get("announcements"))
    features = state.get("features", [])
    if isinstance(features, str):
        features = [features]
    state["features"] = sorted({str(item).strip() for item in features if str(item).strip()})
    return state


def load_license_state(settings):
    settings = settings if isinstance(settings, dict) else {}
    encoded = settings.get("license_state")
    if encoded:
        try:
            encrypted = base64.b64decode(str(encoded).encode("ascii"), validate=True)
            plain = dpapi_unprotect(encrypted, LICENSE_STATE_ENTROPY)
            payload = json.loads(plain.decode("utf-8"))
            return normalize_license_state(payload if isinstance(payload, dict) else {})
        except Exception:
            pass
    legacy = settings.get("license")
    if isinstance(legacy, dict):
        return normalize_license_state(legacy)
    return normalize_license_state({})


def save_license_state(settings, state):
    normalized = normalize_license_state(state)
    plain = json.dumps(normalized, sort_keys=True).encode("utf-8")
    settings["license_state"] = base64.b64encode(dpapi_protect(plain, LICENSE_STATE_ENTROPY)).decode("ascii")
    settings.pop("license", None)
    save_settings(settings)
    return normalized


def clear_license_state(settings, server_url=None):
    state = license_state_template()
    if server_url:
        state["server_url"] = normalize_license_server_url(server_url)
    return save_license_state(settings, state)


def masked_license_key(key):
    text = str(key or "").strip()
    if len(text) <= 14:
        return text
    return f"{text[:8]}...{text[-6:]}"


def feature_title(feature_id):
    return PLAN_FEATURE_TITLES.get(feature_id, feature_id.replace("-", " ").title())


def feature_required_plan(feature_id):
    return PLAN_FEATURE_REQUIREMENTS.get(feature_id, "an active license")


def license_is_active(state):
    current = normalize_license_state(state)
    if current.get("status") != "active":
        return False
    if not current.get("license_key") or not current.get("receipt"):
        return False
    if current.get("machine_id") != current_machine_fingerprint():
        return False
    receipt_expires = parse_utc_text(current.get("receipt_expires_at"))
    if receipt_expires and receipt_expires < datetime.now(timezone.utc):
        return False
    if current.get("last_checked_utc"):
        checked = parse_utc_text(current.get("last_checked_utc"))
        if checked and checked < datetime.now(timezone.utc) - timedelta(days=LICENSE_MAX_AGE_DAYS):
            return False
    return True


def license_feature_allowed(feature_id, settings=None, state=None):
    if not feature_id:
        return True
    current = normalize_license_state(state if state is not None else load_license_state(settings or load_settings()))
    if not license_is_active(current):
        return False
    return feature_id in set(current.get("features", []))


def license_check_age_seconds(state, now=None):
    checked = parse_utc_text(normalize_license_state(state).get("last_checked_utc"))
    if checked is None:
        return None
    current_time = now or datetime.now(timezone.utc)
    return max(0.0, (current_time - checked).total_seconds())


def recommended_license_refresh_seconds(state):
    current = normalize_license_state(state)
    return min(
        max(int(current.get("sync_interval_seconds") or LICENSE_BACKGROUND_REFRESH_SECONDS), LICENSE_MIN_REFRESH_SECONDS),
        LICENSE_MAX_REFRESH_SECONDS,
    )


def refresh_license_for_feature_gate(settings=None, max_age_seconds=LICENSE_GATE_REFRESH_SECONDS):
    current_settings = settings if isinstance(settings, dict) else load_settings()
    state = load_license_state(current_settings)
    if not state.get("license_key") or not state.get("receipt"):
        return state
    age = license_check_age_seconds(state)
    if age is not None and age <= max(0, int(max_age_seconds)):
        return state
    try:
        updated = verify_license_online(state, timeout=LICENSE_GATE_HTTP_TIMEOUT_SECONDS)
    except Exception as exc:
        updated = build_license_failure_state(state, exc)
    return save_license_state(current_settings, updated)


def license_status_text(state):
    current = normalize_license_state(state)
    if license_is_active(current):
        plan_name = current.get("plan_name") or current.get("plan_id", "").title()
        return f"License active: {plan_name}"
    if current.get("license_key"):
        status = current.get("status", "saved").replace("_", " ").upper()
        return f"License saved: {status}"
    return "License inactive: open License Center"


def customer_center_details(state, settings=None):
    current = normalize_license_state(state)
    service = normalize_service_status(current.get("service_status"))
    announcements = normalize_owner_announcements(current.get("announcements"))
    plan_name = current.get("plan_name") or current.get("plan_id", "").replace("-", " ").title() or "No active plan"
    latest = current.get("latest_desktop_version") or "Not checked"
    update_state = "UPDATE READY" if current.get("update_available") else "CURRENT OR NOT CHECKED"
    return {
        "license_status": str(current.get("status", "unlicensed")).replace("_", " ").upper(),
        "plan": plan_name,
        "device_seats": f"{int(current.get('device_active', 0) or 0)}/{int(current.get('device_maximum', 0) or 0)}",
        "desktop": f"{DESKTOP_APP_VERSION} | latest {latest} | {update_state}",
        "api": current.get("api_version") or "Not checked",
        "service": f"{service['mode'].upper()} | {service['message']}",
        "last_sync": current.get("last_checked_utc") or "Never",
        "owner_messages": str(len(announcements)),
        "automatic_updates": "ON" if bool((settings or {}).get("auto_install_signed_updates", False)) else "OFF",
    }


def license_summary_text(state):
    current = normalize_license_state(state)
    lines = [
        f"Server: {current.get('server_url') or DEFAULT_LICENSE_SERVER}",
        f"Machine ID: {current.get('machine_id') or current_machine_fingerprint()}",
    ]
    if current.get("license_key"):
        lines.append(f"License key: {masked_license_key(current['license_key'])}")
    if current.get("plan_name"):
        lines.append(f"Plan: {current['plan_name']}")
    if current.get("last_checked_utc"):
        lines.append(f"Last checked: {current['last_checked_utc']}")
    lines.append(f"Automatic API sync: every {recommended_license_refresh_seconds(current)} seconds")
    if current.get("api_version"):
        lines.append(f"API version: {current['api_version']}")
    if current.get("last_decision_id"):
        lines.append(f"Last decision ID: {current['last_decision_id']}")
    if current.get("device_maximum"):
        lines.append(f"Device seats: {current.get('device_active', 0)}/{current['device_maximum']}")
    if current.get("latest_desktop_version"):
        release_state = "update ready" if current.get("update_available") else "current"
        lines.append(f"Desktop release: {current['latest_desktop_version']} ({release_state})")
    if current.get("receipt_expires_at"):
        lines.append(f"Receipt expires: {current['receipt_expires_at']}")
    if current.get("last_error"):
        lines.append(f"Last error: {current['last_error']}")
    return "\n".join(lines)


def license_feature_lines(state):
    current = normalize_license_state(state)
    features = current.get("features", [])
    if not features:
        return "No premium entitlements loaded yet."
    return "\n".join(f"- {feature_title(feature_id)}" for feature_id in features)


def license_required_message(feature_id):
    return (
        f"{feature_title(feature_id)} needs an active {feature_required_plan(feature_id)} license.\n\n"
        f"Open License Center, paste the license key, and activate it on this PC.\n\n"
        f"Unlocking existing files and recovery tools still stay available."
    )


def ensure_license_feature(feature_id, parent=None, show_message=True):
    state = refresh_license_for_feature_gate()
    if parent is not None and hasattr(parent, "update_license_state_ui"):
        try:
            parent.update_license_state_ui(state)
            if hasattr(parent, "apply_access_state"):
                parent.apply_access_state()
        except Exception:
            pass
    if license_feature_allowed(feature_id, state=state):
        return True
    if show_message:
        messagebox.showwarning("License required", license_required_message(feature_id), parent=parent)
    return False


def license_api_post_json(server_url, api_path, payload, extra_headers=None, timeout=15):
    url = validated_license_server_url(server_url) + api_path
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with API_URL_OPENER.open(request, timeout=max(1, min(int(timeout), 60))) as response:
            raw_bytes = response.read(MAX_API_RESPONSE_BYTES + 1)
            if len(raw_bytes) > MAX_API_RESPONSE_BYTES:
                raise ValueError("API response was too large.")
            raw = raw_bytes.decode("utf-8")
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(MAX_API_RESPONSE_BYTES + 1).decode("utf-8", errors="replace")
            if 300 <= exc.code < 400:
                raise ValueError("API redirects are blocked to protect license credentials.") from exc
            try:
                payload = json.loads(raw)
                message = payload.get("message") or payload.get("error") or raw
            except Exception:
                message = raw or f"API server returned HTTP {exc.code}."
            raise ValueError(message) from exc
        finally:
            exc.close()
    except urllib.error.URLError as exc:
        raise ValueError(f"Could not reach the API server.\n\n{exc.reason}") from exc
    try:
        payload = json.loads(raw) if raw else {}
    except Exception as exc:
        raise ValueError("API server returned invalid JSON.") from exc
    if not isinstance(payload, dict):
        raise ValueError("API server returned an unexpected response.")
    if payload.get("ok") is False:
        raise ValueError(str(payload.get("message") or payload.get("error") or "License request failed."))
    return payload


def license_api_get_json(server_url, api_path, extra_headers=None):
    path = str(api_path or "").strip()
    if not path.startswith("/api/v1/") or "://" in path or "\\" in path or "\r" in path or "\n" in path:
        raise ValueError("API path format is invalid.")
    url = validated_license_server_url(server_url) + path
    headers = {"Accept": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with API_URL_OPENER.open(request, timeout=20) as response:
            raw_bytes = response.read(MAX_API_RESPONSE_BYTES + 1)
            if len(raw_bytes) > MAX_API_RESPONSE_BYTES:
                raise ValueError("API response was too large.")
            raw = raw_bytes.decode("utf-8")
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(MAX_API_RESPONSE_BYTES + 1).decode("utf-8", errors="replace")
            if 300 <= exc.code < 400:
                raise ValueError("API redirects are blocked to protect admin credentials.") from exc
            try:
                error_payload = json.loads(raw)
                message = error_payload.get("message") or error_payload.get("error") or raw
            except Exception:
                message = raw or f"API server returned HTTP {exc.code}."
            raise ValueError(message) from exc
        finally:
            exc.close()
    except urllib.error.URLError as exc:
        raise ValueError(f"Could not reach the API server.\n\n{exc.reason}") from exc
    try:
        payload = json.loads(raw) if raw else {}
    except Exception as exc:
        raise ValueError("API server returned invalid JSON.") from exc
    if not isinstance(payload, dict):
        raise ValueError("API server returned an unexpected response.")
    if payload.get("ok") is False:
        raise ValueError(str(payload.get("message") or payload.get("error") or "API request failed."))
    return payload


def update_version_tuple(value):
    text = str(value or "").strip()
    parts = text.split(".")
    if not text or len(parts) > 8 or any(not part.isdigit() for part in parts):
        raise ValueError("Update version format is invalid.")
    return tuple(int(part) for part in parts)


def compare_update_versions(left, right):
    left_parts = update_version_tuple(left)
    right_parts = update_version_tuple(right)
    length = max(len(left_parts), len(right_parts))
    return (left_parts + (0,) * (length - len(left_parts))) > (right_parts + (0,) * (length - len(right_parts)))


def decode_update_base64url(value):
    text = str(value or "").strip()
    if not text or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in text):
        raise ValueError("Update signature encoding is invalid.")
    try:
        return base64.urlsafe_b64decode(text + "=" * ((4 - len(text) % 4) % 4))
    except Exception as exc:
        raise ValueError("Update signature encoding is invalid.") from exc


def canonical_update_manifest_bytes(manifest):
    payload = dict(manifest)
    payload.pop("signature", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def signed_update_manifest_fields(manifest):
    payload = dict(manifest)
    payload.pop("update_available", None)
    payload.pop("current_version_supported", None)
    payload.pop("api_version", None)
    return payload


def validate_windows_update_manifest(response):
    if not isinstance(response, dict):
        raise ValueError("Update API returned an unexpected response.")
    manifest = response.get("update")
    if not isinstance(manifest, dict):
        raise ValueError("Update API did not return a signed manifest.")
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
        raise ValueError("Update manifest fields are invalid.")
    if manifest.get("schema_version") != 1:
        raise ValueError("Update manifest schema is not supported.")
    if manifest.get("product") != "USB File Locker" or manifest.get("platform") != "windows-source":
        raise ValueError("Update manifest is for a different product or platform.")
    update_version_tuple(manifest.get("version"))
    update_version_tuple(manifest.get("minimum_supported_version"))
    if parse_utc_text(manifest.get("published_at_utc")) is None:
        raise ValueError("Update manifest timestamp is invalid.")
    filename = str(manifest.get("package_filename", ""))
    if not filename.endswith(".zip") or Path(filename).name != filename or len(filename) > 120:
        raise ValueError("Update package filename is invalid.")
    if manifest.get("download_path") != "/api/v1/updates/windows/download":
        raise ValueError("Update package path is invalid.")
    expected_hash = str(manifest.get("sha256", "")).lower()
    if len(expected_hash) != 64 or any(character not in "0123456789abcdef" for character in expected_hash):
        raise ValueError("Update package SHA-256 is invalid.")
    try:
        size_bytes = int(manifest.get("size_bytes", 0))
    except (TypeError, ValueError) as exc:
        raise ValueError("Update package size is invalid.") from exc
    if not 0 < size_bytes <= MAX_UPDATE_PACKAGE_BYTES:
        raise ValueError("Update package size is outside the allowed limit.")
    notes = manifest.get("notes")
    if not isinstance(notes, list) or len(notes) > 12 or any(not isinstance(note, str) or len(note) > 240 for note in notes):
        raise ValueError("Update release notes are invalid.")
    if manifest.get("signing_key_id") != UPDATE_SIGNING_KEY_ID:
        raise ValueError("Update was signed by an unknown release key.")
    if manifest.get("preserves_local_app_data") is not True:
        raise ValueError("Update does not promise to preserve app data.")
    public_key_bytes = decode_update_base64url(UPDATE_SIGNING_PUBLIC_KEY_B64)
    signature = decode_update_base64url(manifest.get("signature"))
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature,
            canonical_update_manifest_bytes(manifest),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("Update manifest signature did not verify.") from exc
    validated = dict(manifest)
    validated["size_bytes"] = size_bytes
    validated["sha256"] = expected_hash
    validated["update_available"] = compare_update_versions(validated["version"], DESKTOP_APP_VERSION)
    validated["current_version_supported"] = not compare_update_versions(
        validated["minimum_supported_version"],
        DESKTOP_APP_VERSION,
    )
    validated["api_version"] = str(response.get("api_version", "") or "")
    return validated


def check_windows_update_online(server_url):
    response = license_api_get_json(server_url, "/api/v1/updates/windows")
    return validate_windows_update_manifest(response)


def format_update_size(size_bytes):
    size = max(0, int(size_bytes or 0))
    if size < 1024:
        return f"{size} bytes"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def update_verification_receipt(manifest, checked_at_utc=None):
    if not isinstance(manifest, dict):
        raise ValueError("Check for a signed update before exporting a verification receipt.")
    api_version = str(manifest.get("api_version", "") or "")
    validated = validate_windows_update_manifest(
        {
            "api_version": api_version,
            "update": signed_update_manifest_fields(manifest),
        }
    )
    return {
        "schema_version": 1,
        "receipt_type": "vaultlink-update-verification",
        "verified_at_utc": str(checked_at_utc or utc_now_text()),
        "installed_version": DESKTOP_APP_VERSION,
        "release_version": validated["version"],
        "minimum_supported_version": validated["minimum_supported_version"],
        "api_version": api_version,
        "published_at_utc": validated["published_at_utc"],
        "package_filename": validated["package_filename"],
        "package_sha256": validated["sha256"],
        "package_size_bytes": validated["size_bytes"],
        "signing_key_id": validated["signing_key_id"],
        "signature_verified": True,
        "app_data_preserved": True,
        "update_available": validated["update_available"],
        "current_version_supported": validated["current_version_supported"],
        "privacy_note": (
            "This receipt contains release metadata only. It excludes license keys, USB secrets, PINs, "
            "passwords, customer data, full local paths, and file contents."
        ),
    }


def update_readiness_report(manifest, runtime_dir=None, app_dir=None):
    if not isinstance(manifest, dict):
        raise ValueError("Check for a signed update before running readiness checks.")
    validated = validate_windows_update_manifest(
        {
            "api_version": str(manifest.get("api_version", "") or ""),
            "update": signed_update_manifest_fields(manifest),
        }
    )
    runtime = Path(runtime_dir or RUNTIME_DIR)
    data_root = Path(app_dir or APP_DIR)
    runtime_exists = runtime.is_dir()
    runtime_writable = runtime_exists and os.access(runtime, os.W_OK)
    git_folder = (runtime / ".git").exists() if runtime_exists else False
    try:
        free_bytes = shutil.disk_usage(data_root).free
    except OSError:
        free_bytes = 0
    required_bytes = max(validated["size_bytes"] * 3, 10 * 1024 * 1024)
    disk_ready = free_bytes >= required_bytes
    supported = bool(validated["current_version_supported"])
    checks = [
        {"name": "Signed release manifest", "passed": True, "detail": "Ed25519 signature verified."},
        {"name": "Current version support", "passed": supported, "detail": "Supported." if supported else "Update required."},
        {"name": "Application folder", "passed": runtime_exists, "detail": "Available." if runtime_exists else "Missing."},
        {"name": "Application folder write access", "passed": runtime_writable, "detail": "Available." if runtime_writable else "Blocked."},
        {
            "name": "Temporary disk space",
            "passed": disk_ready,
            "detail": f"{format_update_size(free_bytes)} free; {format_update_size(required_bytes)} required.",
        },
        {
            "name": "Installation mode",
            "passed": not git_folder,
            "detail": "Automatic signed install." if not git_folder else "Git folder detected; use git pull.",
        },
    ]
    ready = all(item["passed"] for item in checks)
    return {
        "schema_version": 1,
        "checked_at_utc": utc_now_text(),
        "release_version": validated["version"],
        "ready_for_automatic_install": ready,
        "installation_mode": "automatic" if ready else ("git-manual" if git_folder else "blocked"),
        "checks": checks,
        "privacy_note": "Readiness results contain no local paths, license data, USB secrets, PINs, passwords, or file contents.",
    }


UPDATE_ACTIVITY_ACTIONS = {
    "application_update": "Verified update staged",
    "application_auto_update": "Automatic update",
    "application_update_completed": "Update installed",
    "update_hash_copy": "Verified hash copied",
    "update_receipt_export": "Verification receipt exported",
    "update_package_copy": "Verified package downloaded",
    "auto_update_setting": "Automatic update setting changed",
}


def update_activity_summary(records=None, status_path=None, limit=25):
    source_records = list(records if records is not None else load_all_audit_records(APP_DIR))
    events = []
    for record in source_records:
        action = str(record.get("action", ""))
        if action not in UPDATE_ACTIVITY_ACTIONS:
            continue
        events.append(
            {
                "sequence": int(record.get("sequence", 0) or 0),
                "time_utc": str(record.get("time_utc", ""))[:24],
                "event_id": str(record.get("event_id", ""))[:32],
                "action": action,
                "title": UPDATE_ACTIVITY_ACTIONS[action],
                "result": "success" if record.get("result") == "success" else "failure",
            }
        )
    events = events[-max(1, min(int(limit or 25), 100)):]
    latest_install = {}
    status_file = Path(status_path or (APP_DIR / "update-status.json"))
    if status_file.is_file():
        try:
            payload = json.loads(status_file.read_text(encoding="utf-8"))
            version = str(payload.get("version", ""))
            update_version_tuple(version)
            latest_install = {
                "ok": bool(payload.get("ok")),
                "version": version,
                "time_utc": str(payload.get("time_utc", ""))[:24],
                "backup_created": bool(str(payload.get("backup_dir", "")).strip()),
            }
        except Exception:
            latest_install = {"ok": False, "version": "unknown", "time_utc": "", "backup_created": False}
    return {
        "schema_version": 1,
        "latest_install": latest_install,
        "events": events,
        "privacy_note": "Activity includes anonymous event IDs and release actions only; paths and file contents are excluded.",
    }


def download_windows_update_package(server_url, manifest, destination):
    validated = validate_windows_update_manifest({"update": signed_update_manifest_fields(manifest)})
    url = validated_license_server_url(server_url) + validated["download_path"]
    request = urllib.request.Request(url, headers={"Accept": "application/zip"}, method="GET")
    try:
        with API_URL_OPENER.open(request, timeout=60) as response:
            raw = response.read(MAX_UPDATE_PACKAGE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        try:
            message = exc.read(MAX_API_RESPONSE_BYTES + 1).decode("utf-8", errors="replace")
            if 300 <= exc.code < 400:
                raise ValueError("Update redirects are blocked.") from exc
            try:
                payload = json.loads(message)
                message = payload.get("message") or payload.get("error") or message
            except Exception:
                pass
            raise ValueError(message or f"Update API returned HTTP {exc.code}.") from exc
        finally:
            exc.close()
    except urllib.error.URLError as exc:
        raise ValueError(f"Could not download the update package.\n\n{exc.reason}") from exc
    if len(raw) != validated["size_bytes"]:
        raise ValueError("Downloaded update size did not match the signed manifest.")
    actual_hash = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual_hash, validated["sha256"]):
        raise ValueError("Downloaded update SHA-256 did not match the signed manifest.")
    target = Path(destination)
    write_bytes_atomic(target, raw)
    return target


def stage_windows_update(server_url, manifest):
    signed_manifest = signed_update_manifest_fields(manifest)
    validated = validate_windows_update_manifest({"update": signed_manifest})
    stage_dir = secure_mkdtemp(prefix="vaultlink_update_")
    package_path = stage_dir / validated["package_filename"]
    manifest_path = stage_dir / "windows-manifest.json"
    try:
        download_windows_update_package(server_url, validated, package_path)
        write_text_atomic(manifest_path, json.dumps(signed_manifest, indent=2))
        return stage_dir, manifest_path, package_path
    except Exception:
        shutil.rmtree(stage_dir, ignore_errors=True)
        raise


def launch_staged_windows_update(stage_dir, manifest_path, package_path, parent_pid=None):
    stage_root = Path(stage_dir).resolve()
    temp_root = TEMP_DIR.resolve()
    try:
        stage_root.relative_to(temp_root)
    except ValueError as exc:
        raise ValueError("Update staging folder is outside the protected app-data temp folder.") from exc
    manifest_file = Path(manifest_path).resolve()
    package_file = Path(package_path).resolve()
    for candidate in (manifest_file, package_file):
        try:
            candidate.relative_to(stage_root)
        except ValueError as exc:
            raise ValueError("Update staging file is outside the protected staging folder.") from exc
        if not candidate.is_file():
            raise ValueError("A required staged update file is missing.")
    target = RUNTIME_DIR.resolve()
    if (target / ".git").exists():
        raise ValueError(
            "Automatic install is disabled inside a Git working folder. Use git pull there, or run the clean release folder."
        )
    updater = target / "vaultlink_updater.py"
    if not updater.is_file():
        raise ValueError("The signed updater helper is missing from the app folder.")
    process = subprocess.Popen(
        [
            sys.executable,
            str(updater),
            "--manifest",
            str(manifest_file),
            "--package",
            str(package_file),
            "--target",
            str(target),
            "--parent-pid",
            str(int(parent_pid or os.getpid())),
        ],
        cwd=str(target),
        creationflags=0x08000000,
    )
    return process.pid


def validated_admin_api_token(admin_token):
    token = str(admin_token or "").strip()
    if not token:
        raise ValueError("Enter the Railway LICENSE_ADMIN_TOKEN.")
    if len(token) > 4096 or "\r" in token or "\n" in token:
        raise ValueError("Admin token format is invalid.")
    return token


def issue_license_online(
    server_url,
    admin_token,
    plan_id,
    customer_label="",
    customer_email="",
    license_note="",
    max_devices=1,
    expires_at_utc="",
):
    token = validated_admin_api_token(admin_token)
    selected_plan = str(plan_id or "").strip().lower()
    if selected_plan not in LICENSE_PLAN_IDS:
        raise ValueError("Choose one of the seven available license ranks.")
    try:
        device_limit = int(max_devices)
    except (TypeError, ValueError) as exc:
        raise ValueError("Max devices must be a whole number.") from exc
    if not 1 <= device_limit <= 1000:
        raise ValueError("Max devices must be between 1 and 1000.")
    label = str(customer_label or "").strip()
    email = str(customer_email or "").strip()
    if len(label) > 160:
        raise ValueError("Customer label must be 160 characters or fewer.")
    if len(email) > 254:
        raise ValueError("Customer email must be 254 characters or fewer.")
    note = " ".join(str(license_note or "").split())
    if len(note) > 2000:
        raise ValueError("License note must be 2000 characters or fewer.")
    payload = {
        "plan_id": selected_plan,
        "customer_label": label,
        "customer_email": email,
        "license_note": note,
        "max_devices": device_limit,
    }
    expiry = str(expires_at_utc or "").strip()
    if expiry:
        payload["expires_at_utc"] = expiry
    return license_api_post_json(
        server_url,
        "/api/v1/licenses/issue",
        payload,
        extra_headers={"X-License-Admin-Token": token},
    )


def list_admin_licenses_online(server_url, admin_token):
    token = validated_admin_api_token(admin_token)
    return license_api_get_json(
        server_url,
        "/api/v1/admin/licenses",
        extra_headers={"X-License-Admin-Token": token},
    )


def get_admin_dashboard_online(server_url, admin_token):
    token = validated_admin_api_token(admin_token)
    return license_api_get_json(
        server_url,
        "/api/v1/admin/dashboard",
        extra_headers={"X-License-Admin-Token": token},
    )


def admin_license_action_online(server_url, admin_token, action, license_key, note=""):
    token = validated_admin_api_token(admin_token)
    selected_action = str(action or "").strip().lower()
    if selected_action not in {"revoke", "restore", "note", "reset-devices"}:
        raise ValueError("Choose a valid license management action.")
    payload = {"license_key": require_valid_api_license_key(license_key)}
    if selected_action == "revoke":
        payload["revocation_note"] = " ".join(str(note or "").split())[:2000]
    elif selected_action == "note":
        payload["license_note"] = " ".join(str(note or "").split())[:2000]
    return license_api_post_json(
        server_url,
        f"/api/v1/licenses/{selected_action}",
        payload,
        extra_headers={"X-License-Admin-Token": token},
    )


def revoke_license_online(server_url, admin_token, license_key, note=""):
    return admin_license_action_online(server_url, admin_token, "revoke", license_key, note)


def restore_license_online(server_url, admin_token, license_key):
    return admin_license_action_online(server_url, admin_token, "restore", license_key)


def update_license_note_online(server_url, admin_token, license_key, note):
    return admin_license_action_online(server_url, admin_token, "note", license_key, note)


def reset_license_devices_online(server_url, admin_token, license_key):
    return admin_license_action_online(server_url, admin_token, "reset-devices", license_key)


def list_admin_audit_exports_online(server_url, admin_token):
    token = validated_admin_api_token(admin_token)
    return license_api_get_json(
        server_url,
        "/api/v1/admin/audit-exports",
        extra_headers={"X-License-Admin-Token": token},
    )


def valid_audit_export_id(export_id):
    value = str(export_id or "").strip()
    return (
        value.startswith("AUD-")
        and 8 <= len(value) <= 64
        and all(character.isalnum() or character in {"-", "_"} for character in value)
    )


def download_admin_audit_export_online(server_url, admin_token, export_id, destination):
    token = validated_admin_api_token(admin_token)
    clean_export_id = str(export_id or "").strip()
    if not valid_audit_export_id(clean_export_id):
        raise ValueError("Choose a valid API audit export.")
    path = f"/api/v1/admin/audit-exports/{clean_export_id}/download"
    url = validated_license_server_url(server_url) + path
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "X-License-Admin-Token": token,
        },
        method="GET",
    )
    try:
        with API_URL_OPENER.open(request, timeout=30) as response:
            raw = response.read(MAX_AUDIT_API_DOWNLOAD_BYTES + 1)
    except urllib.error.HTTPError as exc:
        try:
            error_body = exc.read(MAX_API_RESPONSE_BYTES + 1).decode("utf-8", errors="replace")
            if 300 <= exc.code < 400:
                raise ValueError("API redirects are blocked to protect admin credentials.") from exc
            try:
                error_payload = json.loads(error_body)
                message = error_payload.get("message") or error_payload.get("error") or error_body
            except Exception:
                message = error_body or f"Audit API returned HTTP {exc.code}."
            raise ValueError(message) from exc
        finally:
            exc.close()
    except urllib.error.URLError as exc:
        raise ValueError(f"Could not download the audit report.\n\n{exc.reason}") from exc
    if len(raw) > MAX_AUDIT_API_DOWNLOAD_BYTES:
        raise ValueError("The downloaded audit report is larger than the app allows.")
    try:
        downloaded = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("The API download was not a valid JSON audit report.") from exc
    if not isinstance(downloaded, dict) or downloaded.get("export_id") != clean_export_id:
        raise ValueError("The downloaded audit report did not match the selected export.")
    target = Path(destination)
    if target.exists() and target.is_dir():
        target = target / f"vaultlink-audit-{clean_export_id}.json"
    if target.suffix.lower() != ".json":
        target = target.with_name(target.name + ".json")
    write_bytes_atomic(target, raw)
    return target


def apply_license_response(state, payload):
    current = normalize_license_state(state)
    plan = payload.get("plan") or {}
    license_info = payload.get("license") or {}
    activation = payload.get("activation") or {}
    device_usage = payload.get("device_usage") or {}
    sync = payload.get("sync") or {}
    release = payload.get("release") or {}
    announcement_payload = payload.get("announcements") or {}
    message = str(payload.get("message", "") or "").strip()
    current["status"] = str(payload.get("status", "active" if payload.get("active") else current.get("status", "saved"))).strip().lower()
    current["plan_id"] = str(plan.get("id", current.get("plan_id", "")) or "").strip().lower()
    current["plan_name"] = str(plan.get("name", current.get("plan_name", "")) or "").strip()
    entitlements = plan.get("entitlements", [])
    if isinstance(entitlements, str):
        entitlements = [entitlements]
    current["features"] = sorted({str(item).strip() for item in entitlements if str(item).strip()})
    current["receipt"] = str(payload.get("receipt", current.get("receipt", "")) or "").strip()
    current["license_id"] = str(license_info.get("license_id", current.get("license_id", "")) or "").strip()
    current["customer_label"] = str(license_info.get("customer_label", current.get("customer_label", "")) or "").strip()
    current["customer_email"] = str(license_info.get("customer_email", current.get("customer_email", "")) or "").strip()
    current["license_expires_at"] = str(license_info.get("expires_at_utc", current.get("license_expires_at", "")) or "").strip()
    current["receipt_expires_at"] = str(activation.get("valid_until_utc", current.get("receipt_expires_at", "")) or "").strip()
    current["machine_id"] = current_machine_fingerprint()
    current["machine_name"] = current_machine_name()
    current["last_checked_utc"] = str(payload.get("server_time_utc", utc_now_text()) or utc_now_text()).strip()
    current["api_version"] = str(payload.get("api_version", sync.get("api_version", current.get("api_version", ""))) or "").strip()
    try:
        current["sync_interval_seconds"] = int(
            sync.get("recommended_interval_seconds", current.get("sync_interval_seconds", LICENSE_BACKGROUND_REFRESH_SECONDS))
            or LICENSE_BACKGROUND_REFRESH_SECONDS
        )
    except (TypeError, ValueError):
        current["sync_interval_seconds"] = LICENSE_BACKGROUND_REFRESH_SECONDS
    current["last_decision_id"] = str(sync.get("decision_id", current.get("last_decision_id", "")) or "").strip()
    current["last_sync_result"] = current["status"]
    current["latest_desktop_version"] = str(release.get("latest_version", current.get("latest_desktop_version", "")) or "").strip()
    current["minimum_supported_version"] = str(release.get("minimum_supported_version", current.get("minimum_supported_version", "")) or "").strip()
    current["update_available"] = bool(release.get("update_available", current.get("update_available", False)))
    current["service_status"] = normalize_service_status(payload.get("service_status", current.get("service_status")))
    current["announcements"] = normalize_owner_announcements(
        announcement_payload.get("items", current.get("announcements", []))
    )
    try:
        current["device_active"] = max(0, int(device_usage.get("active", current.get("device_active", 0)) or 0))
        current["device_maximum"] = max(0, int(device_usage.get("maximum", current.get("device_maximum", 0)) or 0))
    except (TypeError, ValueError):
        current["device_active"] = 0
        current["device_maximum"] = 0
    current["last_error"] = "" if payload.get("active") else message
    return normalize_license_state(current)


def build_license_failure_state(state, message):
    current = normalize_license_state(state)
    current["last_error"] = str(message).strip()
    if current.get("status") == "active" and license_is_active(current):
        return current
    current["status"] = "error"
    return current


def activate_license_online(state):
    current = normalize_license_state(state)
    current["license_key"] = require_valid_api_license_key(current.get("license_key"))
    payload = license_api_post_json(
        current.get("server_url"),
        "/api/v1/licenses/activate",
        {
            "license_key": current.get("license_key"),
            "machine_id": current_machine_fingerprint(),
            "machine_name": current_machine_name(),
            "app_version": DESKTOP_APP_VERSION,
        },
    )
    return apply_license_response(current, payload)


def verify_license_online(state, timeout=15):
    current = normalize_license_state(state)
    current["license_key"] = require_valid_api_license_key(current.get("license_key"))
    request_payload = {
        "license_key": current.get("license_key"),
        "receipt": current.get("receipt", ""),
        "machine_id": current_machine_fingerprint(),
        "app_version": DESKTOP_APP_VERSION,
    }
    try:
        payload = license_api_post_json(
            current.get("server_url"),
            "/api/v1/licenses/sync",
            request_payload,
            timeout=timeout,
        )
    except ValueError as exc:
        if "route not found" not in str(exc).lower():
            raise
        payload = license_api_post_json(
            current.get("server_url"),
            "/api/v1/licenses/verify",
            request_payload,
            timeout=timeout,
        )
    return apply_license_response(current, payload)


def deactivate_license_online(state):
    current = normalize_license_state(state)
    current["license_key"] = require_valid_api_license_key(current.get("license_key"))
    if not current.get("receipt"):
        raise ValueError("This PC does not have an activation receipt to remove.")
    payload = license_api_post_json(
        current.get("server_url"),
        "/api/v1/licenses/deactivate",
        {
            "license_key": current.get("license_key"),
            "receipt": current.get("receipt"),
            "machine_id": current_machine_fingerprint(),
            "app_version": DESKTOP_APP_VERSION,
        },
    )
    if not payload.get("deactivated") or payload.get("status") != "deactivated":
        raise ValueError(payload.get("message") or "The API did not deactivate this PC.")
    return payload


def support_license_payload(state):
    current = normalize_license_state(state)
    current["license_key"] = require_valid_api_license_key(current.get("license_key"))
    if not license_is_active(current):
        raise ValueError("Activate this PC in License Center before contacting the owner.")
    return current, {
        "license_key": current.get("license_key"),
        "receipt": current.get("receipt", ""),
        "machine_id": current_machine_fingerprint(),
        "app_version": DESKTOP_APP_VERSION,
    }


def create_support_ticket_online(state, category, subject, message, steps=""):
    current, payload = support_license_payload(state)
    payload.update(
        {
            "category": str(category or "bug").strip().lower(),
            "subject": str(subject or "").strip(),
            "message": str(message or "").strip(),
            "steps": str(steps or "").strip(),
        }
    )
    return license_api_post_json(
        current.get("server_url"),
        "/api/v1/support-tickets",
        payload,
    )


def list_my_support_tickets_online(state):
    current, payload = support_license_payload(state)
    return license_api_post_json(
        current.get("server_url"),
        "/api/v1/support-tickets/mine",
        payload,
    )


def list_owner_announcements_online(state):
    current, payload = support_license_payload(state)
    return license_api_post_json(
        current.get("server_url"),
        "/api/v1/announcements/mine",
        payload,
    )


def load_customer_workspace_online(state, app_version=None):
    current = normalize_license_state(state)
    current["license_key"] = require_valid_api_license_key(current.get("license_key"))
    payload = license_api_post_json(
        current.get("server_url"),
        "/api/v1/licenses/customer-workspace",
        {
            "license_key": current.get("license_key"),
            "app_version": str(app_version or DESKTOP_APP_VERSION).strip()[:80],
        },
    )
    if payload.get("workspace_schema_version") != 2 or not isinstance(payload.get("summary"), dict):
        raise ValueError("The API returned an unsupported customer workspace response.")
    return payload


def shop_url_for_state(state=None):
    current = normalize_license_state(state or {})
    return validated_license_server_url(current.get("server_url") or DEFAULT_LICENSE_SERVER) + "/shop"


def upload_audit_report_online(state, report=None):
    current = normalize_license_state(state)
    current["license_key"] = require_valid_api_license_key(current.get("license_key"))
    if not license_is_active(current):
        raise ValueError("Activate this PC in License Center before using API audit export.")
    if not license_feature_allowed("audit-log-viewer", state=current):
        raise ValueError("This license plan does not include API audit export.")
    return license_api_post_json(
        current.get("server_url"),
        "/api/v1/audit-exports",
        {
            "license_key": current.get("license_key"),
            "receipt": current.get("receipt"),
            "machine_id": current_machine_fingerprint(),
            "app_version": DESKTOP_APP_VERSION,
            "report": report if isinstance(report, dict) else build_audit_report(),
        },
    )


def download_audit_export_online(state, upload_response, destination):
    current = normalize_license_state(state)
    if not isinstance(upload_response, dict):
        raise ValueError("The API did not return audit export details.")
    download_path = str(upload_response.get("download_path", "")).strip()
    download_token = str(upload_response.get("download_token", "")).strip()
    if (
        not download_path.startswith("/api/v1/audit-exports/")
        or not download_path.endswith("/download")
        or not download_token.startswith("vla1.")
    ):
        raise ValueError("The API returned invalid audit download details.")
    url = validated_license_server_url(current.get("server_url")) + download_path
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {download_token}",
        },
        method="GET",
    )
    try:
        with API_URL_OPENER.open(request, timeout=30) as response:
            raw = response.read(MAX_AUDIT_API_DOWNLOAD_BYTES + 1)
    except urllib.error.HTTPError as exc:
        try:
            error_body = exc.read(MAX_API_RESPONSE_BYTES + 1).decode("utf-8", errors="replace")
            if 300 <= exc.code < 400:
                raise ValueError("API redirects are blocked to protect the audit download token.") from exc
            try:
                error_payload = json.loads(error_body)
                message = error_payload.get("message") or error_payload.get("error") or error_body
            except Exception:
                message = error_body or f"Audit API returned HTTP {exc.code}."
            raise ValueError(message) from exc
        finally:
            exc.close()
    except urllib.error.URLError as exc:
        raise ValueError(f"Could not download the audit report.\n\n{exc.reason}") from exc
    if len(raw) > MAX_AUDIT_API_DOWNLOAD_BYTES:
        raise ValueError("The downloaded audit report is larger than the app allows.")
    try:
        downloaded = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("The API download was not a valid JSON audit report.") from exc
    if not isinstance(downloaded, dict):
        raise ValueError("The API download had an unexpected format.")
    if downloaded.get("export_id") != upload_response.get("export_id"):
        raise ValueError("The downloaded audit report did not match the uploaded export.")
    target = Path(destination)
    if target.exists() and target.is_dir():
        filename = str(upload_response.get("filename", "")).strip() or "vaultlink-audit-export.json"
        target = target / safe_filename_piece(filename, "vaultlink-audit-export.json")
    if target.suffix.lower() != ".json":
        target = target.with_name(target.name + ".json")
    write_bytes_atomic(target, raw)
    return target


def owner_key_allowed(key, policy):
    if not policy:
        return True, ""
    if key.get("key_id") != policy.get("key_id"):
        return False, "This app is locked to a different owner key."
    try:
        origin = key.get("origin") or volume_identity(key["path"])
    except Exception as exc:
        return False, f"Could not read the USB drive info.\n\n{exc}"
    if origin["serial"] != policy.get("volume_serial"):
        return False, "This app is locked to the original owner USB drive."
    return True, ""


def safe_filename_piece(text, fallback="locked_note"):
    cleaned = "".join(character if character.isalnum() or character in {" ", "-", "_"} else "_" for character in (text or "").strip())
    cleaned = " ".join(cleaned.split()).strip(" ._")
    return cleaned[:80] or fallback


def pythonw_path():
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    return pythonw if pythonw.exists() else Path(sys.executable)


def launch_companion_script(script_name, *args):
    script_name = str(script_name)
    feature_id = SCRIPT_LICENSE_FEATURES.get(script_name)
    if feature_id and not license_feature_allowed(feature_id):
        raise PermissionError(license_required_message(feature_id))
    if getattr(sys, "frozen", False):
        exe_path = RUNTIME_DIR / f"{Path(script_name).stem}.exe"
        if not exe_path.exists():
            raise FileNotFoundError(f"Companion app is not packaged here yet: {exe_path.name}")
        command = [str(exe_path), *[str(arg) for arg in args]]
    else:
        script_path = SOURCE_DIR / script_name
        command = [str(pythonw_path()), str(script_path), *[str(arg) for arg in args]]
    subprocess.Popen(command, cwd=str(SOURCE_DIR), close_fds=True)


def launch_main_app_process():
    if getattr(sys, "frozen", False):
        command = [str(Path(sys.executable).resolve())]
    else:
        command = [str(pythonw_path()), str(Path(__file__).resolve())]
    subprocess.Popen(command, cwd=str(SOURCE_DIR), close_fds=True)


def launch_unlocker_process(locked_path):
    locked_path = str(locked_path)
    if getattr(sys, "frozen", False):
        command = [str(Path(sys.executable).resolve()), "--unlock", locked_path]
    else:
        command = [str(pythonw_path()), str(Path(__file__).resolve()), "--unlock", locked_path]
    subprocess.Popen(command, cwd=str(SOURCE_DIR), close_fds=True)


def register_locked_file_association():
    if LAB_MODE:
        raise PermissionError("File association changes are disabled in OWNER LAB mode.")
    import winreg

    prog_id = "USBFileLocker.LockedFile"
    if getattr(sys, "frozen", False):
        launcher = Path(sys.executable).resolve()
        command = f'"{launcher}" --unlock "%1"'
        icon = f'"{launcher}",0'
    else:
        script_path = Path(__file__).resolve()
        command = f'"{pythonw_path()}" "{script_path}" --unlock "%1"'
        icon = f'"{pythonw_path()}",0'

    for extension in (".locked", ".lookeed"):
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, fr"Software\Classes\{extension}") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, prog_id)

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, fr"Software\Classes\{prog_id}") as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "USB File Locker Locked File")
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, fr"Software\Classes\{prog_id}\DefaultIcon") as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, icon)
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, fr"Software\Classes\{prog_id}\shell\open\command") as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, command)

    try:
        ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
    except Exception:
        pass

    return command


def create_key_file(path):
    secret = secrets.token_bytes(64)
    key_id = hashlib.sha256(secret).hexdigest()[:16]
    data = {
        "type": "USB_FILE_LOCKER_MASTER_KEY",
        "version": 1,
        "key_id": key_id,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "secret": base64.b64encode(secret).decode("ascii"),
    }
    write_text_atomic(path, json.dumps(data, indent=2))
    return data


def load_key_file(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("type") != "USB_FILE_LOCKER_MASTER_KEY":
        raise ValueError("That is not a USB File Locker master key.")
    secret = base64.b64decode(data["secret"].encode("ascii"))
    if len(secret) < 32:
        raise ValueError("The key file is not strong enough.")
    try:
        origin = volume_identity(path)
    except Exception:
        origin = None
    return {
        "path": str(path),
        "key_id": data.get("key_id") or hashlib.sha256(secret).hexdigest()[:16],
        "secret": secret,
        "origin": origin,
    }


def derive_entropy(key_secret, pin):
    pin_bytes = (pin or "").encode("utf-8")
    return hashlib.sha256(b"USBFileLocker-v1|" + key_secret + b"|" + pin_bytes).digest()


def security_profile_settings(name=None):
    return SECURITY_PROFILES[normalize_security_profile_name(name or DEFAULT_SECURITY_PROFILE)]


def security_profile_for_settings(settings):
    if not isinstance(settings, dict):
        return DEFAULT_SECURITY_PROFILE
    return normalize_security_profile_name(settings.get("security_profile", DEFAULT_SECURITY_PROFILE))


def security_profile_summary(name):
    profile_name = normalize_security_profile_name(name)
    profile = security_profile_settings(profile_name)
    return (
        f"{profile['label']} - AES-256-GCM with scrypt N={profile['kdf_n']:,}, "
        f"r={profile['kdf_r']}, p={profile['kdf_p']} and about {profile['memory_mb']} MB KDF memory"
    )


def portable_crypto_from_header(header):
    if header.get("cipher", "AES-256-GCM") != "AES-256-GCM":
        raise ValueError("This lock uses an unsupported cipher.")
    if header.get("kdf", "scrypt") != "scrypt":
        raise ValueError("This lock uses an unsupported key-derivation method.")
    salt = base64.b64decode(header["salt"].encode("ascii"), validate=True)
    nonce = base64.b64decode(header["nonce"].encode("ascii"), validate=True)
    if len(salt) < 16 or len(salt) > 64:
        raise ValueError("This lock has an invalid salt size.")
    if len(nonce) != 12:
        raise ValueError("This lock has an invalid AES-GCM nonce size.")
    n = int(header.get("kdf_n", SECURITY_PROFILES["balanced"]["kdf_n"]))
    r = int(header.get("kdf_r", SECURITY_PROFILES["balanced"]["kdf_r"]))
    p = int(header.get("kdf_p", SECURITY_PROFILES["balanced"]["kdf_p"]))
    if n < MIN_KDF_N or n > MAX_KDF_N or (n & (n - 1)) != 0:
        raise ValueError("This lock has an invalid scrypt N setting.")
    if r < MIN_KDF_R or r > MAX_KDF_R:
        raise ValueError("This lock has an invalid scrypt r setting.")
    if p < MIN_KDF_P or p > MAX_KDF_P:
        raise ValueError("This lock has an invalid scrypt p setting.")
    return salt, nonce, n, r, p


def derive_portable_key(key_secret, pin, salt, n=2**15, r=8, p=1):
    material = key_secret + b"\0" + (pin or "").encode("utf-8")
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(material)


def portable_header_bytes(header):
    return json.dumps(header, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def pack_blob(magic, header, encrypted):
    header_bytes = json.dumps(header).encode("utf-8")
    return magic + struct.pack(">I", len(header_bytes)) + header_bytes + encrypted


def unpack_legacy_locked(data):
    return unpack_blob(data, LEGACY_MAGIC, "This is not a legacy USB File Locker .locked file.")


def unpack_blob(data, magic, error):
    if not data.startswith(magic):
        raise ValueError(error)
    start = len(magic)
    if len(data) < start + 4:
        raise ValueError("The locked file header is incomplete.")
    header_len = struct.unpack(">I", data[start : start + 4])[0]
    if header_len <= 0 or header_len > MAX_LOCKED_HEADER_BYTES:
        raise ValueError("The locked file header size is invalid.")
    header_start = start + 4
    header_end = header_start + header_len
    if header_end > len(data):
        raise ValueError("The locked file header is damaged.")
    header = json.loads(data[header_start:header_end].decode("utf-8"))
    encrypted = data[header_end:]
    return header, encrypted


def unique_path(path):
    path = Path(path)
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    for index in range(1, 10000):
        candidate = parent / f"{stem} ({index}){suffix}"
        if not candidate.exists():
            return candidate
    raise RuntimeError("Could not find a free output filename.")


def is_locked_path(path):
    name = Path(path).name.lower()
    return name.endswith(".locked") or name.endswith(".lookeed")


def resolve_unlock_target(path):
    path = Path(path)
    if is_locked_path(path):
        return path
    for suffix in (".locked", ".lookeed", ".folder.locked"):
        candidate = Path(str(path) + suffix)
        if candidate.exists():
            return candidate
    return None


def common_user_dirs():
    home = Path.home()
    candidates = [
        home / "Desktop",
        home / "OneDrive" / "Desktop",
        home / "Documents",
        home / "OneDrive" / "Documents",
        home / "Downloads",
    ]
    seen = set()
    found = []
    for path in candidates:
        try:
            resolved = path.resolve()
        except Exception:
            continue
        if resolved.exists() and resolved not in seen:
            seen.add(resolved)
            found.append(resolved)
    return found


def preferred_desktop_dir():
    home = Path.home()
    for candidate in (home / "OneDrive" / "Desktop", home / "Desktop"):
        if candidate.exists():
            return candidate
    return home


def ensure_perm_unlock_folder():
    return ensure_directory_destination(preferred_desktop_dir() / "PERM UNLOCK", "PERM UNLOCK folder")


def ensure_directory_destination(path, label="destination"):
    destination = Path(path)
    if destination.exists() and not destination.is_dir():
        raise ValueError(f"The {label} must be a folder, not a file.")
    destination.mkdir(parents=True, exist_ok=True)
    return destination


def scan_personal_file_candidates():
    results = []
    for root in common_user_dirs():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [name for name in dirnames if name.lower() not in WALK_SKIP_DIRS]
            for filename in filenames:
                path = Path(dirpath) / filename
                name = filename.lower().replace(" ", "")
                if path.suffix.lower() not in PERSONAL_FILE_EXTS:
                    continue
                if not any(keyword in name for keyword in PERSONAL_FILE_KEYWORDS):
                    continue
                try:
                    if path.stat().st_size > MAX_SCAN_FILE_SIZE:
                        continue
                except Exception:
                    continue
                results.append(str(path))
                if len(results) >= MAX_SCAN_RESULTS:
                    return results
    return results


def find_locked_files_in_roots(roots, max_results=MAX_SCAN_RESULTS, stop_event=None):
    results = []
    seen_roots = set()
    for root in roots:
        if stop_event is not None and stop_event.is_set():
            return results
        try:
            root = Path(root).resolve()
        except Exception:
            root = Path(root)
        if root in seen_roots or not root.exists():
            continue
        seen_roots.add(root)
        for dirpath, dirnames, filenames in os.walk(root):
            if stop_event is not None and stop_event.is_set():
                return results
            dirnames[:] = [name for name in dirnames if name.lower() not in WALK_SKIP_DIRS]
            for filename in filenames:
                if stop_event is not None and stop_event.is_set():
                    return results
                if filename.lower().endswith((".locked", ".lookeed")):
                    results.append(str(Path(dirpath) / filename))
                    if len(results) >= max_results:
                        return results
    return results


def find_locked_files():
    return find_locked_files_in_roots(common_user_dirs())


def path_is_link_or_junction(path):
    path = Path(path)
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction and is_junction())


def build_folder_archive(folder):
    folder = Path(folder)
    handle, temp_name = secure_mkstemp(prefix="usb-locker-folder-", suffix=".zip")
    os.close(handle)
    archive_path = Path(temp_name)
    file_count = 0
    total_size = 0
    try:
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
            for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
                current = Path(dirpath)
                safe_dirs = []
                for dirname in dirnames:
                    child = current / dirname
                    if path_is_link_or_junction(child):
                        raise ValueError(f"Folder links are not supported: {child.name}")
                    safe_dirs.append(dirname)
                dirnames[:] = safe_dirs

                relative_dir = current.relative_to(folder)
                if relative_dir.parts:
                    info = zipfile.ZipInfo(relative_dir.as_posix().rstrip("/") + "/")
                    info.external_attr = (stat.S_IFDIR | 0o700) << 16
                    archive.writestr(info, b"")

                for filename in filenames:
                    source = current / filename
                    if path_is_link_or_junction(source):
                        raise ValueError(f"File links are not supported: {source.name}")
                    relative = source.relative_to(folder).as_posix()
                    archive.write(source, relative)
                    file_count += 1
                    total_size += source.stat().st_size
        return archive_path, file_count, total_size
    except Exception:
        archive_path.unlink(missing_ok=True)
        raise


def portable_lock_header(original_name, original_size, key, kind="file", security_profile=None, **extra):
    profile_name = normalize_security_profile_name(security_profile or DEFAULT_SECURITY_PROFILE)
    profile = security_profile_settings(profile_name)
    salt = secrets.token_bytes(profile["salt_bytes"])
    nonce = secrets.token_bytes(12)
    header = {
        "format_version": PORTABLE_FORMAT_VERSION,
        "cipher": "AES-256-GCM",
        "kdf": "scrypt",
        "kdf_n": profile["kdf_n"],
        "kdf_r": profile["kdf_r"],
        "kdf_p": profile["kdf_p"],
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "security_profile": profile_name,
        "kdf_memory_mb": profile["memory_mb"],
        "kind": kind,
        "original_name": original_name,
        "original_size": original_size,
        "key_id": key["key_id"],
        "locked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "portable": True,
    }
    header.update(extra)
    return header


def write_portable_locked(source_path, out_path, header, key, pin):
    source_path = Path(source_path)
    out_path = Path(out_path)
    header_bytes = portable_header_bytes(header)
    salt, nonce, n, r, p = portable_crypto_from_header(header)
    encryption_key = derive_portable_key(
        key["secret"],
        pin,
        salt,
        n,
        r,
        p,
    )
    encryptor = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header_bytes)
    try:
        with source_path.open("rb") as source, out_path.open("xb") as destination:
            destination.write(PORTABLE_MAGIC)
            destination.write(struct.pack(">I", len(header_bytes)))
            destination.write(header_bytes)
            while True:
                chunk = source.read(PORTABLE_CHUNK_SIZE)
                if not chunk:
                    break
                destination.write(encryptor.update(chunk))
            destination.write(encryptor.finalize())
            destination.write(encryptor.tag)
    except Exception:
        out_path.unlink(missing_ok=True)
        raise
    return out_path


def read_portable_header(path):
    path = Path(path)
    with path.open("rb") as source:
        magic = source.read(len(PORTABLE_MAGIC))
        if magic != PORTABLE_MAGIC:
            raise ValueError("This is not a portable USB File Locker file.")
        length_bytes = source.read(4)
        if len(length_bytes) != 4:
            raise ValueError("The portable locked-file header is incomplete.")
        header_length = struct.unpack(">I", length_bytes)[0]
        if header_length <= 0 or header_length > MAX_LOCKED_HEADER_BYTES:
            raise ValueError("The portable locked-file header size is invalid.")
        header_bytes = source.read(header_length)
        if len(header_bytes) != header_length:
            raise ValueError("The portable locked-file header is damaged.")
        header = json.loads(header_bytes.decode("ascii"))
        encrypted_offset = len(PORTABLE_MAGIC) + 4 + header_length
        encrypted_length = path.stat().st_size - encrypted_offset - PORTABLE_TAG_SIZE
        if encrypted_length < 0:
            raise ValueError("The portable locked file is incomplete.")
        source.seek(-PORTABLE_TAG_SIZE, os.SEEK_END)
        tag = source.read(PORTABLE_TAG_SIZE)
    return header, header_bytes, encrypted_offset, encrypted_length, tag


def locked_file_info(path):
    path = Path(path)
    with path.open("rb") as source:
        magic = source.read(max(len(LEGACY_MAGIC), len(PORTABLE_MAGIC)))
    if magic == PORTABLE_MAGIC:
        header, _header_bytes, _offset, _length, _tag = read_portable_header(path)
        return {
            "format": "portable",
            "portable": True,
            "kind": header.get("kind", "file"),
            "header": header,
        }
    if magic == LEGACY_MAGIC:
        header, _encrypted = unpack_legacy_locked(path.read_bytes())
        return {
            "format": "legacy_windows_dpapi",
            "portable": False,
            "kind": header.get("kind", "file"),
            "header": header,
        }
    raise ValueError("This is not a USB File Locker .locked file.")


def check_locked_key(header, key):
    locked_key_id = header.get("key_id")
    if locked_key_id and locked_key_id != key["key_id"]:
        raise ValueError(
            f"Wrong USB key. This lock needs key ID {locked_key_id}; "
            f"the loaded key is {key['key_id']}."
        )


def decrypt_portable_to_file(path, destination, key, pin):
    path = Path(path)
    destination = Path(destination)
    header, header_bytes, encrypted_offset, encrypted_length, tag = read_portable_header(path)
    check_locked_key(header, key)
    try:
        salt, nonce, n, r, p = portable_crypto_from_header(header)
        encryption_key = derive_portable_key(
            key["secret"],
            pin,
            salt,
            n,
            r,
            p,
        )
        decryptor = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(header_bytes)
        with path.open("rb") as source, destination.open("xb") as output:
            source.seek(encrypted_offset)
            remaining = encrypted_length
            while remaining:
                chunk = source.read(min(PORTABLE_CHUNK_SIZE, remaining))
                if not chunk:
                    raise ValueError("The encrypted data ended unexpectedly.")
                remaining -= len(chunk)
                output.write(decryptor.update(chunk))
            output.write(decryptor.finalize())
        return header
    except InvalidTag as exc:
        destination.unlink(missing_ok=True)
        raise ValueError("The PIN is wrong, the USB key is wrong, or the locked file is damaged.") from exc
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def decrypt_locked_to_file(path, destination, key, pin):
    path = Path(path)
    info = locked_file_info(path)
    header = info["header"]
    check_locked_key(header, key)
    if info["portable"]:
        return decrypt_portable_to_file(path, destination, key, pin)

    try:
        _header, encrypted = unpack_legacy_locked(path.read_bytes())
        plain = dpapi_unprotect(encrypted, derive_entropy(key["secret"], pin))
    except OSError as exc:
        raise ValueError(
            "This is an old Windows-bound lock. It can only be opened by the "
            "Windows account that created it. On the original PC, use UPGRADE "
            "OLD LOCKS, then copy the new portable .locked file here."
        ) from exc
    Path(destination).write_bytes(plain)
    return header


def lock_file(path, key, pin):
    path = Path(path)
    if is_locked_path(path):
        raise ValueError("Already locked.")
    if path.is_file():
        header = portable_lock_header(path.name, path.stat().st_size, key, kind="file")
        out_path = unique_path(path.with_name(path.name + ".locked"))
        return write_portable_locked(path, out_path, header, key, pin)
    if path.is_dir():
        archive_path, file_count, total_size = build_folder_archive(path)
        try:
            header = portable_lock_header(
                path.name,
                total_size,
                key,
                kind="folder",
                archive_format="zip",
                file_count=file_count,
                archive_size=archive_path.stat().st_size,
            )
            out_path = unique_path(path.with_name(path.name + ".folder.locked"))
            return write_portable_locked(archive_path, out_path, header, key, pin)
        finally:
            archive_path.unlink(missing_ok=True)
    raise ValueError("The selected file or folder does not exist.")


def verify_locked_file(locked_path, original_path, key, pin):
    locked_path = Path(locked_path)
    original_path = Path(original_path)
    handle, temp_name = secure_mkstemp(prefix="usb-locker-verify-")
    os.close(handle)
    temp_path = Path(temp_name)
    temp_path.unlink(missing_ok=True)
    try:
        header = decrypt_locked_to_file(locked_path, temp_path, key, pin)
        if original_path.is_file() and header.get("kind", "file") == "file":
            if header.get("original_size") != original_path.stat().st_size:
                return False
            return file_sha256(temp_path) == file_sha256(original_path)
        if original_path.is_dir() and header.get("kind") == "folder":
            return verify_folder_archive(temp_path, original_path)
        return False
    finally:
        temp_path.unlink(missing_ok=True)


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while True:
            chunk = source.read(PORTABLE_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.digest()


def safe_zip_member_path(name):
    if "\\" in name or "\0" in name:
        raise ValueError("The folder archive contains an unsafe path.")
    pure = PurePosixPath(name)
    if pure.is_absolute() or not pure.parts:
        raise ValueError("The folder archive contains an unsafe path.")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("The folder archive contains an unsafe path.")
    if ":" in pure.parts[0]:
        raise ValueError("The folder archive contains an unsafe drive path.")
    return Path(*pure.parts)


def verify_folder_archive(archive_path, folder):
    folder = Path(folder)
    expected_files = {}
    for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
        current = Path(dirpath)
        for dirname in dirnames:
            if path_is_link_or_junction(current / dirname):
                return False
        for filename in filenames:
            source = current / filename
            if path_is_link_or_junction(source):
                return False
            expected_files[source.relative_to(folder).as_posix()] = source

    with zipfile.ZipFile(archive_path, "r") as archive:
        archived_files = {}
        for info in archive.infolist():
            safe_zip_member_path(info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                return False
            if not info.is_dir():
                archived_files[info.filename] = info
        if set(archived_files) != set(expected_files):
            return False
        for name, source in expected_files.items():
            digest = hashlib.sha256()
            with archive.open(archived_files[name], "r") as archived:
                while True:
                    chunk = archived.read(PORTABLE_CHUNK_SIZE)
                    if not chunk:
                        break
                    digest.update(chunk)
            if digest.digest() != file_sha256(source):
                return False
    return True


def extract_folder_archive(archive_path, destination):
    destination = Path(destination)
    destination_root = destination.resolve()
    with zipfile.ZipFile(archive_path, "r") as archive:
        infos = archive.infolist()
        total_size = sum(info.file_size for info in infos if not info.is_dir())
        if len(infos) > 1_000_000 or total_size > 2 * 1024 * 1024 * 1024 * 1024:
            raise ValueError("The folder archive is too large to extract safely.")
        for info in infos:
            relative = safe_zip_member_path(info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ValueError("Folder archives containing links are not supported.")
            target = (destination / relative).resolve()
            try:
                target.relative_to(destination_root)
            except ValueError as exc:
                raise ValueError("The folder archive tried to write outside its output folder.") from exc
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info, "r") as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, PORTABLE_CHUNK_SIZE)


def unlock_file(path, key, pin, output_dir=None):
    path = Path(path)
    if not is_locked_path(path):
        partner = resolve_unlock_target(path)
        if partner:
            path = partner
        else:
            raise ValueError(f"{path.name} is a normal file. Choose a .locked file, or click LOCK SELECTED FILES first.")
    info = locked_file_info(path)
    header = info["header"]
    check_locked_key(header, key)
    original_name = header.get("original_name") or path.stem
    parent = Path(output_dir) if output_dir else path.parent
    parent.mkdir(parents=True, exist_ok=True)

    if header.get("kind", "file") == "folder":
        handle, temp_name = secure_mkstemp(prefix="usb-locker-unlock-", suffix=".zip")
        os.close(handle)
        archive_path = Path(temp_name)
        archive_path.unlink(missing_ok=True)
        out_path = unique_path(parent / original_name)
        temp_folder = parent / f".{out_path.name}.unlocking-{secrets.token_hex(6)}"
        try:
            decrypt_locked_to_file(path, archive_path, key, pin)
            temp_folder.mkdir(parents=True, exist_ok=False)
            extract_folder_archive(archive_path, temp_folder)
            temp_folder.replace(out_path)
            return out_path
        except Exception:
            if temp_folder.exists():
                shutil.rmtree(temp_folder, ignore_errors=True)
            raise
        finally:
            archive_path.unlink(missing_ok=True)

    out_path = unique_path(parent / original_name)
    partial = parent / f".{out_path.name}.unlocking-{secrets.token_hex(6)}"
    try:
        decrypt_locked_to_file(path, partial, key, pin)
        partial.replace(out_path)
        return out_path
    except Exception:
        partial.unlink(missing_ok=True)
        raise


def upgrade_legacy_locked(path, key, pin):
    path = Path(path)
    info = locked_file_info(path)
    if info["portable"]:
        raise ValueError("This locked file is already portable.")
    handle, temp_name = secure_mkstemp(prefix="usb-locker-upgrade-")
    os.close(handle)
    temp_path = Path(temp_name)
    temp_path.unlink(missing_ok=True)
    try:
        header = decrypt_locked_to_file(path, temp_path, key, pin)
        original_name = header.get("original_name") or path.stem
        portable_header = portable_lock_header(original_name, temp_path.stat().st_size, key, kind="file")
        base_name = path.name
        for suffix in (".locked", ".lookeed"):
            if base_name.lower().endswith(suffix):
                base_name = base_name[: -len(suffix)]
                break
        out_path = unique_path(path.with_name(base_name + ".portable.locked"))
        write_portable_locked(temp_path, out_path, portable_header, key, pin)
        check_handle, check_name = secure_mkstemp(prefix="usb-locker-upgrade-check-")
        os.close(check_handle)
        check_path = Path(check_name)
        check_path.unlink(missing_ok=True)
        try:
            decrypt_locked_to_file(out_path, check_path, key, pin)
            if file_sha256(check_path) != file_sha256(temp_path):
                raise ValueError("The upgraded portable lock failed verification.")
        finally:
            check_path.unlink(missing_ok=True)
        return out_path
    finally:
        temp_path.unlink(missing_ok=True)


def verify_locked_health(path, key, pin):
    path = Path(path)
    handle, temp_name = secure_mkstemp(prefix="usb-locker-health-")
    os.close(handle)
    temp_path = Path(temp_name)
    temp_path.unlink(missing_ok=True)
    try:
        header = decrypt_locked_to_file(path, temp_path, key, pin)
        kind = header.get("kind", "file")
        if kind == "folder":
            with zipfile.ZipFile(temp_path, "r") as archive:
                bad_member = archive.testzip()
                if bad_member:
                    raise ValueError("The folder archive contains damaged data.")
                infos = archive.infolist()
                for info in infos:
                    safe_zip_member_path(info.filename)
                    mode = (info.external_attr >> 16) & 0o170000
                    if mode == stat.S_IFLNK:
                        raise ValueError("The folder archive contains an unsupported link.")
                return {
                    "kind": "folder",
                    "format": locked_file_info(path)["format"],
                    "file_count": sum(not info.is_dir() for info in infos),
                    "total_size": sum(info.file_size for info in infos if not info.is_dir()),
                }
        expected_size = header.get("original_size")
        actual_size = temp_path.stat().st_size
        if expected_size is not None and int(expected_size) != actual_size:
            raise ValueError("The unlocked size does not match the signed header.")
        return {
            "kind": "file",
            "format": locked_file_info(path)["format"],
            "file_count": 1,
            "total_size": actual_size,
        }
    finally:
        temp_path.unlink(missing_ok=True)


def run_portable_recovery_test(key, pin):
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    test_root = Path(tempfile.mkdtemp(prefix="usb-locker-self-test-", dir=TEMP_DIR))
    try:
        plain_path = test_root / "recovery-test.bin"
        plain_path.write_bytes(secrets.token_bytes(512 * 1024 + 17))
        expected_hash = file_sha256(plain_path)
        locked_path = lock_file(plain_path, key, pin)
        info = locked_file_info(locked_path)
        if not info["portable"]:
            raise ValueError("The self-test did not create a portable lock.")
        plain_path.unlink()
        output_dir = test_root / "restored"
        restored = unlock_file(locked_path, key, pin, output_dir)
        if file_sha256(restored) != expected_hash:
            raise ValueError("The recovery self-test restored different data.")
        return {
            "format": info["format"],
            "key_id": key["key_id"],
            "bytes_tested": restored.stat().st_size,
        }
    finally:
        shutil.rmtree(test_root, ignore_errors=True)


def should_auto_delete_unlocked(path):
    return Path(path).is_file()


def delete_temp_unlocked_file(path):
    path = Path(path)
    if not path.exists():
        return True
    path.unlink()
    log_event("delete_unlocked_temp", path, "ok")
    return True


def start_temp_delete_worker(path):
    thread = threading.Thread(target=delete_temp_after_delay, args=(path,), name="DeleteUnlockedTempAfterDelay")
    thread.daemon = False
    thread.start()
    return thread


def schedule_temp_cleanup(path, master=None, close_master_when_done=False):
    if master is not None:
        TempCleanupWindow(master, path, close_master_when_done=close_master_when_done)
    else:
        start_temp_delete_worker(path)


def open_temp_then_delete(path, master=None, close_master_when_done=False):
    path = Path(path)
    if path.suffix.lower() not in TEXT_VIEW_EXTS:
        try:
            os.startfile(path)
        except Exception as exc:
            log_event("open_temp_unlocked_file", path, "failed", str(exc))
            schedule_temp_cleanup(path, master, close_master_when_done=close_master_when_done)
            messagebox.showerror(
                "Could not open temporary file",
                f"Windows could not open this unlocked file:\n{path}\n\n"
                "The unlocked copy will still be deleted automatically.\n\n"
                f"{exc}",
            )
            return False
        schedule_temp_cleanup(path, master, close_master_when_done=close_master_when_done)
        return True

    try:
        process = subprocess.Popen(["notepad.exe", str(path)])
    except Exception as exc:
        log_event("open_temp_unlocked_text", path, "failed", str(exc))
        if master is not None:
            schedule_temp_cleanup(path, master, close_master_when_done=False)
        else:
            start_temp_delete_worker(path)
        messagebox.showerror(
            "Could not open temporary file",
            f"Could not open this unlocked text file:\n{path}\n\n"
            "The unlocked copy will still be deleted automatically.\n\n"
            f"{exc}",
        )
        return False

    def worker(open_process):
        try:
            open_process.wait()
            delete_temp_unlocked_file(path)
        except Exception as exc:
            log_event("delete_unlocked_temp_after_view", path, "failed", str(exc))
            start_temp_delete_worker(path)
            if master is not None:
                try:
                    master.after(
                        0,
                        lambda message=str(exc): messagebox.showerror(
                            "Could not open temporary file",
                            f"Could not open this unlocked text file:\n{path}\n\n"
                            "The unlocked copy will still be deleted automatically.\n\n"
                            f"{message}",
                        ),
                    )
                except Exception:
                    pass
        finally:
            if close_master_when_done and master is not None:
                try:
                    master.after(0, master.destroy)
                except Exception:
                    pass

    thread = threading.Thread(target=worker, args=(process,), name="DeleteUnlockedTextAfterView")
    thread.daemon = False
    thread.start()
    return True


def delete_temp_after_delay(path):
    time.sleep(TEMP_DELETE_SECONDS)
    while Path(path).exists():
        try:
            delete_temp_unlocked_file(path)
            return
        except Exception as exc:
            log_event("delete_unlocked_temp_retry", path, "failed", str(exc))
            time.sleep(10)


class TempCleanupWindow(tk.Toplevel):
    def __init__(self, master, path, close_master_when_done=False):
        super().__init__(master)
        self.path = Path(path)
        self.close_master_when_done = close_master_when_done
        self.seconds_left = TEMP_DELETE_SECONDS
        self.title("Temporary Unlock Cleanup")
        self.geometry("520x230")
        self.resizable(False, False)
        self.configure(bg=BG)
        self.status = tk.StringVar(value="This unlocked copy will be deleted automatically.")
        self.timer = tk.StringVar(value="")
        self.build_ui()
        self.tick()

    def build_ui(self):
        wrap = tk.Frame(self, bg=BG)
        wrap.pack(fill="both", expand=True, padx=18, pady=16)
        tk.Label(wrap, text="Temporary Unlocked File", bg=BG, fg=TEXT, font=("Segoe UI", 18, "bold")).pack(anchor="w")
        tk.Label(wrap, text=str(self.path), bg=BG, fg=MUTED, font=("Segoe UI", 9), wraplength=470, justify="left").pack(anchor="w", pady=(4, 12))
        tk.Label(wrap, textvariable=self.timer, bg=BG, fg=YELLOW, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        tk.Label(wrap, textvariable=self.status, bg=BG, fg=MUTED, font=("Segoe UI", 9), wraplength=470, justify="left").pack(anchor="w", pady=(4, 12))
        row = tk.Frame(wrap, bg=BG)
        row.pack(fill="x")
        tk.Button(row, text="DELETE NOW", command=self.try_delete, bg=GREEN, fg=BLACK, relief="flat", font=("Segoe UI", 10, "bold")).pack(side="left", ipadx=18, ipady=8)
        tk.Button(row, text="OPEN FOLDER", command=self.open_folder, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 10, "bold")).pack(side="left", padx=(10, 0), ipadx=14, ipady=8)

    def open_folder(self):
        try:
            os.startfile(self.path.parent)
        except Exception as exc:
            self.status.set("Could not open the file folder.")
            messagebox.showerror("Could not open folder", str(exc))

    def tick(self):
        if not self.path.exists():
            self.finish()
            return
        minutes, seconds = divmod(max(0, self.seconds_left), 60)
        self.timer.set(f"Auto-delete in {minutes:02d}:{seconds:02d}")
        if self.seconds_left <= 0:
            self.try_delete(auto_retry=True)
            return
        self.seconds_left -= 1
        self.after(1000, self.tick)

    def try_delete(self, auto_retry=False):
        try:
            delete_temp_unlocked_file(self.path)
            self.finish()
        except Exception as exc:
            log_event("delete_unlocked_temp_window", self.path, "failed", str(exc))
            self.status.set("Could not delete yet. Close the app that opened the file; I will retry.")
            if auto_retry:
                self.after(5000, lambda: self.try_delete(auto_retry=True))

    def finish(self):
        self.status.set("Temporary unlocked copy deleted.")
        if self.close_master_when_done:
            try:
                self.master.destroy()
                return
            except Exception:
                pass
        self.after(500, self.destroy)


def load_personal_vault(key, pin):
    if not VAULT_FILE.exists():
        return []
    header, encrypted = unpack_blob(VAULT_FILE.read_bytes(), VAULT_MAGIC, "This is not a USB File Locker personal vault.")
    check_locked_key(header, key)
    if header.get("cipher") == "AES-256-GCM":
        try:
            salt = base64.b64decode(header["salt"].encode("ascii"), validate=True)
            nonce = base64.b64decode(header["nonce"].encode("ascii"), validate=True)
            vault_key = derive_portable_key(
                key["secret"],
                pin,
                salt,
                int(header.get("kdf_n", 2**15)),
                int(header.get("kdf_r", 8)),
                int(header.get("kdf_p", 1)),
            )
            plain = AESGCM(vault_key).decrypt(nonce, encrypted, portable_header_bytes(header))
        except InvalidTag as exc:
            raise ValueError("The PIN is wrong, the USB key is wrong, or the vault is damaged.") from exc
    else:
        try:
            entropy = derive_entropy(key["secret"], pin)
            plain = dpapi_unprotect(encrypted, entropy)
        except OSError as exc:
            raise ValueError(
                "This is an old Windows-bound vault. Open it on the Windows account "
                "that created it, then save it once to upgrade it to portable encryption."
            ) from exc
    data = json.loads(plain.decode("utf-8"))
    return data.get("entries", [])


def save_personal_vault(entries, key, pin):
    payload = {
        "version": 1,
        "key_id": key["key_id"],
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "entries": entries,
    }
    plain = json.dumps(payload, indent=2).encode("utf-8")
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    header = {
        "format_version": PORTABLE_FORMAT_VERSION,
        "kind": "personal_vault",
        "cipher": "AES-256-GCM",
        "kdf": "scrypt",
        "kdf_n": 2**15,
        "kdf_r": 8,
        "kdf_p": 1,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "key_id": key["key_id"],
        "updated_at": payload["updated_at"],
        "entry_count": len(entries),
        "portable": True,
    }
    vault_key = derive_portable_key(key["secret"], pin, salt)
    encrypted = AESGCM(vault_key).encrypt(nonce, plain, portable_header_bytes(header))
    write_bytes_atomic(VAULT_FILE, pack_blob(VAULT_MAGIC, header, encrypted))
    return VAULT_FILE


class UpdateCenterWindow(tk.Toplevel):
    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.title("VaultLink Update Center" + (" - OWNER LAB" if LAB_MODE else ""))
        self.geometry("900x760")
        self.minsize(780, 660)
        self.configure(bg=BG)
        self.current_var = tk.StringVar(value=f"Installed version: {DESKTOP_APP_VERSION}" + (" (OWNER LAB)" if LAB_MODE else ""))
        self.latest_var = tk.StringVar(value="Latest signed version: checking...")
        self.api_var = tk.StringVar(value="API compatibility: checking...")
        self.verification_var = tk.StringVar(value="Signature and package identity: not checked")
        self.preservation_var = tk.StringVar(value="Preserved: keys, licenses, settings, vault data, audit logs, and locked files")
        self.status_var = tk.StringVar(value="Ready to check for a signed update.")
        self.auto_var = tk.BooleanVar(value=False if LAB_MODE else bool(owner.settings.get("auto_update_check", True)))
        self.auto_install_var = tk.BooleanVar(value=False if LAB_MODE else bool(owner.settings.get("auto_install_signed_updates", False)))
        self.notes = None
        self.check_button = None
        self.install_button = None
        self.hash_button = None
        self.receipt_button = None
        self.details_button = None
        self.download_button = None
        self.build_ui()
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.show_manifest(owner.latest_update_manifest)

    def build_ui(self):
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True, padx=24, pady=22)
        tk.Label(outer, text="Update Center", bg=BG, fg=TEXT, font=("Segoe UI", 25, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="SIGNED RELEASE MANIFEST | SHA-256 PACKAGE CHECK | APP-DATA PRESERVED",
            bg=BG,
            fg=GREEN,
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w", pady=(4, 16))

        status_panel = tk.Frame(outer, bg=PANEL)
        status_panel.pack(fill="x")
        for variable, color in (
            (self.current_var, TEXT),
            (self.latest_var, YELLOW),
            (self.api_var, MUTED),
            (self.verification_var, GREEN),
        ):
            tk.Label(
                status_panel,
                textvariable=variable,
                bg=PANEL,
                fg=color,
                justify="left",
                font=("Segoe UI", 10, "bold"),
            ).pack(anchor="w", padx=18, pady=(12 if variable is self.current_var else 2, 0))
        tk.Label(
            status_panel,
            textvariable=self.preservation_var,
            bg=PANEL,
            fg=MUTED,
            justify="left",
            wraplength=680,
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=18, pady=(8, 14))

        tk.Label(outer, text="RELEASE NOTES", bg=BG, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(16, 6))
        self.notes = tk.Text(
            outer,
            height=6,
            bg=FIELD,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            wrap="word",
            font=("Segoe UI", 10),
            state="disabled",
        )
        self.notes.pack(fill="both", expand=True)

        options = tk.Frame(outer, bg=BG)
        options.pack(fill="x", pady=(12, 0))
        auto_check = tk.Checkbutton(
            options,
            text="AUTO-CHECK DAILY",
            variable=self.auto_var,
            command=lambda: self.owner.set_auto_update_check(self.auto_var.get()),
            bg=BG,
            fg=TEXT,
            selectcolor=FIELD,
            activebackground=BG,
            activeforeground=TEXT,
            font=("Segoe UI", 8, "bold"),
        )
        auto_check.pack(side="left")
        auto_install = tk.Checkbutton(
            options,
            text="AUTO-INSTALL VERIFIED UPDATES",
            variable=self.auto_install_var,
            command=self.set_auto_install,
            bg=BG,
            fg=TEXT,
            selectcolor=FIELD,
            activebackground=BG,
            activeforeground=TEXT,
            font=("Segoe UI", 8, "bold"),
        )
        auto_install.pack(side="left", padx=(16, 0))
        if LAB_MODE:
            auto_check.configure(state="disabled")
            auto_install.configure(state="disabled")
            self.status_var.set("OWNER LAB mode: update installation is disabled for this private runtime.")

        controls = tk.Frame(outer, bg=BG)
        controls.pack(fill="x", pady=(14, 0))
        self.check_button = tk.Button(
            controls,
            text="CHECK NOW",
            command=lambda: self.owner.start_update_check(silent=False),
            bg="#252936",
            fg=TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        self.check_button.pack(side="left", ipadx=14, ipady=8)
        self.install_button = tk.Button(
            controls,
            text="INSTALL VERIFIED UPDATE",
            command=self.owner.install_latest_update,
            state="disabled",
            bg=GREEN,
            fg=BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        self.install_button.pack(side="left", padx=(10, 0), ipadx=14, ipady=8)
        tk.Button(
            controls,
            text="SERVICE STATUS",
            command=self.owner.open_customer_status,
            bg="#252936",
            fg=TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(
            controls,
            text="CLOSE",
            command=self.destroy,
            bg="#252936",
            fg=TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right", ipadx=14, ipady=8)
        web_controls = tk.Frame(outer, bg=BG)
        web_controls.pack(fill="x", pady=(10, 0))
        tk.Button(
            web_controls,
            text="WEB UPDATE CHECK",
            command=self.owner.open_web_update_center,
            bg="#252936",
            fg=TEXT,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", ipadx=12, ipady=7)
        tk.Button(
            web_controls,
            text="RECOVERY READINESS",
            command=self.owner.open_recovery_readiness,
            bg=YELLOW,
            fg=BLACK,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", padx=(10, 0), ipadx=12, ipady=7)
        self.details_button = tk.Button(
            web_controls,
            text="VERIFICATION DETAILS",
            command=self.show_verification_details,
            state="disabled",
            bg="#252936",
            fg=TEXT,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        )
        self.details_button.pack(side="left", padx=(10, 0), ipadx=12, ipady=7)

        evidence_controls = tk.Frame(outer, bg=BG)
        evidence_controls.pack(fill="x", pady=(10, 0))
        self.hash_button = tk.Button(
            evidence_controls,
            text="COPY VERIFIED SHA-256",
            command=self.copy_verified_hash,
            state="disabled",
            bg="#252936",
            fg=TEXT,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        )
        self.hash_button.pack(side="left", ipadx=12, ipady=7)
        self.receipt_button = tk.Button(
            evidence_controls,
            text="EXPORT VERIFICATION RECEIPT",
            command=self.export_verification_receipt,
            state="disabled",
            bg="#252936",
            fg=TEXT,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        )
        self.receipt_button.pack(side="left", padx=(10, 0), ipadx=12, ipady=7)
        tk.Button(
            evidence_controls,
            text="BACK UP APP DATA",
            command=self.owner.backup_app_data,
            bg=YELLOW,
            fg=BLACK,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", padx=(10, 0), ipadx=12, ipady=7)

        tools_controls = tk.Frame(outer, bg=BG)
        tools_controls.pack(fill="x", pady=(10, 0))
        tk.Button(
            tools_controls,
            text="UPDATE READINESS",
            command=self.show_update_readiness,
            bg="#252936",
            fg=TEXT,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", ipadx=12, ipady=7)
        self.download_button = tk.Button(
            tools_controls,
            text="DOWNLOAD VERIFIED COPY",
            command=self.owner.download_latest_update_copy,
            state="disabled",
            bg="#252936",
            fg=TEXT,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        )
        self.download_button.pack(side="left", padx=(10, 0), ipadx=12, ipady=7)
        tk.Button(
            tools_controls,
            text="UPDATE ACTIVITY",
            command=self.show_update_activity,
            bg="#252936",
            fg=TEXT,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", padx=(10, 0), ipadx=12, ipady=7)
        tk.Button(
            tools_controls,
            text="UPDATE BACKUPS",
            command=self.owner.open_update_backups,
            bg="#252936",
            fg=TEXT,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", padx=(10, 0), ipadx=12, ipady=7)
        tk.Label(
            outer,
            textvariable=self.status_var,
            bg=BG,
            fg=MUTED,
            justify="left",
            wraplength=700,
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(12, 0))

    def set_auto_install(self):
        enabled = bool(self.auto_install_var.get())
        if enabled:
            self.auto_var.set(True)
        self.owner.set_auto_install_updates(enabled)

    def set_notes(self, lines):
        text = "\n".join(f"- {line}" for line in lines) if lines else "No release notes were supplied."
        self.notes.configure(state="normal")
        self.notes.delete("1.0", "end")
        self.notes.insert("1.0", text)
        self.notes.configure(state="disabled")

    def checked_at_utc(self):
        return str(self.owner.settings.get("last_update_check_utc", "") or utc_now_text())

    def copy_verified_hash(self):
        manifest = self.owner.latest_update_manifest
        value = str((manifest or {}).get("sha256", "")).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            messagebox.showerror("No verified hash", "Check for a signed update first.", parent=self)
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.status_var.set("Copied the SHA-256 from the verified signed manifest.")
        log_event("update_hash_copy", "release", "ok")

    def export_verification_receipt(self):
        manifest = self.owner.latest_update_manifest
        try:
            receipt = update_verification_receipt(manifest, self.checked_at_utc())
        except Exception as exc:
            messagebox.showerror("Receipt unavailable", str(exc), parent=self)
            return
        target = filedialog.asksaveasfilename(
            title="Export privacy-safe update verification receipt",
            defaultextension=".json",
            initialfile=f"VaultLink-Update-Receipt-{receipt['release_version']}.json",
            filetypes=[("JSON receipt", "*.json")],
        )
        if not target:
            return
        try:
            write_text_atomic(Path(target), json.dumps(receipt, indent=2))
            self.status_var.set("Exported a privacy-safe signed-update verification receipt.")
            log_event("update_receipt_export", "release", "ok")
        except Exception as exc:
            log_event("update_receipt_export", "release", "failed")
            messagebox.showerror("Could not export receipt", str(exc), parent=self)

    def show_verification_details(self):
        manifest = self.owner.latest_update_manifest
        try:
            receipt = update_verification_receipt(manifest, self.checked_at_utc())
        except Exception as exc:
            messagebox.showerror("Verification unavailable", str(exc), parent=self)
            return
        lines = [
            f"Release: {receipt['release_version']}",
            f"Installed: {receipt['installed_version']}",
            f"Minimum supported: {receipt['minimum_supported_version']}",
            f"Published: {receipt['published_at_utc']}",
            f"Checked: {receipt['verified_at_utc']}",
            f"API: {receipt['api_version'] or 'not reported'}",
            f"Package: {receipt['package_filename']}",
            f"Size: {format_update_size(receipt['package_size_bytes'])}",
            f"Signing key ID: {receipt['signing_key_id']}",
            f"SHA-256: {receipt['package_sha256']}",
            "",
            "Ed25519 signature: VERIFIED",
            "Package hash format: VERIFIED",
            "App-data preservation promise: VERIFIED",
            "",
            receipt["privacy_note"],
        ]
        messagebox.showinfo("Signed Update Verification", "\n".join(lines), parent=self)

    def show_update_readiness(self):
        try:
            report = update_readiness_report(self.owner.latest_update_manifest)
        except Exception as exc:
            messagebox.showerror("Readiness unavailable", str(exc), parent=self)
            return
        lines = [
            f"Release: {report['release_version']}",
            f"Install mode: {report['installation_mode']}",
            f"Automatic install ready: {'YES' if report['ready_for_automatic_install'] else 'NO'}",
            "",
        ]
        for item in report["checks"]:
            lines.append(f"{'PASS' if item['passed'] else 'CHECK'} | {item['name']} | {item['detail']}")
        lines.extend(["", report["privacy_note"]])
        messagebox.showinfo("Update Readiness", "\n".join(lines), parent=self)

    def show_update_activity(self):
        report = update_activity_summary()
        lines = []
        latest = report.get("latest_install") or {}
        if latest:
            lines.extend(
                [
                    f"Latest installer result: {'SUCCESS' if latest['ok'] else 'FAILED'}",
                    f"Version: {latest['version']}",
                    f"Time: {latest['time_utc'] or 'unknown'}",
                    f"Rollback backup created: {'yes' if latest['backup_created'] else 'no'}",
                    "",
                ]
            )
        lines.append("RECENT ANONYMOUS UPDATE EVENTS")
        lines.append("------------------------------")
        for event in reversed(report["events"]):
            lines.append(
                f"{event['time_utc'] or 'unknown'} | {event['result'].upper()} | "
                f"{event['title']} | event {event['event_id'] or 'unknown'}"
            )
        if not report["events"]:
            lines.append("No update activity has been recorded yet.")
        lines.extend(["", report["privacy_note"]])
        messagebox.showinfo("Update Activity", "\n".join(lines), parent=self)

    def show_manifest(self, manifest, error=""):
        busy = self.owner.update_operation in {"check", "stage", "copy"}
        self.check_button.configure(state="disabled" if busy else "normal")
        if error:
            self.latest_var.set("Latest signed version: unavailable")
            self.api_var.set("API compatibility: check failed")
            self.status_var.set(error)
            self.verification_var.set("Signature and package identity: check failed")
            self.install_button.configure(state="disabled")
            self.hash_button.configure(state="disabled")
            self.receipt_button.configure(state="disabled")
            self.details_button.configure(state="disabled")
            self.download_button.configure(state="disabled")
            self.set_notes([])
            return
        if not manifest:
            self.latest_var.set("Latest signed version: not checked")
            self.api_var.set("API compatibility: not checked")
            self.status_var.set("Check the API for a signed release.")
            self.verification_var.set("Signature and package identity: not checked")
            self.install_button.configure(state="disabled")
            self.hash_button.configure(state="disabled")
            self.receipt_button.configure(state="disabled")
            self.details_button.configure(state="disabled")
            self.download_button.configure(state="disabled")
            self.set_notes([])
            return
        version = manifest.get("version", "unknown")
        available = bool(manifest.get("update_available"))
        supported = bool(manifest.get("current_version_supported"))
        self.latest_var.set(f"Latest signed version: {version}")
        compatibility = "supported" if supported else "update required"
        self.api_var.set(f"API {manifest.get('api_version', 'unknown')} | Current desktop: {compatibility}")
        self.verification_var.set(
            f"VERIFIED SIGNATURE | {format_update_size(manifest.get('size_bytes'))} | "
            f"KEY {manifest.get('signing_key_id', 'unknown')} | SHA-256 {str(manifest.get('sha256', ''))[:16]}..."
        )
        self.hash_button.configure(state="normal")
        self.receipt_button.configure(state="normal")
        self.details_button.configure(state="normal")
        self.download_button.configure(state="disabled" if busy else "normal")
        if available and not supported:
            self.status_var.set("This desktop version is below the supported floor. Install the verified update before relying on API features.")
        elif available:
            self.status_var.set("A newer signed update is ready. Review the notes, then install it.")
        else:
            self.status_var.set("This app is already on the latest signed version.")
        can_install = available and not busy and not LAB_MODE and not (RUNTIME_DIR / ".git").exists()
        self.install_button.configure(state="normal" if can_install else "disabled")
        if LAB_MODE:
            self.status_var.set("OWNER LAB mode: signed releases may be inspected or downloaded, but installation is disabled.")
        elif available and (RUNTIME_DIR / ".git").exists():
            self.status_var.set("Update found. This is a Git working folder, so use git pull instead of auto-install.")
        self.set_notes(manifest.get("notes") or [])


class OwnerNewsWindow(tk.Toplevel):
    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.title("VaultLink Owner News")
        self.geometry("720x620")
        self.minsize(640, 520)
        self.configure(bg=BG)
        self.status_var = tk.StringVar(value="Checking for owner announcements...")
        self.results = queue.Queue()
        self.busy = False
        self.news_box = None
        self.refresh_button = None
        self.build_ui()
        self.after(150, self.refresh_news)

    def build_ui(self):
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True, padx=24, pady=20)
        tk.Label(outer, text="Owner News", bg=BG, fg=TEXT, font=("Segoe UI", 24, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="READ-ONLY MESSAGES FOR YOUR LICENSE RANK | MESSAGES CANNOT RUN COMMANDS OR ACCESS FILES",
            bg=BG,
            fg=GREEN,
            font=("Segoe UI", 8, "bold"),
            wraplength=660,
            justify="left",
        ).pack(anchor="w", pady=(4, 14))

        self.news_box = tk.Text(
            outer,
            bg=FIELD,
            fg=TEXT,
            relief="flat",
            wrap="word",
            font=("Segoe UI", 10),
            padx=14,
            pady=12,
            state="disabled",
        )
        self.news_box.pack(fill="both", expand=True)

        controls = tk.Frame(outer, bg=BG)
        controls.pack(fill="x", pady=(12, 0))
        self.refresh_button = tk.Button(
            controls,
            text="REFRESH NEWS",
            command=self.refresh_news,
            bg="#58b7e8",
            fg=BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        self.refresh_button.pack(side="left", ipadx=14, ipady=8)
        tk.Button(
            controls,
            text="OPEN SHOP",
            command=self.owner.open_shop,
            bg=GREEN,
            fg=BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(10, 0), ipadx=14, ipady=8)
        tk.Button(
            controls,
            text="CLOSE",
            command=self.destroy,
            bg="#252936",
            fg=TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right", ipadx=14, ipady=8)
        tk.Label(
            outer,
            textvariable=self.status_var,
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 9),
            wraplength=660,
            justify="left",
        ).pack(anchor="w", pady=(10, 0))

    def refresh_news(self):
        if self.busy:
            return
        self.owner.settings = load_settings()
        self.owner.update_license_state_ui(load_license_state(self.owner.settings))
        state = self.owner.license_state
        self.busy = True
        self.refresh_button.configure(state="disabled", text="CHECKING...")
        self.status_var.set("Checking the API for active owner announcements...")

        def worker():
            try:
                result = list_owner_announcements_online(state)
                error = ""
            except Exception as exc:
                result = None
                error = str(exc)
            self.results.put((result, error))

        threading.Thread(target=worker, name="OwnerAnnouncementList", daemon=True).start()
        self.after(60, self.poll_results)

    def poll_results(self):
        try:
            result, error = self.results.get_nowait()
        except queue.Empty:
            if self.busy and self.winfo_exists():
                self.after(60, self.poll_results)
            return
        self.busy = False
        self.refresh_button.configure(state="normal", text="REFRESH NEWS")
        if error:
            self.status_var.set(error)
            log_event("owner_announcement_view", "api", "failed")
            messagebox.showerror("Owner News API error", error, parent=self)
            return
        items = (result or {}).get("items") or []
        self.render_news(items, (result or {}).get("service_status"))
        rank = int((result or {}).get("plan_rank", 1) or 1)
        self.status_var.set(f"Loaded {len(items)} active message(s) for Rank {rank}.")
        log_event("owner_announcement_view", "api", "ok")

    def render_news(self, items, service_status=None):
        blocks = []
        service = normalize_service_status(service_status)
        blocks.append(
            "\n".join(
                [
                    f"[SERVICE {service['mode'].upper()}]",
                    service["message"],
                    f"Updated: {service['updated_at_utc'] or 'default status'}",
                    f"Expires: {service['expires_at_utc'] or 'not scheduled'}",
                ]
            )
        )
        for item in items:
            severity = str(item.get("severity", "info") or "info").upper()
            block = [
                f"[{severity}] {item.get('title', 'Owner announcement')}",
                f"Audience: {item.get('audience', 'All ranks')}",
                f"Published: {item.get('created_at_utc', '')}",
            ]
            if item.get("expires_at_utc"):
                block.append(f"Expires: {item.get('expires_at_utc')}")
            block.extend(["", str(item.get("message", ""))])
            blocks.append("\n".join(block))
        text = "\n\n".join(blocks) if blocks else "There are no active owner announcements for this license rank."
        self.news_box.configure(state="normal")
        self.news_box.delete("1.0", "end")
        self.news_box.insert("1.0", text)
        self.news_box.configure(state="disabled")


class SupportCenterWindow(tk.Toplevel):
    CATEGORIES = {
        "BUG": "bug",
        "CRASH": "crash",
        "LICENSING": "licensing",
        "UPDATE": "update",
        "SECURITY": "security",
        "IDEA": "idea",
        "OTHER": "other",
    }

    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.title("VaultLink Bug Center")
        self.geometry("780x760")
        self.minsize(700, 680)
        self.configure(bg=BG)
        self.category_var = tk.StringVar(value="BUG")
        self.subject_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready to contact the VaultLink owner.")
        self.results = queue.Queue()
        self.busy = False
        self.message_box = None
        self.steps_box = None
        self.ticket_box = None
        self.send_button = None
        self.refresh_button = None
        self.build_ui()
        self.after(150, self.refresh_tickets)

    def build_ui(self):
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True, padx=24, pady=20)
        tk.Label(outer, text="Bug Center", bg=BG, fg=TEXT, font=("Segoe UI", 24, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="NO FILES OR LOCAL LOGS ATTACHED | NEVER INCLUDE PASSWORDS, PINS, USB SECRETS, OR CLIENT INFORMATION",
            bg=BG,
            fg=YELLOW,
            font=("Segoe UI", 8, "bold"),
            wraplength=720,
            justify="left",
        ).pack(anchor="w", pady=(4, 14))

        form = tk.Frame(outer, bg=PANEL)
        form.pack(fill="x")
        heading = tk.Frame(form, bg=PANEL)
        heading.pack(fill="x", padx=16, pady=(14, 8))
        category_host = tk.Frame(heading, bg=PANEL)
        category_host.pack(side="left", fill="x")
        tk.Label(category_host, text="CATEGORY", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
        ttk.Combobox(
            category_host,
            textvariable=self.category_var,
            values=list(self.CATEGORIES),
            state="readonly",
            width=16,
        ).pack(anchor="w", pady=(4, 0))
        subject_host = tk.Frame(heading, bg=PANEL)
        subject_host.pack(side="left", fill="x", expand=True, padx=(14, 0))
        tk.Label(subject_host, text="SUBJECT", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
        tk.Entry(
            subject_host,
            textvariable=self.subject_var,
            bg=FIELD,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            font=("Segoe UI", 10),
        ).pack(fill="x", pady=(4, 0), ipady=6)

        tk.Label(form, text="WHAT HAPPENED", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=16)
        self.message_box = tk.Text(form, height=6, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", wrap="word", font=("Segoe UI", 10))
        self.message_box.pack(fill="x", padx=16, pady=(4, 10))
        tk.Label(form, text="STEPS TO REPRODUCE, OPTIONAL", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=16)
        self.steps_box = tk.Text(form, height=4, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", wrap="word", font=("Segoe UI", 10))
        self.steps_box.pack(fill="x", padx=16, pady=(4, 12))

        controls = tk.Frame(form, bg=PANEL)
        controls.pack(fill="x", padx=16, pady=(0, 14))
        self.send_button = tk.Button(
            controls,
            text="SEND TO OWNER",
            command=self.send_ticket,
            bg=GREEN,
            fg=BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        self.send_button.pack(side="left", ipadx=16, ipady=8)
        self.refresh_button = tk.Button(
            controls,
            text="CHECK OWNER REPLIES",
            command=self.refresh_tickets,
            bg="#252936",
            fg=TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        self.refresh_button.pack(side="left", padx=(10, 0), ipadx=14, ipady=8)
        tk.Button(
            controls,
            text="CLOSE",
            command=self.destroy,
            bg="#252936",
            fg=TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right", ipadx=14, ipady=8)

        tk.Label(outer, text="MY REPORTS AND OWNER REPLIES", bg=BG, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(14, 6))
        self.ticket_box = tk.Text(outer, height=12, bg=FIELD, fg=TEXT, relief="flat", wrap="word", font=("Consolas", 9), state="disabled")
        self.ticket_box.pack(fill="both", expand=True)
        tk.Label(outer, textvariable=self.status_var, bg=BG, fg=MUTED, font=("Segoe UI", 9), wraplength=720, justify="left").pack(anchor="w", pady=(10, 0))

    def set_busy(self, busy, message=""):
        self.busy = busy
        state = "disabled" if busy else "normal"
        self.send_button.configure(state=state)
        self.refresh_button.configure(state=state)
        if message:
            self.status_var.set(message)

    def current_license_state(self):
        self.owner.settings = load_settings()
        self.owner.update_license_state_ui(load_license_state(self.owner.settings))
        return self.owner.license_state

    def send_ticket(self):
        if self.busy:
            return
        subject = self.subject_var.get().strip()
        category = self.CATEGORIES.get(self.category_var.get(), "bug")
        message = self.message_box.get("1.0", "end").strip()
        steps = self.steps_box.get("1.0", "end").strip()
        if len(subject) < 3:
            messagebox.showwarning("Subject needed", "Write a short subject with at least 3 characters.", parent=self)
            return
        if len(message) < 10:
            messagebox.showwarning("Description needed", "Describe what happened using at least 10 characters.", parent=self)
            return
        if not messagebox.askyesno(
            "Send bug report",
            "Send this text to the VaultLink owner through the API?\n\nNo files or local logs will be attached automatically.",
            parent=self,
        ):
            return
        state = self.current_license_state()
        self.set_busy(True, "Sending bug report to the owner...")

        def worker():
            try:
                result = create_support_ticket_online(
                    state,
                    category,
                    subject,
                    message,
                    steps,
                )
                error = ""
            except Exception as exc:
                result = None
                error = str(exc)
            self.results.put(("send", result, error))

        threading.Thread(target=worker, name="SupportTicketSend", daemon=True).start()
        self.after(60, self.poll_results)

    def refresh_tickets(self):
        if self.busy:
            return
        state = self.current_license_state()
        self.set_busy(True, "Checking the API for owner replies...")

        def worker():
            try:
                result = list_my_support_tickets_online(state)
                error = ""
            except Exception as exc:
                result = None
                error = str(exc)
            self.results.put(("list", result, error))

        threading.Thread(target=worker, name="SupportTicketList", daemon=True).start()
        self.after(60, self.poll_results)

    def poll_results(self):
        try:
            mode, result, error = self.results.get_nowait()
        except queue.Empty:
            if self.busy and self.winfo_exists():
                self.after(60, self.poll_results)
            return
        self.set_busy(False)
        if error:
            self.status_var.set(error)
            log_event("support_ticket_submit" if mode == "send" else "support_ticket_view", "api", "failed")
            messagebox.showerror("Bug Center API error", error, parent=self)
            return
        if mode == "send":
            ticket = (result or {}).get("ticket") or {}
            self.subject_var.set("")
            self.message_box.delete("1.0", "end")
            self.steps_box.delete("1.0", "end")
            self.status_var.set(f"Sent {ticket.get('ticket_id', 'bug report')} to the owner.")
            log_event("support_ticket_submit", "api", "ok")
            self.after(100, self.refresh_tickets)
            return
        items = (result or {}).get("items") or []
        self.render_tickets(items)
        self.status_var.set(f"Loaded {len(items)} report(s) and owner replies.")
        log_event("support_ticket_view", "api", "ok")

    def render_tickets(self, items):
        blocks = []
        for item in items:
            block = [
                f"{item.get('ticket_id', 'UNKNOWN')} | {str(item.get('status', 'open')).replace('_', ' ').upper()}",
                f"Subject: {item.get('subject', '')}",
                f"Sent: {item.get('created_at_utc', '')}",
            ]
            reply = str(item.get("owner_reply", "") or "").strip()
            block.append(f"Owner reply: {reply or 'No reply yet.'}")
            blocks.append("\n".join(block))
        text = "\n\n".join(blocks) if blocks else "No bug reports have been sent from this licensed PC."
        self.ticket_box.configure(state="normal")
        self.ticket_box.delete("1.0", "end")
        self.ticket_box.insert("1.0", text)
        self.ticket_box.configure(state="disabled")


class CustomerCenterWindow(tk.Toplevel):
    DETAIL_FIELDS = (
        ("LICENSE STATUS", "license_status"),
        ("PLAN", "plan"),
        ("DEVICE SEATS", "device_seats"),
        ("DESKTOP RELEASE", "desktop"),
        ("API VERSION", "api"),
        ("SERVICE STATUS", "service"),
        ("LAST LICENSE SYNC", "last_sync"),
        ("OWNER MESSAGES", "owner_messages"),
        ("AUTOMATIC VERIFIED UPDATES", "automatic_updates"),
    )

    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.title("VaultLink Customer Center")
        self.geometry("780x690")
        self.minsize(700, 620)
        self.configure(bg=BG)
        self.status_var = tk.StringVar(value="Customer information is privacy-safe and stored locally unless you verify online.")
        self.value_vars = {key: tk.StringVar(value="-") for _label, key in self.DETAIL_FIELDS}
        self.results = queue.Queue()
        self.busy = False
        self.verify_button = None
        self.build_ui()
        self.render_current()

    def build_ui(self):
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True, padx=24, pady=20)
        tk.Label(outer, text="Customer Center", bg=BG, fg=TEXT, font=("Segoe UI", 24, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="LICENSE KEY AND RECEIPT HIDDEN | NO FILES, PATHS, USB SECRETS, OR MACHINE ID SHOWN",
            bg=BG,
            fg=GREEN,
            font=("Segoe UI", 8, "bold"),
            wraplength=720,
            justify="left",
        ).pack(anchor="w", pady=(4, 14))

        details = tk.Frame(outer, bg=PANEL)
        details.pack(fill="both", expand=True)
        for index, (label, key) in enumerate(self.DETAIL_FIELDS):
            row = tk.Frame(details, bg=PANEL)
            row.pack(fill="x", padx=18, pady=(12 if index == 0 else 5, 0))
            tk.Label(row, text=label, width=25, anchor="w", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
            tk.Label(
                row,
                textvariable=self.value_vars[key],
                anchor="w",
                justify="left",
                bg=PANEL,
                fg=TEXT,
                font=("Segoe UI", 9, "bold"),
                wraplength=470,
            ).pack(side="left", fill="x", expand=True)

        primary = tk.Frame(outer, bg=BG)
        primary.pack(fill="x", pady=(14, 0))
        self.verify_button = tk.Button(primary, text="VERIFY LICENSE NOW", command=self.verify_now, bg=GREEN, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold"))
        self.verify_button.pack(side="left", ipadx=12, ipady=8)
        tk.Button(primary, text="CUSTOMER WORKSPACE", command=self.owner.open_customer_workspace, bg=BLUE, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(8, 0), ipadx=10, ipady=8)
        tk.Button(primary, text="UPDATE CENTER", command=self.owner.open_update_center, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(8, 0), ipadx=10, ipady=8)
        secondary = tk.Frame(outer, bg=BG)
        secondary.pack(fill="x", pady=(8, 0))
        tk.Button(secondary, text="PUBLIC STATUS", command=self.owner.open_customer_status, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=10, ipady=8)
        tk.Button(secondary, text="OWNER NEWS", command=self.owner.open_owner_news, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(8, 0), ipadx=10, ipady=8)
        tk.Button(secondary, text="BUG CENTER", command=self.owner.open_support_center, bg="#58b7e8", fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(8, 0), ipadx=10, ipady=8)
        tk.Button(secondary, text="SHOP", command=self.owner.open_shop, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(8, 0), ipadx=10, ipady=8)

        tertiary = tk.Frame(outer, bg=BG)
        tertiary.pack(fill="x", pady=(8, 0))
        tk.Button(tertiary, text="LICENSE CENTER", command=self.owner.open_license_center, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=10, ipady=8)
        tk.Button(tertiary, text="CLOSE", command=self.destroy, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=12, ipady=8)
        tk.Label(outer, textvariable=self.status_var, bg=BG, fg=MUTED, font=("Segoe UI", 9), wraplength=720, justify="left").pack(anchor="w", pady=(10, 0))

    def render_current(self):
        self.owner.settings = load_settings()
        self.owner.update_license_state_ui(load_license_state(self.owner.settings))
        details = customer_center_details(self.owner.license_state, self.owner.settings)
        for key, variable in self.value_vars.items():
            variable.set(details.get(key, "-"))
        has_proof = bool(self.owner.license_state.get("license_key") and self.owner.license_state.get("receipt"))
        self.verify_button.configure(state="normal" if has_proof and not self.busy else "disabled")

    def verify_now(self):
        if self.busy:
            return
        self.render_current()
        state = normalize_license_state(self.owner.license_state)
        if not state.get("license_key") or not state.get("receipt"):
            self.status_var.set("Open License Center to activate a license before verifying.")
            return
        self.busy = True
        self.verify_button.configure(state="disabled", text="VERIFYING...")
        self.status_var.set("Checking the license, device seat, service status, messages, and release information...")

        def worker():
            try:
                updated = verify_license_online(state)
                error = ""
            except Exception as exc:
                updated = None
                error = str(exc)
            self.results.put((updated, error))

        threading.Thread(target=worker, name="CustomerCenterVerify", daemon=True).start()
        self.after(75, self.poll_verify)

    def poll_verify(self):
        try:
            updated, error = self.results.get_nowait()
        except queue.Empty:
            if self.busy and self.winfo_exists():
                self.after(75, self.poll_verify)
            return
        self.busy = False
        self.verify_button.configure(text="VERIFY LICENSE NOW")
        if error:
            self.status_var.set(f"Verification failed: {error}")
            log_event("customer_center_verify", "api", "failed")
            self.render_current()
            return
        self.owner.update_license_state_ui(updated, save=True)
        self.owner.apply_access_state()
        self.render_current()
        self.status_var.set("Customer information refreshed from the API.")
        log_event("customer_center_verify", "api", "ok")


class USBFileLocker(tk.Tk):
    def __init__(self):
        super().__init__()
        cleanup_stale_secure_temp()
        self.title("USB File Locker" + (f" - OWNER LAB {DESKTOP_APP_VERSION}" if LAB_MODE else ""))
        self.geometry("920x760")
        self.minsize(860, 720)
        self.configure(bg=BG)
        self.settings = load_settings()
        self.owner_policy = load_owner_policy(self.settings)
        self.key = None
        self.status = tk.StringVar(value="No master USB key loaded.")
        self.key_status = tk.StringVar(value="LOCKED - load your master USB key")
        self.access_status = tk.StringVar(value="")
        self.breach_status = tk.StringVar(value="Breach detection ready.")
        self.license_state = load_license_state(self.settings)
        self.license_status = tk.StringVar(value=license_status_text(self.license_state))
        self.license_refresh_results = queue.Queue()
        self.license_refresh_in_progress = False
        self.license_refresh_after_id = None
        self.last_license_notice_status = ""
        self.update_results = queue.Queue()
        self.update_operation = ""
        self.latest_update_manifest = None
        self.update_window = None
        self.customer_window = None
        self.support_window = None
        self.news_window = None
        self.update_button = None
        self.cloud_audit_results = queue.Queue()
        self.cloud_audit_in_progress = False
        self.pin_visible = tk.BooleanVar(value=False)
        self.pin_mode = tk.StringVar(value="USB KEY ONLY")
        self.progress_value = tk.DoubleVar(value=0)
        self.progress_text = tk.StringVar(value="Ready")
        self.busy = False
        self.cancel_event = threading.Event()
        self.busy_buttons = []
        self.key_required_buttons = []
        self.license_gated_buttons = {}
        self.secondary_windows = []
        self.build_ui()
        self.protocol("WM_DELETE_WINDOW", self.close_requested)
        self.try_load_last_key()
        self.apply_access_state()
        self.refresh_breach_status()
        self.schedule_license_refresh(INITIAL_LICENSE_REFRESH_MS)
        self.after(20000, self.periodic_breach_refresh)
        self.after(1500, self.monitor_loaded_key)
        self.after(30000, self.periodic_cloud_audit_upload)
        if not LAB_MODE and self.settings.get("auto_update_check", True):
            self.after(6000, self.auto_check_for_updates)
        if LAB_MODE:
            log_event("owner_lab_runtime_start", "release", "ok", f"version={DESKTOP_APP_VERSION}")
        completed_update = os.environ.pop("VAULTLINK_UPDATE_COMPLETED", "").strip()
        if completed_update:
            log_event("application_update_completed", "release", "ok")
            self.after(
                1200,
                lambda version=completed_update: messagebox.showinfo(
                    "VaultLink updated",
                    f"Update {version} installed successfully. Your keys and app data were preserved.",
                    parent=self,
                ),
            )

    def build_ui(self):
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True, padx=26, pady=22)

        tk.Label(outer, text="USB File Locker", bg=BG, fg=TEXT, font=("Segoe UI", 25, "bold")).pack(anchor="w")
        if LAB_MODE:
            tk.Label(
                outer,
                text=f"OWNER LAB {DESKTOP_APP_VERSION} | PRIVATE VERIFIED CANDIDATE | STABLE APP NOT REPLACED",
                bg=BG,
                fg=YELLOW,
                font=("Segoe UI", 9, "bold"),
            ).pack(anchor="w", pady=(2, 4))
        tk.Label(outer, textvariable=self.key_status, bg=BG, fg=YELLOW, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(2, 2))
        tk.Label(outer, textvariable=self.access_status, bg=BG, fg=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 14))
        tk.Label(
            outer,
            text="PRIVACY LOGGING ON - activity history never stores client file names",
            bg=BG,
            fg=GREEN,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", pady=(0, 10))
        tk.Label(outer, textvariable=self.breach_status, bg=BG, fg=YELLOW, font=("Segoe UI", 9, "bold"), wraplength=860, justify="left").pack(anchor="w", pady=(0, 10))
        self.license_status_label = tk.Label(
            outer,
            textvariable=self.license_status,
            bg=BG,
            fg=GREEN,
            font=("Segoe UI", 9, "bold"),
            wraplength=860,
            justify="left",
        )
        self.license_status_label.pack(anchor="w", pady=(0, 12))

        panel = tk.Frame(outer, bg=PANEL)
        panel.pack(fill="both", expand=True)

        top = tk.Frame(panel, bg=PANEL)
        top.pack(fill="x", padx=18, pady=(18, 10))
        self.create_key_button = tk.Button(top, text="CREATE MASTER USB KEY", command=self.create_key, bg=WHITE, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold"))
        self.create_key_button.pack(side="left", ipadx=10, ipady=8)
        self.load_key_button = tk.Button(top, text="LOAD USB KEY", command=self.load_key, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.load_key_button.pack(side="left", padx=(10, 0), ipadx=10, ipady=8)
        self.panic_button = tk.Button(top, text="PANIC LOCK NOW", command=self.panic_lock_now, bg=RED, fg=WHITE, relief="flat", font=("Segoe UI", 9, "bold"))
        self.panic_button.pack(side="left", padx=(10, 0), ipadx=10, ipady=8)
        self.register_button = tk.Button(top, text="REGISTER .LOCKED", command=self.register_association_from_gui, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.register_button.pack(side="left", padx=(10, 0), ipadx=10, ipady=8)
        self.license_button = tk.Button(top, text="LICENSE CENTER", command=self.open_license_center, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.license_button.pack(side="left", padx=(10, 0), ipadx=10, ipady=8)

        top_tools = tk.Frame(panel, bg=PANEL)
        top_tools.pack(fill="x", padx=18, pady=(0, 10))
        self.apps_hub_button = tk.Button(top_tools, text="APPS HUB", command=self.open_apps_hub, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.apps_hub_button.pack(side="left", padx=(10, 0), ipadx=10, ipady=8)
        self.recovery_button = tk.Button(top_tools, text="RECOVERY CENTER", command=self.open_recovery_center, bg=YELLOW, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold"))
        self.recovery_button.pack(side="left", padx=(10, 0), ipadx=10, ipady=8)
        self.breach_button = tk.Button(top_tools, text="BREACH CHECK", command=self.open_breach_check, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.breach_button.pack(side="left", padx=(10, 0), ipadx=10, ipady=8)
        self.global_guard_button = tk.Button(top_tools, text="GLOBAL GUARD", command=self.open_global_breach_guard, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.global_guard_button.pack(side="left", padx=(10, 0), ipadx=10, ipady=8)
        self.owner_update_button = None
        if (SOURCE_DIR / "owner_update_lab.py").is_file():
            self.owner_update_button = tk.Button(top_tools, text="OWNER UPDATE LAB", command=self.open_owner_update_lab, bg=BLUE, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold"))
            self.owner_update_button.pack(side="left", padx=(10, 0), ipadx=10, ipady=8)
        self.audit_button = tk.Button(top_tools, text="AUDIT LOG", command=self.open_log, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.audit_button.pack(side="right", ipadx=10, ipady=8)

        owner_row = tk.Frame(panel, bg=PANEL)
        owner_row.pack(fill="x", padx=18, pady=(0, 10))
        tk.Label(owner_row, text="OWNER USB MODE", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        self.owner_enable_button = tk.Button(owner_row, text="REQUIRE THIS USB", command=self.enable_owner_usb_mode, bg=GREEN, fg=BLACK, relief="flat", font=("Segoe UI", 8, "bold"))
        self.owner_enable_button.pack(side="left", padx=(10, 0), ipadx=10, ipady=6)
        self.owner_disable_button = tk.Button(owner_row, text="TURN OFF USB REQUIREMENT", command=self.disable_owner_usb_mode, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 8, "bold"))
        self.owner_disable_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        self.owner_verify_button = tk.Button(owner_row, text="VERIFY OWNER USB", command=self.verify_owner_usb_now, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 8, "bold"))
        self.owner_verify_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        self.support_button = tk.Button(owner_row, text="BUG CENTER", command=self.open_support_center, bg="#58b7e8", fg=BLACK, relief="flat", font=("Segoe UI", 8, "bold"))
        self.support_button.pack(side="right", ipadx=10, ipady=6)
        self.news_button = tk.Button(owner_row, text="OWNER NEWS", command=self.open_owner_news, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 8, "bold"))
        self.news_button.pack(side="right", padx=(0, 8), ipadx=10, ipady=6)
        self.shop_button = tk.Button(owner_row, text="SHOP", command=self.open_shop, bg=GREEN, fg=BLACK, relief="flat", font=("Segoe UI", 8, "bold"))
        self.shop_button.pack(side="right", padx=(0, 8), ipadx=10, ipady=6)

        customer_row = tk.Frame(panel, bg=PANEL)
        customer_row.pack(fill="x", padx=18, pady=(0, 10))
        tk.Label(customer_row, text="CUSTOMER SELF-SERVICE", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        self.customer_button = tk.Button(customer_row, text="CUSTOMER CENTER", command=self.open_customer_center, bg=GREEN, fg=BLACK, relief="flat", font=("Segoe UI", 8, "bold"))
        self.customer_button.pack(side="left", padx=(10, 0), ipadx=10, ipady=6)
        self.customer_workspace_button = tk.Button(customer_row, text="CUSTOMER WORKSPACE", command=self.open_customer_workspace, bg=BLUE, fg=BLACK, relief="flat", font=("Segoe UI", 8, "bold"))
        self.customer_workspace_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        self.trust_center_button = tk.Button(customer_row, text="TRUST & RECOVERY", command=self.open_trust_recovery_center, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 8, "bold"))
        self.trust_center_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        self.customer_status_button = tk.Button(customer_row, text="PUBLIC STATUS", command=self.open_customer_status, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 8, "bold"))
        self.customer_status_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        self.readiness_button = tk.Button(customer_row, text="RECOVERY READINESS", command=self.open_recovery_readiness, bg=YELLOW, fg=BLACK, relief="flat", font=("Segoe UI", 8, "bold"))
        self.readiness_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)

        local_control_row = tk.Frame(panel, bg=PANEL)
        local_control_row.pack(fill="x", padx=18, pady=(0, 10))
        tk.Label(local_control_row, text="LOCAL CUSTOMER TOOLS", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        self.local_control_button = tk.Button(local_control_row, text="LOCAL CONTROL CENTER", command=self.open_local_control_center, bg=BLUE, fg=BLACK, relief="flat", font=("Segoe UI", 8, "bold"))
        self.local_control_button.pack(side="left", padx=(10, 0), ipadx=10, ipady=6)
        self.diagnostics_button = tk.Button(local_control_row, text="DIAGNOSTICS CENTER", command=self.open_diagnostics_center, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 8, "bold"))
        self.diagnostics_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        self.incident_button = tk.Button(local_control_row, text="INCIDENT RESPONSE", command=self.open_incident_response_center, bg=YELLOW, fg=BLACK, relief="flat", font=("Segoe UI", 8, "bold"))
        self.incident_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        self.recovery_drill_button = tk.Button(local_control_row, text="RECOVERY DRILLS", command=self.open_recovery_drill_center, bg=GREEN, fg=BLACK, relief="flat", font=("Segoe UI", 8, "bold"))
        self.recovery_drill_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        tk.Label(
            panel,
            text="Read-only checks, recovery drills, and fixed response playbooks stay local. Local Control listens only on 127.0.0.1.",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 8),
            wraplength=820,
            justify="left",
        ).pack(anchor="w", padx=18, pady=(0, 10))

        storage_row = tk.Frame(panel, bg=PANEL)
        storage_row.pack(fill="x", padx=18, pady=(0, 10))
        tk.Label(storage_row, text="DATA AND BACKUPS", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        self.recent_keys_button = tk.Button(storage_row, text="RECENT KEYS", command=self.open_recent_keys, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 8, "bold"))
        self.recent_keys_button.pack(side="left", padx=(10, 0), ipadx=10, ipady=6)
        self.open_data_button = tk.Button(storage_row, text="OPEN DATA FOLDER", command=self.open_data_folder, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 8, "bold"))
        self.open_data_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        self.backup_data_button = tk.Button(storage_row, text="BACK UP APP DATA", command=self.backup_app_data, bg=YELLOW, fg=BLACK, relief="flat", font=("Segoe UI", 8, "bold"))
        self.backup_data_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        self.restore_data_button = tk.Button(storage_row, text="RESTORE APP DATA", command=self.restore_app_data, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 8, "bold"))
        self.restore_data_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        self.update_button = tk.Button(storage_row, text="UPDATE CENTER", command=self.open_update_center, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 8, "bold"))
        self.update_button.pack(side="right", ipadx=10, ipady=6)

        pin_row = tk.Frame(panel, bg=PANEL)
        pin_row.pack(fill="x", padx=18, pady=(2, 12))
        tk.Label(pin_row, text="EXTRA PIN OPTIONAL, NOT SAVED", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        self.pin_entry = tk.Entry(pin_row, show="*", width=18, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 11))
        self.pin_entry.pack(side="left", padx=(12, 0), ipady=6)
        self.pin_entry.bind("<KeyRelease>", self.update_pin_mode)
        tk.Checkbutton(
            pin_row,
            text="SHOW PIN",
            variable=self.pin_visible,
            command=self.toggle_pin_visibility,
            bg=PANEL,
            fg=TEXT,
            selectcolor=FIELD,
            activebackground=PANEL,
            activeforeground=TEXT,
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", padx=(10, 0))
        tk.Label(pin_row, textvariable=self.pin_mode, bg=PANEL, fg=GREEN, font=("Segoe UI", 8, "bold")).pack(side="left", padx=(12, 0))
        tk.Label(pin_row, text="Exact and case-sensitive.", bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(side="left", padx=(10, 0))

        files_row = tk.Frame(panel, bg=PANEL)
        files_row.pack(fill="x", padx=18, pady=(4, 6))
        tk.Label(files_row, text="FILES AND FOLDERS", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        self.add_files_button = tk.Button(files_row, text="ADD FILES", command=self.add_files, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.add_files_button.pack(side="right", ipadx=10, ipady=6)
        self.add_folder_button = tk.Button(files_row, text="ADD FOLDER", command=self.add_folder, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.add_folder_button.pack(side="right", padx=(0, 8), ipadx=10, ipady=6)
        self.add_perm_unlock_items_button = tk.Button(files_row, text="ADD PERM UNLOCK ITEMS", command=self.add_perm_unlock_items, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.add_perm_unlock_items_button.pack(side="right", padx=(0, 8), ipadx=10, ipady=6)
        self.remove_selected_button = tk.Button(files_row, text="REMOVE SELECTED", command=self.remove_selected_files, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.remove_selected_button.pack(side="right", padx=(0, 8), ipadx=10, ipady=6)
        self.clear_files_button = tk.Button(files_row, text="CLEAR", command=self.clear_files, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.clear_files_button.pack(side="right", padx=(0, 8), ipadx=10, ipady=6)

        queue_row = tk.Frame(panel, bg=PANEL)
        queue_row.pack(fill="x", padx=18, pady=(0, 6))
        tk.Label(queue_row, text="QUEUE TOOLS", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        self.open_selected_button = tk.Button(queue_row, text="OPEN SELECTED", command=self.open_selected_items, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.open_selected_button.pack(side="left", padx=(10, 0), ipadx=10, ipady=6)
        self.open_selected_folder_button = tk.Button(queue_row, text="OPEN FOLDER", command=self.open_selected_item_folders, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.open_selected_folder_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        self.remove_missing_button = tk.Button(queue_row, text="REMOVE MISSING", command=self.remove_missing_files, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.remove_missing_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        self.sort_list_button = tk.Button(queue_row, text="SORT LIST", command=self.sort_file_list, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.sort_list_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        self.save_list_button = tk.Button(queue_row, text="SAVE LIST", command=self.save_file_list, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.save_list_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        self.load_list_button = tk.Button(queue_row, text="LOAD LIST", command=self.load_file_list, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.load_list_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)

        tools_row = tk.Frame(panel, bg=PANEL)
        tools_row.pack(fill="x", padx=18, pady=(0, 6))
        self.find_locked_button = tk.Button(tools_row, text="FIND LOCKED", command=self.find_locked_files_gui, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.find_locked_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        self.scan_personal_button = tk.Button(tools_row, text="SCAN PERSONAL FILES", command=self.scan_personal_files, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.scan_personal_button.pack(side="left", ipadx=10, ipady=6)
        self.check_format_button = tk.Button(tools_row, text="CHECK LOCK FORMAT", command=self.check_locked_compatibility, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.check_format_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        self.upgrade_button = tk.Button(tools_row, text="UPGRADE OLD LOCKS", command=self.upgrade_legacy_selected, bg=YELLOW, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold"))
        self.upgrade_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=6)

        self.file_list = tk.Listbox(
            panel,
            height=8,
            bg=FIELD,
            fg=TEXT,
            selectbackground=GREEN,
            selectforeground=BLACK,
            highlightthickness=1,
            highlightcolor="#343946",
            highlightbackground="#343946",
            bd=0,
            font=("Segoe UI", 10),
        )
        self.file_list.pack(fill="both", expand=True, padx=18)

        action_row = tk.Frame(panel, bg=PANEL)
        action_row.pack(fill="x", padx=18, pady=(14, 8))
        self.lock_button = tk.Button(action_row, text="LOCK COPY", command=self.lock_selected, bg=GREEN, fg=BLACK, relief="flat", font=("Segoe UI", 10, "bold"))
        self.lock_button.pack(side="left", ipadx=18, ipady=10)
        self.lock_remove_button = tk.Button(
            action_row,
            text="LOCK + REMOVE ORIGINAL",
            command=self.lock_and_remove_selected,
            bg=YELLOW,
            fg=BLACK,
            relief="flat",
            font=("Segoe UI", 10, "bold"),
        )
        self.lock_remove_button.pack(side="left", padx=(12, 0), ipadx=14, ipady=10)
        self.unlock_button = tk.Button(action_row, text="UNLOCK HERE", command=self.unlock_selected, bg=WHITE, fg=BLACK, relief="flat", font=("Segoe UI", 10, "bold"))
        self.unlock_button.pack(side="left", padx=(12, 0), ipadx=18, ipady=10)
        self.perm_unlock_button = tk.Button(action_row, text="PERM UNLOCK", command=self.perm_unlock_selected, bg=YELLOW, fg=BLACK, relief="flat", font=("Segoe UI", 10, "bold"))
        self.perm_unlock_button.pack(side="left", padx=(12, 0), ipadx=18, ipady=10)
        self.busy_buttons = [self.lock_button, self.lock_remove_button, self.unlock_button, self.perm_unlock_button]

        secondary_row = tk.Frame(panel, bg=PANEL)
        secondary_row.pack(fill="x", padx=18, pady=(0, 8))
        self.unlock_to_folder_button = tk.Button(secondary_row, text="UNLOCK TO FOLDER", command=self.unlock_selected_to_folder, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 10, "bold"))
        self.unlock_to_folder_button.pack(side="left", ipadx=14, ipady=8)
        self.perm_unlock_folder_button = tk.Button(secondary_row, text="PERM UNLOCK FOLDER", command=self.perm_unlock_selected_to_perm_folder, bg=YELLOW, fg=BLACK, relief="flat", font=("Segoe UI", 10, "bold"))
        self.perm_unlock_folder_button.pack(side="left", padx=(10, 0), ipadx=14, ipady=8)
        self.lock_note_button = tk.Button(secondary_row, text="LOCK A TEXT NOTE", command=self.lock_text_note, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 10, "bold"))
        self.lock_note_button.pack(side="left", padx=(10, 0), ipadx=14, ipady=8)
        self.personal_vault_button = tk.Button(secondary_row, text="PERSONAL VAULT", command=self.open_personal_vault, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 10, "bold"))
        self.personal_vault_button.pack(side="left", padx=(10, 0), ipadx=14, ipady=8)

        progress_row = tk.Frame(panel, bg=PANEL)
        progress_row.pack(fill="x", padx=18, pady=(2, 8))
        ttk.Progressbar(progress_row, variable=self.progress_value, maximum=100).pack(side="left", fill="x", expand=True)
        tk.Label(progress_row, textvariable=self.progress_text, bg=PANEL, fg=MUTED, font=("Segoe UI", 8)).pack(side="left", padx=(10, 0))
        self.cancel_button = tk.Button(
            progress_row,
            text="CANCEL AFTER CURRENT",
            command=self.cancel_current_job,
            state="disabled",
            bg="#252936",
            fg=TEXT,
            disabledforeground=MUTED,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        )
        self.cancel_button.pack(side="right", padx=(10, 0), ipadx=8, ipady=4)

        tk.Label(panel, text="New locks are portable between Windows PCs. LOCK + REMOVE ORIGINAL verifies before deleting.", bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", padx=18)
        tk.Label(outer, textvariable=self.status, bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(10, 0))
        self.key_required_buttons = [
            self.recovery_button,
            self.add_files_button,
            self.add_folder_button,
            self.clear_files_button,
            self.find_locked_button,
            self.scan_personal_button,
            self.check_format_button,
            self.upgrade_button,
            self.lock_button,
            self.lock_remove_button,
            self.unlock_button,
            self.perm_unlock_button,
            self.unlock_to_folder_button,
            self.perm_unlock_folder_button,
            self.lock_note_button,
            self.personal_vault_button,
        ]
        self.license_gated_buttons = {
            self.recovery_drill_button: "recovery-drill-center",
            self.incident_button: "incident-response-center",
            self.diagnostics_button: "diagnostics-center",
            self.apps_hub_button: "privacy-safety-hub",
            self.breach_button: "global-breach-guard",
            self.global_guard_button: "global-breach-guard",
            self.owner_enable_button: "owner-usb-mode",
            self.owner_disable_button: "owner-usb-mode",
            self.owner_verify_button: "owner-usb-mode",
            self.scan_personal_button: "portable-locking",
            self.lock_button: "portable-locking",
            self.lock_remove_button: "portable-locking",
            self.lock_note_button: "quick-lock-note",
            self.add_perm_unlock_items_button: "perm-unlock",
            self.perm_unlock_button: "perm-unlock",
            self.perm_unlock_folder_button: "perm-unlock",
            self.personal_vault_button: "personal-vault",
        }

    def toggle_pin_visibility(self):
        self.pin_entry.configure(show="" if self.pin_visible.get() else "*")

    def periodic_cloud_audit_upload(self):
        if self.winfo_exists():
            self.after(15 * 60 * 1000, self.periodic_cloud_audit_upload)
        settings = load_settings()
        if not settings.get("cloud_audit_enabled") or self.cloud_audit_in_progress:
            return
        state = load_license_state(settings)
        if not license_is_active(state) or not license_feature_allowed("audit-log-viewer", state=state):
            return
        self.cloud_audit_in_progress = True

        def worker():
            try:
                report = build_audit_report()
                fingerprint = audit_report_snapshot_fingerprint(report)
                if fingerprint == str(settings.get("last_cloud_audit_fingerprint", "")):
                    self.cloud_audit_results.put(("skip", None, fingerprint, ""))
                    return
                response = upload_audit_report_online(state, report=report)
                self.cloud_audit_results.put(("success", response, fingerprint, ""))
            except Exception as exc:
                self.cloud_audit_results.put(("error", None, "", str(exc)))

        threading.Thread(target=worker, name="VaultLinkCloudAuditUpload", daemon=True).start()
        self.after(75, self.poll_cloud_audit_results)

    def poll_cloud_audit_results(self):
        try:
            outcome, response, fingerprint, error = self.cloud_audit_results.get_nowait()
        except queue.Empty:
            if self.cloud_audit_in_progress and self.winfo_exists():
                self.after(75, self.poll_cloud_audit_results)
            return
        self.cloud_audit_in_progress = False
        if outcome == "skip":
            return
        if outcome == "error":
            self.status.set(f"Automatic API audit upload failed: {error}")
            return
        settings = load_settings()
        settings["last_cloud_audit_fingerprint"] = fingerprint
        settings["last_cloud_audit_export_id"] = str((response or {}).get("export_id", ""))
        settings["last_cloud_audit_utc"] = utc_now_text()
        save_settings(settings)
        event_count = int((response or {}).get("event_count", 0) or 0)
        breach_level = str(((response or {}).get("breach_summary") or {}).get("level", "unknown"))
        log_event("audit_api_auto_upload", "api", "ok", f"events={event_count};level={breach_level}")
        self.status.set(
            f"Automatic privacy-safe API audit uploaded: {event_count} event(s), breach level {breach_level.upper()}."
        )

    def set_auto_update_check(self, enabled):
        if LAB_MODE:
            self.status.set("Automatic update checks stay disabled in OWNER LAB mode.")
            return
        self.settings["auto_update_check"] = bool(enabled)
        save_settings(self.settings)
        self.status.set("Automatic daily update checks enabled." if enabled else "Automatic update checks turned off.")

    def set_auto_install_updates(self, enabled):
        if LAB_MODE:
            self.status.set("Update installation stays disabled in OWNER LAB mode.")
            if self.update_window is not None:
                self.update_window.auto_install_var.set(False)
            return
        self.settings["auto_install_signed_updates"] = bool(enabled)
        if enabled:
            self.settings["auto_update_check"] = True
        save_settings(self.settings)
        self.status.set(
            "Verified updates will install automatically after a successful signature and hash check."
            if enabled
            else "Automatic update installation turned off."
        )
        log_event("auto_update_setting", "local", "ok", f"enabled={int(bool(enabled))}")

    def auto_check_for_updates(self):
        if LAB_MODE:
            return
        if not self.settings.get("auto_update_check", True):
            return
        last_check = parse_utc_text(self.settings.get("last_update_check_utc"))
        if last_check and (datetime.now(timezone.utc) - last_check).total_seconds() < 20 * 60 * 60:
            return
        self.start_update_check(silent=True)

    def open_update_center(self):
        if self.update_window is not None:
            try:
                if self.update_window.winfo_exists():
                    self.update_window.lift()
                    self.update_window.focus_set()
                    return self.update_window
            except tk.TclError:
                pass
        self.update_window = UpdateCenterWindow(self)
        self.register_secondary_window(self.update_window)
        if self.latest_update_manifest is None and not self.update_operation:
            self.start_update_check(silent=False)
        return self.update_window

    def open_customer_status(self):
        try:
            state = load_license_state(load_settings())
            server = validated_license_server_url(state.get("server_url") or DEFAULT_LICENSE_SERVER)
            os.startfile(server + "/status")
            self.status.set("Opened the public VaultLink customer status page.")
            log_event("customer_status_open", "api", "ok")
        except Exception as exc:
            self.status.set("Could not open the customer status page.")
            log_event("customer_status_open", "api", "failed")
            messagebox.showerror("Could not open Customer Status", str(exc), parent=self)

    def open_web_update_center(self):
        try:
            state = load_license_state(load_settings())
            server = validated_license_server_url(state.get("server_url") or DEFAULT_LICENSE_SERVER)
            os.startfile(server + "/update")
            self.status.set("Opened the online VaultLink Update Center.")
            log_event("web_update_center_open", "api", "ok")
        except Exception as exc:
            self.status.set("Could not open the online Update Center.")
            log_event("web_update_center_open", "api", "failed")
            messagebox.showerror("Could not open Update Center", str(exc), parent=self)

    def open_recovery_readiness(self):
        try:
            state = load_license_state(load_settings())
            server = validated_license_server_url(state.get("server_url") or DEFAULT_LICENSE_SERVER)
            os.startfile(server + "/readiness")
            self.status.set("Opened VaultLink Recovery Readiness.")
            log_event("recovery_readiness_open", "api", "ok")
        except Exception as exc:
            self.status.set("Could not open Recovery Readiness.")
            log_event("recovery_readiness_open", "api", "failed")
            messagebox.showerror("Could not open Recovery Readiness", str(exc), parent=self)

    def open_update_backups(self):
        try:
            backup_dir = APP_DIR / "update_backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            os.startfile(backup_dir)
            self.status.set("Opened the local signed-update backup folder.")
            log_event("update_backups_open", "release", "ok")
        except Exception as exc:
            self.status.set("Could not open the update backup folder.")
            log_event("update_backups_open", "release", "failed")
            messagebox.showerror("Could not open update backups", str(exc), parent=self)

    def refresh_update_window(self, error=""):
        if self.update_window is None:
            return
        try:
            if self.update_window.winfo_exists():
                self.update_window.show_manifest(self.latest_update_manifest, error=error)
        except tk.TclError:
            pass

    def start_update_check(self, silent=False):
        if self.update_operation:
            return
        try:
            state = load_license_state(load_settings())
            server = validated_license_server_url(state.get("server_url") or DEFAULT_LICENSE_SERVER)
        except Exception as exc:
            if not silent:
                messagebox.showerror("Update check failed", str(exc), parent=self)
            return
        self.update_operation = "check"
        if self.update_button is not None:
            self.update_button.configure(state="disabled", text="CHECKING...")
        self.refresh_update_window()
        if self.update_window is not None and self.update_window.winfo_exists():
            self.update_window.status_var.set("Checking the API for a signed Windows release...")

        def worker():
            try:
                manifest = check_windows_update_online(server)
                error = ""
            except Exception as exc:
                manifest = None
                error = str(exc)
            self.update_results.put(("check", manifest, error, bool(silent)))

        threading.Thread(target=worker, name="VaultLinkUpdateCheck", daemon=True).start()
        self.after(75, self.poll_update_results)

    def poll_update_results(self):
        try:
            operation, payload, error, silent = self.update_results.get_nowait()
        except queue.Empty:
            if self.update_operation and self.winfo_exists():
                self.after(75, self.poll_update_results)
            return
        self.update_operation = ""
        if operation == "check":
            if error:
                if self.update_button is not None:
                    self.update_button.configure(state="normal", text="UPDATE CENTER", bg="#252936", fg=TEXT)
                self.refresh_update_window(error=error)
                if not silent:
                    messagebox.showerror("Update check failed", error, parent=self)
                return
            self.latest_update_manifest = payload
            self.settings["last_update_check_utc"] = utc_now_text()
            available = bool(payload.get("update_available"))
            update_required = available and not bool(payload.get("current_version_supported"))
            if update_required:
                self.update_button.configure(state="normal", text="UPDATE REQUIRED", bg=RED, fg=WHITE)
            elif available:
                self.update_button.configure(state="normal", text="UPDATE AVAILABLE", bg=GREEN, fg=BLACK)
            else:
                self.update_button.configure(state="normal", text="UPDATE CENTER", bg="#252936", fg=TEXT)
            self.refresh_update_window()
            save_settings(self.settings)
            if available and silent:
                version = str(payload.get("version", ""))
                if self.settings.get("auto_install_signed_updates", False):
                    self.status.set(f"Verified update {version} found. Preparing automatic installation...")
                    log_event("application_auto_update", "api", "ok", f"verified={version}")
                    self.install_latest_update(automatic=True)
                    return
                if self.settings.get("last_update_notice_version") != version:
                    self.settings["last_update_notice_version"] = version
                    save_settings(self.settings)
                    open_center = messagebox.askyesno(
                        "Verified update required" if update_required else "Verified update available",
                        (
                            f"VaultLink {version} is required because this desktop build is below the supported floor."
                            if update_required
                            else f"VaultLink {version} is available and its release signature verified."
                        ) + "\n\nOpen Update Center?",
                        parent=self,
                    )
                    if open_center:
                        self.open_update_center()
            return
        if operation == "copy":
            if error:
                if self.update_button is not None:
                    self.update_button.configure(state="normal", text="UPDATE CENTER", bg="#252936", fg=TEXT)
                self.refresh_update_window(error=error)
                messagebox.showerror("Verified download failed", error, parent=self)
                return
            self.update_button.configure(state="normal", text="UPDATE CENTER", bg="#252936", fg=TEXT)
            self.refresh_update_window()
            log_event("update_package_copy", "release", "ok")
            self.status.set("Saved a separately verified copy of the signed update package.")
            messagebox.showinfo("Verified copy saved", f"Saved and verified:\n{payload}", parent=self)
            return
        if operation == "stage":
            if error:
                self.update_button.configure(state="normal", text="UPDATE AVAILABLE", bg=GREEN, fg=BLACK)
                self.refresh_update_window(error=error)
                if silent:
                    self.status.set(f"Automatic update could not be installed: {error}")
                    log_event("application_auto_update", "api", "failed")
                else:
                    messagebox.showerror("Update download failed", error, parent=self)
                return
            stage_dir, manifest_path, package_path = payload
            try:
                launch_staged_windows_update(
                    stage_dir,
                    manifest_path,
                    package_path,
                    parent_pid=os.getpid(),
                )
                version = str((self.latest_update_manifest or {}).get("version", "unknown"))
                log_event("application_update", "api", "ok", f"version={version}")
                self.status.set(f"Verified update {version} staged. Closing for installation...")
                self.after(350, self.destroy)
            except Exception as exc:
                self.update_button.configure(state="normal", text="UPDATE AVAILABLE", bg=GREEN, fg=BLACK)
                self.refresh_update_window(error=str(exc))
                messagebox.showerror("Could not start updater", str(exc), parent=self)

    def install_latest_update(self, automatic=False):
        if LAB_MODE:
            self.status.set("Update installation is disabled in OWNER LAB mode. Build or publish from Owner Update Lab instead.")
            if not automatic:
                messagebox.showinfo(
                    "Lab mode protection",
                    "Update installation is disabled in OWNER LAB mode. The stable app remains untouched.",
                    parent=self,
                )
            return
        manifest = self.latest_update_manifest
        if not manifest or not manifest.get("update_available"):
            messagebox.showinfo("No update ready", "Check for an update first.", parent=self)
            return
        if self.update_operation:
            return
        if (RUNTIME_DIR / ".git").exists():
            if automatic:
                self.status.set("A verified update is available, but Git working folders must be updated with git pull.")
            else:
                messagebox.showinfo(
                    "Git folder detected",
                    "Automatic installation is disabled in a Git working folder. Use git pull, or run the clean release folder.",
                    parent=self,
                )
            return
        version = str(manifest.get("version", "unknown"))
        size_mb = int(manifest.get("size_bytes", 0)) / (1024 * 1024)
        confirmed = automatic or messagebox.askyesno(
            "Install verified update",
            f"Install VaultLink {version} ({size_mb:.1f} MB)?\n\n"
            "The Ed25519 signature and SHA-256 package hash will be checked again. "
            "Current app files are backed up, and LocalAppData is not replaced.",
            parent=self,
        )
        if not confirmed:
            return
        state = load_license_state(load_settings())
        server = validated_license_server_url(state.get("server_url") or DEFAULT_LICENSE_SERVER)
        self.update_operation = "stage"
        self.update_button.configure(state="disabled", text="DOWNLOADING...")
        self.refresh_update_window()
        if self.update_window is not None and self.update_window.winfo_exists():
            self.update_window.status_var.set("Downloading and verifying the signed update package...")

        def worker():
            try:
                staged = stage_windows_update(server, manifest)
                error = ""
            except Exception as exc:
                staged = None
                error = str(exc)
            self.update_results.put(("stage", staged, error, bool(automatic)))

        threading.Thread(target=worker, name="VaultLinkUpdateDownload", daemon=True).start()
        self.after(75, self.poll_update_results)

    def download_latest_update_copy(self):
        manifest = self.latest_update_manifest
        if not manifest:
            messagebox.showinfo("No release loaded", "Check for a signed update first.", parent=self)
            return
        if self.update_operation:
            return
        target = filedialog.asksaveasfilename(
            title="Save verified signed update package",
            defaultextension=".zip",
            initialfile=str(manifest.get("package_filename", "VaultLink-Windows.zip")),
            filetypes=[("ZIP package", "*.zip")],
        )
        if not target:
            return
        try:
            state = load_license_state(load_settings())
            server = validated_license_server_url(state.get("server_url") or DEFAULT_LICENSE_SERVER)
        except Exception as exc:
            messagebox.showerror("Verified download unavailable", str(exc), parent=self)
            return
        self.update_operation = "copy"
        if self.update_button is not None:
            self.update_button.configure(state="disabled", text="DOWNLOADING...")
        self.refresh_update_window()

        def worker():
            try:
                saved = download_windows_update_package(server, manifest, Path(target))
                error = ""
            except Exception as exc:
                saved = None
                error = str(exc)
            self.update_results.put(("copy", saved, error, False))

        threading.Thread(target=worker, name="VaultLinkVerifiedUpdateCopy", daemon=True).start()
        self.after(75, self.poll_update_results)

    def update_pin_mode(self, _event=None):
        if self.pin_entry.get():
            self.pin_mode.set("USB KEY + PIN ACTIVE")
        else:
            self.pin_mode.set("USB KEY ONLY")

    def register_secondary_window(self, window):
        self.secondary_windows.append(window)
        window.bind("<Destroy>", lambda _event, win=window: self.secondary_windows.remove(win) if win in self.secondary_windows else None, add="+")

    def active_key_matches_owner_policy(self):
        if not self.key:
            return False
        allowed, _message = owner_key_allowed(self.key, self.owner_policy)
        return allowed

    def update_license_state_ui(self, state=None, save=False):
        if state is None:
            self.license_state = load_license_state(self.settings)
        else:
            self.license_state = normalize_license_state(state)
            if save:
                self.license_state = save_license_state(self.settings, self.license_state)
        self.license_status.set(license_status_text(self.license_state))
        status = self.license_state.get("status", "unlicensed")
        color = GREEN if license_is_active(self.license_state) else (RED if status == "revoked" else YELLOW)
        if getattr(self, "license_status_label", None):
            self.license_status_label.configure(fg=color)
        return self.license_state

    def apply_access_state(self):
        locked = not self.active_key_matches_owner_policy()
        if self.owner_policy:
            self.access_status.set(f"Owner USB required: {owner_policy_description(self.owner_policy)}")
        else:
            self.access_status.set("Standard mode: load or create a master key, then lock, unlock, or use the vault.")
        if self.owner_policy and self.active_key_matches_owner_policy():
            self.key_status.set(f"OWNER USB VERIFIED - ID {self.key['key_id']}")
        elif self.owner_policy:
            self.key_status.set("OWNER USB REQUIRED - load the registered USB key")
        elif self.key:
            self.key_status.set(f"UNLOCKED WITH USB KEY - ID {self.key['key_id']}")
        else:
            self.key_status.set("LOCKED - load your master USB key")
        for button in self.key_required_buttons:
            button.configure(state="disabled" if locked else "normal")
        self.create_key_button.configure(state="disabled" if self.owner_policy else "normal")
        self.owner_enable_button.configure(state="normal" if self.key else "disabled")
        disable_owner_off = not self.owner_policy or not self.active_key_matches_owner_policy()
        self.owner_disable_button.configure(state="disabled" if disable_owner_off else "normal")
        self.owner_verify_button.configure(state="normal" if self.owner_policy else "disabled")
        for button, feature_id in self.license_gated_buttons.items():
            allowed = license_feature_allowed(feature_id, state=self.license_state)
            if not allowed:
                button.configure(state="disabled")
            elif (
                button not in self.key_required_buttons
                and button not in {
                    self.owner_enable_button,
                    self.owner_disable_button,
                    self.owner_verify_button,
                }
            ):
                button.configure(state="normal")
        if getattr(self, "busy", False):
            for button in self.busy_buttons:
                button.configure(state="disabled")
        owner_update_button = getattr(self, "owner_update_button", None)
        if owner_update_button is not None:
            owner_release_ready = bool(
                self.settings.get("owner_usb_policy")
                and self.owner_policy
                and self.active_key_matches_owner_policy()
            )
            owner_update_button.configure(state="normal" if owner_release_ready else "disabled")

    def unload_session(self, reason, action_name, result):
        previous_key = self.key["key_id"] if self.key else ""
        self.key = None
        try:
            self.pin_entry.delete(0, "end")
        except Exception:
            pass
        self.update_pin_mode()
        for window in list(self.secondary_windows):
            try:
                if window.winfo_exists():
                    window.destroy()
            except Exception:
                pass
        self.apply_access_state()
        self.status.set(reason)
        log_event(action_name, previous_key or "loaded_key", result)

    def clear_loaded_key(self, reason, log_name="usb_key_removed"):
        self.unload_session(reason, log_name, "failed")

    def panic_lock_now(self):
        if self.busy:
            messagebox.showinfo(
                "Job running",
                "A lock or unlock job is still running.\n\n"
                "Click CANCEL AFTER CURRENT first, wait for it to stop, then use PANIC LOCK NOW again.",
            )
            self.status.set("Could not panic-lock while a job is running.")
            return
        has_open_window = any(
            getattr(window, "winfo_exists", lambda: False)()
            for window in list(self.secondary_windows)
        )
        if not self.key and not self.pin_entry.get() and not has_open_window:
            self.status.set("App already locked.")
            return
        self.unload_session(
            "Panic lock complete. USB key unloaded, PIN cleared, and extra windows closed.",
            "panic_lock",
            "ok",
        )
        try:
            self.iconify()
        except Exception:
            pass
        messagebox.showinfo(
            "Panic lock complete",
            "The loaded USB key was unloaded, the PIN box was cleared, and extra windows were closed.",
        )

    def open_apps_hub(self):
        if not ensure_license_feature("privacy-safety-hub", parent=self):
            self.status.set("Apps Hub needs an active Pro license.")
            return
        try:
            launch_companion_script("privacy_safety_hub.py")
            self.status.set("Opened Apps Hub.")
        except Exception as exc:
            self.status.set("Could not open Apps Hub.")
            messagebox.showerror("Could not open Apps Hub", str(exc))

    def open_owner_update_lab(self):
        if not self.settings.get("owner_usb_policy") or not self.owner_policy:
            messagebox.showerror("Owner mode required", "Enable owner USB mode before opening the Update Lab.", parent=self)
            return
        if not self.active_key_matches_owner_policy() or not self.key:
            messagebox.showerror("Owner USB required", "Load the registered owner USB before opening the Update Lab.", parent=self)
            return
        try:
            fresh_key = load_key_file(self.key["path"])
            allowed, reason = owner_key_allowed(fresh_key, self.owner_policy)
            if not allowed:
                raise ValueError(reason)
            origin = fresh_key.get("origin") or {}
            if origin.get("drive_type") != DRIVE_REMOVABLE:
                raise ValueError("The registered owner USB must currently be a removable drive.")
            launch_companion_script("owner_update_lab.py", "--owner-key", fresh_key["path"])
            self.status.set("Opened the private owner Update Lab.")
            log_event("owner_update_lab_open", "local", "ok")
        except Exception as exc:
            self.status.set("Could not open the owner Update Lab.")
            log_event("owner_update_lab_open", "local", "failed")
            messagebox.showerror("Could not open Update Lab", str(exc), parent=self)

    def open_support_center(self):
        if self.support_window is not None and self.support_window.winfo_exists():
            self.support_window.lift()
            self.support_window.focus_force()
            return
        self.support_window = SupportCenterWindow(self)
        self.register_secondary_window(self.support_window)
        self.status.set("Opened Bug Center.")

    def open_customer_center(self):
        if self.customer_window is not None and self.customer_window.winfo_exists():
            self.customer_window.render_current()
            self.customer_window.lift()
            self.customer_window.focus_force()
            return
        self.customer_window = CustomerCenterWindow(self)
        self.register_secondary_window(self.customer_window)
        self.status.set("Opened Customer Center.")

    def open_customer_workspace(self):
        try:
            launch_companion_script("customer_hub.py")
            self.status.set("Opened the Customer Workspace.")
            log_event("customer_workspace_open", "api", "ok")
        except Exception as exc:
            self.status.set("Could not open the Customer Workspace.")
            log_event("customer_workspace_open", "api", "failed")
            messagebox.showerror("Could not open Customer Workspace", str(exc), parent=self)

    def open_trust_recovery_center(self):
        try:
            launch_companion_script("trust_recovery_center.py")
            self.status.set("Opened the Trust & Recovery Center.")
            log_event("trust_center_open", "local", "ok")
        except Exception as exc:
            self.status.set("Could not open the Trust & Recovery Center.")
            log_event("trust_center_open", "local", "failed")
            messagebox.showerror("Could not open Trust & Recovery Center", str(exc), parent=self)

    def open_diagnostics_center(self):
        try:
            launch_companion_script("diagnostics_center.py")
            self.status.set("Opened Diagnostics Center.")
            log_event("diagnostics_center_open", "local", "ok")
        except Exception as exc:
            self.status.set("Could not open Diagnostics Center.")
            log_event("diagnostics_center_open", "local", "failed")
            messagebox.showerror("Could not open Diagnostics Center", str(exc), parent=self)

    def open_incident_response_center(self):
        try:
            launch_companion_script("incident_response_center.py")
            self.status.set("Opened Incident Response Center.")
            log_event("incident_center_open", "local", "ok")
        except Exception as exc:
            self.status.set("Could not open Incident Response Center.")
            log_event("incident_center_open", "local", "failed")
            messagebox.showerror("Could not open Incident Response Center", str(exc), parent=self)

    def open_recovery_drill_center(self):
        try:
            launch_companion_script("recovery_drill_center.py")
            self.status.set("Opened Recovery Drill Center.")
            log_event("recovery_drill_center_open", "local_center", "ok")
        except Exception as exc:
            self.status.set("Could not open Recovery Drill Center.")
            log_event("recovery_drill_center_open", "local_center", "failed")
            messagebox.showerror("Could not open Recovery Drill Center", str(exc), parent=self)

    def open_local_control_center(self):
        try:
            launch_companion_script("local_control_center.py")
            self.status.set("Opened the same-PC Local Control Center.")
            log_event("local_control_center_open", "loopback", "ok")
        except Exception as exc:
            self.status.set("Could not open the Local Control Center.")
            log_event("local_control_center_open", "loopback", "failed")
            messagebox.showerror("Could not open Local Control Center", str(exc), parent=self)

    def open_owner_news(self):
        if self.news_window is not None and self.news_window.winfo_exists():
            self.news_window.lift()
            self.news_window.focus_force()
            return
        self.news_window = OwnerNewsWindow(self)
        self.register_secondary_window(self.news_window)
        self.status.set("Opened Owner News.")

    def show_new_owner_notices(self):
        if not license_is_active(self.license_state) and self.license_state.get("status") != "limited":
            return
        raw_seen = self.settings.get("seen_owner_announcement_ids", [])
        if not isinstance(raw_seen, list):
            raw_seen = []
        seen = {str(value) for value in raw_seen if str(value)}
        new_items = [
            item
            for item in normalize_owner_announcements(self.license_state.get("announcements"))
            if item.get("announcement_id") not in seen
        ]
        service = normalize_service_status(self.license_state.get("service_status"))
        service_id = ""
        if service["mode"] != "normal":
            service_id = f"SERVICE-{service['mode']}-{service['updated_at_utc'] or service['message']}"
            service_id = hashlib.sha256(service_id.encode("utf-8")).hexdigest()[:24]
        show_service = bool(service_id and service_id not in seen)
        if not new_items and not show_service:
            return

        blocks = []
        warning = show_service
        if show_service:
            blocks.append(f"SERVICE {service['mode'].upper()}\n{service['message']}")
            seen.add(service_id)
        for item in new_items[:5]:
            severity = str(item.get("severity", "info")).upper()
            warning = warning or severity in {"SECURITY", "MAINTENANCE"}
            blocks.append(
                f"{severity}: {item.get('title') or 'Owner announcement'}\n"
                f"{str(item.get('message', ''))[:700]}"
            )
            seen.add(str(item.get("announcement_id")))
        if len(new_items) > 5:
            blocks.append(f"Open OWNER NEWS to read {len(new_items) - 5} more message(s).")
            for item in new_items[5:]:
                seen.add(str(item.get("announcement_id")))

        self.settings["seen_owner_announcement_ids"] = list(seen)[-200:]
        save_settings(self.settings)
        text = "\n\n".join(blocks)
        self.status.set("A new VaultLink owner notice was shown on screen.")
        log_event("owner_announcement_view", "api", "ok", f"onscreen={len(new_items)};service={int(show_service)}")
        if warning:
            messagebox.showwarning("VaultLink Owner Notice", text, parent=self)
        else:
            messagebox.showinfo("VaultLink Owner Notice", text, parent=self)

    def open_shop(self):
        try:
            state = load_license_state(load_settings())
            url = shop_url_for_state(state)
            os.startfile(url)
            self.status.set("Opened the VaultLink Shop in your browser.")
            log_event("shop_open", "api", "ok")
        except Exception as exc:
            self.status.set("Could not open the VaultLink Shop.")
            log_event("shop_open", "api", "failed")
            messagebox.showerror("Could not open Shop", str(exc), parent=self)

    def schedule_license_refresh(self, delay_ms=None):
        if self.license_refresh_after_id is not None:
            try:
                self.after_cancel(self.license_refresh_after_id)
            except Exception:
                pass
        if delay_ms is None:
            delay_ms = recommended_license_refresh_seconds(self.license_state) * 1000
        self.license_refresh_after_id = self.after(max(250, int(delay_ms)), self.refresh_license_state_silent)

    def refresh_license_state_silent(self):
        self.license_refresh_after_id = None
        if self.license_refresh_in_progress:
            return
        state = load_license_state(self.settings)
        if not state.get("license_key") or not state.get("receipt"):
            self.update_license_state_ui(state)
            self.apply_access_state()
            self.schedule_license_refresh(LICENSE_BACKGROUND_REFRESH_SECONDS * 1000)
            return

        self.license_refresh_in_progress = True

        def worker():
            try:
                updated = verify_license_online(state)
            except Exception as exc:
                updated = build_license_failure_state(state, exc)
            self.license_refresh_results.put(updated)

        threading.Thread(target=worker, name="LicenseRefresh", daemon=True).start()
        self.after(50, self.poll_license_refresh)

    def poll_license_refresh(self):
        try:
            state = self.license_refresh_results.get_nowait()
        except queue.Empty:
            if self.license_refresh_in_progress and self.winfo_exists():
                self.after(50, self.poll_license_refresh)
            return
        self.license_refresh_in_progress = False
        self.finish_license_refresh(state, automatic=True)

    def finish_license_refresh(self, state, automatic=False):
        previous = normalize_license_state(self.license_state)
        self.update_license_state_ui(state, save=True)
        self.apply_access_state()
        current_status = self.license_state.get("status", "unlicensed")
        if automatic and previous.get("status") != current_status:
            if license_is_active(self.license_state):
                self.status.set("License restored by the API. Premium controls are available again.")
                log_event("license_sync", "api", "ok")
                self.last_license_notice_status = "active"
            elif current_status in {"revoked", "limited", "expired", "deactivated", "reset", "wrong_machine", "receipt_expired"}:
                reason = self.license_state.get("last_error") or f"License status changed to {current_status}."
                self.status.set(f"API license check disabled premium controls: {reason}")
                log_event("license_sync", "api", "failed")
                if self.last_license_notice_status != current_status:
                    self.last_license_notice_status = current_status
                    messagebox.showwarning(
                        "License access changed",
                        f"The API reported {current_status.replace('_', ' ')}.\n\n{reason}\n\n"
                        "Premium controls are now disabled. Unlocking existing files and recovery tools remain available.",
                        parent=self,
                    )
        if automatic and license_is_active(self.license_state):
            self.show_new_owner_notices()
        self.schedule_license_refresh()

    def open_license_center(self):
        dialog = tk.Toplevel(self)
        self.register_secondary_window(dialog)
        dialog.title("License Center")
        dialog.geometry("780x700")
        dialog.minsize(720, 650)
        dialog.configure(bg=BG)

        state = normalize_license_state(self.license_state)
        server_var = tk.StringVar(value=state.get("server_url", DEFAULT_LICENSE_SERVER))
        license_var = tk.StringVar(value=state.get("license_key", ""))
        status_var = tk.StringVar(value=license_status_text(state))
        summary_var = tk.StringVar(value=license_summary_text(state))
        features_var = tk.StringVar(value=license_feature_lines(state))
        machine_var = tk.StringVar(value=current_machine_fingerprint())

        tk.Label(dialog, text="License Center", bg=BG, fg=TEXT, font=("Segoe UI", 24, "bold")).pack(anchor="w", padx=22, pady=(20, 4))
        tk.Label(
            dialog,
            text="Activate this PC against your VaultLink API license, then the app will unlock the right tool set for the saved plan.",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 10),
            wraplength=700,
            justify="left",
        ).pack(anchor="w", padx=22, pady=(0, 16))

        panel_host = tk.Frame(dialog, bg=BG)
        panel_host.pack(fill="both", expand=True, padx=22, pady=(0, 20))
        panel_canvas = tk.Canvas(panel_host, bg=PANEL, highlightthickness=0, borderwidth=0)
        panel_scrollbar = ttk.Scrollbar(panel_host, orient="vertical", command=panel_canvas.yview)
        panel_canvas.configure(yscrollcommand=panel_scrollbar.set)
        panel_scrollbar.pack(side="right", fill="y")
        panel_canvas.pack(side="left", fill="both", expand=True)
        panel = tk.Frame(panel_canvas, bg=PANEL)
        panel_window = panel_canvas.create_window((0, 0), window=panel, anchor="nw")

        def resize_license_panel(_event=None):
            panel_canvas.configure(scrollregion=panel_canvas.bbox("all"))

        def fit_license_panel(event):
            panel_canvas.itemconfigure(panel_window, width=event.width)

        panel.bind("<Configure>", resize_license_panel)
        panel_canvas.bind("<Configure>", fit_license_panel)
        dialog.bind(
            "<MouseWheel>",
            lambda event: panel_canvas.yview_scroll(-1 if event.delta > 0 else 1, "units"),
        )

        def add_label(text, row):
            tk.Label(panel, text=text, bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).grid(row=row, column=0, sticky="w", padx=18, pady=(16 if row == 0 else 12, 4))

        add_label("LICENSE API URL", 0)
        server_entry = tk.Entry(panel, textvariable=server_var, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 10))
        server_entry.grid(row=1, column=0, sticky="ew", padx=18, ipady=7)

        add_label("LICENSE KEY", 2)
        license_entry = tk.Entry(panel, textvariable=license_var, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Consolas", 10))
        license_entry.grid(row=3, column=0, sticky="ew", padx=18, ipady=7)

        add_label("THIS PC", 4)
        tk.Entry(panel, textvariable=machine_var, state="readonly", readonlybackground=FIELD, fg=TEXT, relief="flat", font=("Consolas", 10)).grid(row=5, column=0, sticky="ew", padx=18, ipady=7)

        action_row = tk.Frame(panel, bg=PANEL)
        action_row.grid(row=6, column=0, sticky="ew", padx=18, pady=(16, 0))
        request_results = queue.Queue()
        request_busy = False
        request_buttons = {}

        def refresh_dialog(new_state=None):
            current = normalize_license_state(new_state if new_state is not None else self.license_state)
            status_var.set(license_status_text(current))
            summary_var.set(license_summary_text(current))
            features_var.set(license_feature_lines(current))
            if new_state is not None:
                server_var.set(current.get("server_url", DEFAULT_LICENSE_SERVER))
                license_var.set(current.get("license_key", ""))

        def persist_and_refresh(new_state):
            self.finish_license_refresh(new_state)
            refresh_dialog(self.license_state)

        def collect_state():
            fresh = license_state_with_key(
                self.license_state,
                license_var.get(),
                server_var.get(),
            )
            fresh["machine_id"] = current_machine_fingerprint()
            fresh["machine_name"] = current_machine_name()
            return fresh

        def set_request_busy(busy, mode=""):
            nonlocal request_busy
            request_busy = busy
            for button in request_buttons.values():
                button.configure(state="disabled" if busy else "normal")
            if busy:
                verb = {
                    "activate": "Activating",
                    "verify": "Verifying",
                    "deactivate": "Removing",
                }.get(mode, "Checking")
                status_var.set(f"{verb} license with the API...")

        def finish_license_request(mode, source_state, updated, error):
            set_request_busy(False)
            if error is not None:
                failed = build_license_failure_state(source_state, error)
                persist_and_refresh(failed)
                if mode == "deactivation":
                    log_event("license_deactivate", "api", "failed")
                self.status.set(f"License {mode} failed.")
                messagebox.showerror(f"License {mode} failed", str(error), parent=dialog)
                return
            if mode == "deactivation":
                cleared = clear_license_state(self.settings, source_state.get("server_url"))
                self.license_state = cleared
                self.license_status.set(license_status_text(cleared))
                self.apply_access_state()
                refresh_dialog(cleared)
                log_event("license_deactivate", "api", "ok")
                self.status.set("License activation removed from this PC through the API.")
                messagebox.showinfo(
                    "License removed from this PC",
                    "The API deactivated this receipt and the saved key was removed from this PC. The owner can still revoke the whole license separately.",
                    parent=dialog,
                )
                return
            persist_and_refresh(updated)
            if license_is_active(updated):
                if mode == "activation":
                    self.status.set(f"License activated for {updated.get('plan_name') or updated.get('plan_id', '').title()}.")
                    messagebox.showinfo(
                        "License activated",
                        "This PC is now activated and the matching plan controls are available.",
                        parent=dialog,
                    )
                else:
                    self.status.set("License verification complete.")
                    messagebox.showinfo(
                        "License verified",
                        "The saved license and receipt are valid on this PC.",
                        parent=dialog,
                    )
                return
            self.status.set(f"License {mode} finished, but the plan is not active.")
            messagebox.showwarning(
                "License not active",
                updated.get("last_error") or license_status_text(updated),
                parent=dialog,
            )

        def poll_license_request():
            try:
                mode, source_state, updated, error = request_results.get_nowait()
            except queue.Empty:
                if request_busy and dialog.winfo_exists():
                    dialog.after(50, poll_license_request)
                return
            finish_license_request(mode, source_state, updated, error)

        def start_license_request(mode):
            if request_busy:
                return
            source_state = collect_state()
            try:
                source_state["license_key"] = require_valid_api_license_key(source_state.get("license_key"))
                source_state["server_url"] = validated_license_server_url(source_state.get("server_url"))
            except Exception as exc:
                failed = build_license_failure_state(source_state, exc)
                persist_and_refresh(failed)
                messagebox.showerror("License key needs attention", str(exc), parent=dialog)
                return
            set_request_busy(True, mode)

            def worker():
                try:
                    if mode == "activate":
                        updated = activate_license_online(source_state)
                        label = "activation"
                    elif mode == "deactivate":
                        updated = deactivate_license_online(source_state)
                        label = "deactivation"
                    else:
                        updated = verify_license_online(source_state)
                        label = "verification"
                    error = None
                except Exception as exc:
                    updated = None
                    error = exc
                    label = {
                        "activate": "activation",
                        "deactivate": "deactivation",
                    }.get(mode, "verification")
                request_results.put((label, source_state, updated, error))

            threading.Thread(target=worker, name=f"License-{mode}", daemon=True).start()
            dialog.after(50, poll_license_request)

        def activate_now():
            start_license_request("activate")

        def verify_now():
            start_license_request("verify")

        def deactivate_now():
            if request_busy:
                return
            if not self.license_state.get("receipt"):
                messagebox.showerror(
                    "No activation to remove",
                    "This PC does not have a saved activation receipt.",
                    parent=dialog,
                )
                return
            if not messagebox.askyesno(
                "Remove license from this PC",
                "Deactivate this PC through the API and remove its saved license key and receipt?\n\nThis does not revoke the customer's whole license.",
                parent=dialog,
            ):
                return
            start_license_request("deactivate")

        def clear_now():
            if request_busy:
                return
            if not messagebox.askyesno(
                "Clear local license copy only",
                "Remove the saved key and receipt only from this PC?\n\nThe API activation will not be deactivated. Use REMOVE FROM THIS PC when online.",
                parent=dialog,
            ):
                return
            cleared = clear_license_state(self.settings, server_var.get())
            self.license_state = cleared
            self.license_status.set(license_status_text(cleared))
            self.apply_access_state()
            refresh_dialog(cleared)
            log_event("license_local_clear", "local", "ok")
            self.status.set("Cleared only the local license copy from this PC.")

        def use_default_server():
            server_var.set(DEFAULT_LICENSE_SERVER)

        def copy_machine_id():
            dialog.clipboard_clear()
            dialog.clipboard_append(machine_var.get())
            self.status.set("Copied this PC's machine ID.")

        def open_issuer_app():
            try:
                launch_companion_script("license_issuer.py")
                self.status.set("Opened VaultLink License Issuer.")
            except Exception as exc:
                messagebox.showerror("Could not open License Issuer", str(exc), parent=dialog)

        request_buttons["activate"] = tk.Button(action_row, text="ACTIVATE", command=activate_now, bg=GREEN, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold"))
        request_buttons["activate"].pack(side="left", ipadx=16, ipady=8)
        request_buttons["verify"] = tk.Button(action_row, text="VERIFY", command=verify_now, bg=WHITE, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold"))
        request_buttons["verify"].pack(side="left", padx=(10, 0), ipadx=16, ipady=8)
        tk.Button(action_row, text="DEFAULT API", command=use_default_server, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(action_row, text="COPY MACHINE ID", command=copy_machine_id, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(action_row, text="ISSUER APP", command=open_issuer_app, bg=YELLOW, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=10, ipady=8)
        removal_row = tk.Frame(panel, bg=PANEL)
        removal_row.grid(row=7, column=0, sticky="ew", padx=18, pady=(12, 0))
        request_buttons["deactivate"] = tk.Button(
            removal_row,
            text="REMOVE FROM THIS PC",
            command=deactivate_now,
            bg=RED,
            fg=WHITE,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        request_buttons["deactivate"].pack(side="left", ipadx=16, ipady=8)
        request_buttons["clear"] = tk.Button(
            removal_row,
            text="CLEAR LOCAL COPY ONLY",
            command=clear_now,
            bg="#252936",
            fg=TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        request_buttons["clear"].pack(side="left", padx=(10, 0), ipadx=14, ipady=8)

        status_panel = tk.Frame(panel, bg="#181c24")
        status_panel.grid(row=8, column=0, sticky="nsew", padx=18, pady=(16, 12))
        tk.Label(status_panel, text="STATUS", bg="#181c24", fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=14, pady=(14, 4))
        tk.Label(status_panel, textvariable=status_var, bg="#181c24", fg=GREEN, font=("Segoe UI", 10, "bold"), justify="left", wraplength=620).pack(anchor="w", padx=14)
        tk.Label(status_panel, textvariable=summary_var, bg="#181c24", fg=TEXT, font=("Segoe UI", 9), justify="left", wraplength=620).pack(anchor="w", padx=14, pady=(8, 14))

        feature_panel = tk.Frame(panel, bg="#181c24")
        feature_panel.grid(row=9, column=0, sticky="nsew", padx=18, pady=(0, 18))
        tk.Label(feature_panel, text="ENTITLEMENTS", bg="#181c24", fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=14, pady=(14, 4))
        tk.Label(feature_panel, textvariable=features_var, bg="#181c24", fg=TEXT, font=("Segoe UI", 9), justify="left", wraplength=620).pack(anchor="w", padx=14, pady=(0, 14))

        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(8, weight=1)
        panel.rowconfigure(9, weight=1)
        license_entry.focus_set()

    def refresh_breach_status(self):
        try:
            summary = breach_detection_summary()
            prefix = {
                "clear": "BREACH CHECK: CLEAR",
                "warning": "BREACH CHECK: WARNING",
                "high": "BREACH CHECK: HIGH RISK",
                "critical": "BREACH CHECK: CRITICAL",
            }.get(summary["level"], "BREACH CHECK")
            self.breach_status.set(f"{prefix} - {summary['headline']}")
        except Exception as exc:
            self.breach_status.set(f"BREACH CHECK UNAVAILABLE - {exc}")

    def periodic_breach_refresh(self):
        try:
            self.refresh_breach_status()
        finally:
            if self.winfo_exists():
                self.after(20000, self.periodic_breach_refresh)

    def open_breach_check(self):
        if not ensure_license_feature("global-breach-guard", parent=self):
            self.status.set("Breach Detection needs an active Pro license.")
            return
        try:
            _window, summary = open_breach_detection_window(self)
            self.breach_status.set(
                {
                    "clear": "BREACH CHECK: CLEAR",
                    "warning": "BREACH CHECK: WARNING",
                    "high": "BREACH CHECK: HIGH RISK",
                    "critical": "BREACH CHECK: CRITICAL",
                }.get(summary["level"], "BREACH CHECK")
                + f" - {summary['headline']}"
            )
        except Exception as exc:
            self.status.set("Could not open Breach Detection.")
            messagebox.showerror("Could not open Breach Detection", str(exc))

    def open_global_breach_guard(self):
        if not ensure_license_feature("global-breach-guard", parent=self):
            self.status.set("Global Breach Guard needs an active Pro license.")
            return
        try:
            launch_companion_script("global_breach_guard.py")
            self.status.set("Opened Global Breach Guard.")
        except Exception as exc:
            self.status.set("Could not open Global Breach Guard.")
            messagebox.showerror("Could not open Global Breach Guard", str(exc))

    def open_data_folder(self):
        try:
            os.startfile(APP_DIR)
            self.status.set("Opened the app data folder.")
        except Exception as exc:
            self.status.set("Could not open the app data folder.")
            messagebox.showerror("Could not open data folder", str(exc))

    def backup_app_data(self):
        destination = filedialog.askdirectory(title="Choose folder for app data backup")
        if not destination:
            self.status.set("App data backup canceled.")
            return
        try:
            backup_dir, copied, summary = export_app_data_backup(destination)
            log_event("backup_app_data", backup_dir, "ok", f"files={len(copied)}")
            self.status.set(f"Backed up app data to {backup_dir}.")
            messagebox.showinfo(
                "App data backed up",
                f"Saved backup folder:\n{backup_dir}\n\n"
                f"Copied {len(copied)} file(s).\n"
                "USB key files were not included.",
            )
        except Exception as exc:
            log_event("backup_app_data", destination, "failed", str(exc))
            self.status.set("Could not back up app data.")
            messagebox.showerror("Backup failed", str(exc))

    def restore_app_data(self):
        source = filedialog.askdirectory(title="Choose app data backup folder to restore")
        if not source:
            self.status.set("App data restore canceled.")
            return
        if not messagebox.askyesno(
            "Restore app data",
            "This will replace matching app-data files in your USB File Locker data folder.\n\n"
            "A safety snapshot of the current app data will be made first.\n\nContinue?",
        ):
            self.status.set("App data restore canceled.")
            return
        try:
            snapshot_dir, restored_files, summary = restore_app_data_backup(source)
            self.settings = load_settings()
            self.owner_policy = load_owner_policy(self.settings)
            self.apply_access_state()
            log_event("restore_app_data", source, "ok", f"files={len(restored_files)}")
            self.status.set(f"Restored app data from {source}.")
            messagebox.showinfo(
                "App data restored",
                f"Restored {len(restored_files)} file(s) from:\n{source}\n\n"
                f"Safety snapshot saved in:\n{snapshot_dir}",
            )
        except Exception as exc:
            log_event("restore_app_data", source, "failed", str(exc))
            self.status.set("Could not restore app data.")
            messagebox.showerror("Restore failed", str(exc))

    def open_recent_keys(self):
        dialog = tk.Toplevel(self)
        self.register_secondary_window(dialog)
        dialog.title("Recent USB Keys")
        dialog.geometry("860x420")
        dialog.minsize(760, 360)
        dialog.configure(bg=BG)
        status = tk.StringVar(value="Pick a saved key path to load it fast.")
        recent_paths = []

        outer = tk.Frame(dialog, bg=BG)
        outer.pack(fill="both", expand=True, padx=18, pady=16)

        tk.Label(outer, text="Recent USB Keys", bg=BG, fg=TEXT, font=("Segoe UI", 22, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="Saved key paths stay in the app data folder so updates do not wipe them.",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(4, 12))

        list_frame = tk.Frame(outer, bg=PANEL)
        list_frame.pack(fill="both", expand=True)
        key_list = tk.Listbox(
            list_frame,
            bg=FIELD,
            fg=TEXT,
            selectbackground=GREEN,
            selectforeground=BLACK,
            highlightthickness=1,
            highlightcolor="#343946",
            highlightbackground="#343946",
            bd=0,
            font=("Segoe UI", 10),
        )
        key_list.pack(side="left", fill="both", expand=True, padx=(14, 0), pady=14)
        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=key_list.yview)
        scroll.pack(side="left", fill="y", padx=(0, 14), pady=14)
        key_list.configure(yscrollcommand=scroll.set)

        def refresh_recent(select_first=True):
            recent_paths[:] = recent_key_paths_from_settings(self.settings)
            key_list.delete(0, "end")
            for path in recent_paths:
                marker = "READY" if Path(path).exists() else "MISSING"
                key_list.insert("end", f"[{marker}] {path}")
            if recent_paths and select_first:
                key_list.selection_set(0)
                key_list.see(0)
            if recent_paths:
                status.set(f"Showing {len(recent_paths)} saved key path(s).")
            else:
                status.set("No recent USB key paths are saved yet.")

        def selected_recent_path():
            selection = key_list.curselection()
            if not selection:
                return None
            return recent_paths[selection[0]]

        def load_selected():
            path = selected_recent_path()
            if not path:
                status.set("Pick a recent key first.")
                return
            if not Path(path).exists():
                status.set("That saved key path is not available right now.")
                if messagebox.askyesno("Missing key", "That USB key path is missing.\n\nRemove it from recent keys?"):
                    remove_entry(path)
                return
            try:
                self.set_key(load_key_file(path))
                log_event("load_recent_key", path, "ok", self.key["key_id"])
                self.status.set(f"Loaded recent master key from {key_location_summary(self.key)}")
                dialog.destroy()
            except Exception as exc:
                log_event("load_recent_key", path, "failed", str(exc))
                status.set("Could not load that recent key.")
                messagebox.showerror("Could not load recent key", str(exc))

        def remove_entry(path=None):
            chosen = path or selected_recent_path()
            if not chosen:
                status.set("Pick a recent key first.")
                return
            kept = [item for item in recent_key_paths_from_settings(self.settings) if item != chosen]
            self.settings["recent_key_paths"] = kept
            if kept:
                self.settings["last_key_path"] = kept[0]
            elif self.settings.get("last_key_path") == chosen:
                self.settings.pop("last_key_path", None)
            save_settings(self.settings)
            refresh_recent()
            status.set("Removed that saved key path.")

        def remove_missing():
            before = len(recent_key_paths_from_settings(self.settings))
            kept = remove_missing_recent_key_paths(self.settings)
            save_settings(self.settings)
            refresh_recent()
            removed = before - len(kept)
            status.set(f"Removed {removed} missing key path(s)." if removed else "No missing key paths were found.")

        def copy_selected_path():
            path = selected_recent_path()
            if not path:
                status.set("Pick a recent key first.")
                return
            self.clipboard_clear()
            self.clipboard_append(path)
            self.update()
            status.set("Copied the selected key path.")

        def open_selected_folder():
            path = selected_recent_path()
            if not path:
                status.set("Pick a recent key first.")
                return
            parent = Path(path).parent
            if not parent.exists():
                status.set("That key folder is not available right now.")
                return
            try:
                os.startfile(parent)
                status.set("Opened the selected key folder.")
            except Exception as exc:
                status.set("Could not open the selected key folder.")
                messagebox.showerror("Could not open key folder", str(exc))

        buttons = tk.Frame(outer, bg=BG)
        buttons.pack(fill="x", pady=(12, 0))
        tk.Button(buttons, text="LOAD SELECTED", command=load_selected, bg=GREEN, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=14, ipady=8)
        tk.Button(buttons, text="COPY PATH", command=copy_selected_path, bg=WHITE, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(buttons, text="OPEN FOLDER", command=open_selected_folder, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(buttons, text="REMOVE SELECTED", command=remove_entry, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(buttons, text="REMOVE MISSING", command=remove_missing, bg=YELLOW, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(buttons, text="CLOSE", command=dialog.destroy, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=16, ipady=8)
        tk.Label(outer, textvariable=status, bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(12, 0))

        refresh_recent()

    def verify_owner_usb_now(self):
        if not ensure_license_feature("owner-usb-mode", parent=self):
            self.status.set("Owner USB mode needs an active Pro license.")
            return
        if not self.owner_policy:
            self.status.set("Owner USB mode is off.")
            messagebox.showinfo("Owner USB mode off", "This PC is not currently locked to an owner USB.")
            return
        details = [f"Expected owner USB:\n{owner_policy_description(self.owner_policy)}"]
        if not self.key:
            self.status.set("Owner USB mode is on. Load the registered USB key to unlock this PC.")
            messagebox.showwarning(
                "Owner USB required",
                "\n\n".join(
                    details
                    + [
                        "No USB key is loaded right now.\n\n"
                        "Load the registered owner USB key to unlock the app on this PC."
                    ]
                ),
            )
            return
        details.append(f"Loaded USB key:\n{key_location_summary(self.key)}\nKey ID {self.key['key_id']}")
        allowed, message = owner_key_allowed(self.key, self.owner_policy)
        if allowed:
            self.status.set("Owner USB verified.")
            messagebox.showinfo(
                "Owner USB verified",
                "\n\n".join(details + ["This PC is currently unlocked with the registered owner USB."]),
            )
            return
        self.status.set("Owner USB check failed.")
        messagebox.showerror(
            "Owner USB check failed",
            "\n\n".join(details + [f"Result:\n{message}"]),
        )

    def monitor_loaded_key(self):
        try:
            if self.key:
                if self.owner_policy:
                    allowed, _message = owner_key_allowed(self.key, self.owner_policy)
                    if not allowed:
                        self.clear_loaded_key("Owner USB was removed or replaced. The app locked itself again.", "owner_usb_removed")
                elif not Path(self.key["path"]).exists():
                    self.clear_loaded_key("Loaded key file is no longer available. The app locked itself again.", "usb_key_removed")
        finally:
            if self.winfo_exists():
                self.after(1500, self.monitor_loaded_key)

    def enable_owner_usb_mode(self):
        if not ensure_license_feature("owner-usb-mode", parent=self):
            self.status.set("Owner USB mode needs an active Pro license.")
            return
        if not self.require_key():
            return
        origin = self.key.get("origin")
        if not origin:
            messagebox.showerror("Drive info missing", "Could not read the current key drive information.")
            return
        if origin["drive_type"] != DRIVE_REMOVABLE:
            if not messagebox.askyesno(
                "Not a removable USB",
                "This key is not on a removable USB drive.\n\nYou can still bind the app to this drive, but the strongest protection is a real USB stick.\n\nContinue?",
            ):
                return
        policy = {
            "key_id": self.key["key_id"],
            "volume_serial": origin["serial"],
            "volume_root": origin["root"],
            "volume_label": origin["label"],
            "drive_type_name": origin["drive_type_name"],
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        save_owner_policy(self.settings, policy)
        self.owner_policy = policy
        self.apply_access_state()
        self.status.set(f"Owner USB mode is on for {origin['root']} {origin['label']}.")
        log_event("configuration_change", "owner_usb_mode", "ok")
        messagebox.showinfo(
            "Owner USB mode enabled",
            "This app is now tied to the loaded owner key and this drive.\n\n"
            "If the USB disappears, the app will lock itself again.",
        )

    def disable_owner_usb_mode(self):
        if not ensure_license_feature("owner-usb-mode", parent=self):
            self.status.set("Owner USB mode needs an active Pro license.")
            return
        if not self.owner_policy:
            self.status.set("Owner USB mode is already off.")
            return
        if not self.active_key_matches_owner_policy():
            messagebox.showerror("Owner USB required", "Load the registered owner USB key first.")
            return
        if not messagebox.askyesno("Turn off owner USB mode", "Turn off the owner USB requirement for this PC?"):
            return
        save_owner_policy(self.settings, None)
        self.owner_policy = None
        self.apply_access_state()
        self.status.set("Owner USB mode turned off.")
        log_event("configuration_change", "owner_usb_mode", "ok")

    def confirmed_lock_pin(self):
        pin = self.pin_entry.get()
        if not pin:
            return ""
        confirmation = simpledialog.askstring(
            "Confirm extra PIN",
            "Re-enter the exact PIN.\n\nIf you forget it, the locked data cannot be recovered.",
            show="*",
            parent=self,
        )
        if confirmation is None:
            self.status.set("Lock canceled before PIN confirmation.")
            return None
        if not hmac.compare_digest(pin.encode("utf-8"), confirmation.encode("utf-8")):
            messagebox.showerror("PINs do not match", "The two PIN entries were different. Nothing was locked.")
            self.status.set("PIN confirmation failed. Nothing was locked.")
            return None
        return pin

    def close_requested(self):
        if self.busy:
            messagebox.showinfo(
                "Operation running",
                "Wait for the current item to finish, or click CANCEL AFTER CURRENT.",
            )
            return
        self.destroy()

    def cancel_current_job(self):
        if self.busy:
            self.cancel_event.set()
            self.progress_text.set("Cancel requested")
            self.status.set("Cancel requested. The current item will finish safely.")

    def start_background_job(self, label, total, worker, finished):
        if self.busy:
            messagebox.showinfo("Please wait", "Another lock, unlock, or verification job is already running.")
            return False
        self.busy = True
        self.cancel_event.clear()
        self.progress_value.set(0)
        self.progress_text.set(f"{label}: 0/{max(total, 1)}")
        self.status.set(f"{label} started...")
        self.cancel_button.configure(state="normal")
        for button in self.busy_buttons:
            button.configure(state="disabled")

        events = queue.Queue()

        def report(completed, text=None):
            events.put(("progress", completed, text))

        def run():
            try:
                result = worker(report, self.cancel_event)
                error = None
            except Exception as exc:
                result = None
                error = exc
            events.put(("complete", result, error))

        def complete(result, error):
            self.busy = False
            self.cancel_button.configure(state="disabled")
            for button in self.busy_buttons:
                button.configure(state="normal")
            self.apply_access_state()
            if error is not None:
                self.progress_text.set("Failed")
                self.status.set(f"{label} failed.")
                messagebox.showerror(f"{label} failed", str(error))
                return
            self.progress_value.set(100)
            self.progress_text.set("Complete")
            finished(result)

        def poll_events():
            completed = False
            while True:
                try:
                    event = events.get_nowait()
                except queue.Empty:
                    break
                if event[0] == "progress":
                    _kind, count, text = event
                    self.progress_value.set((count / max(total, 1)) * 100)
                    self.progress_text.set(text or f"{label}: {count}/{total}")
                elif event[0] == "complete":
                    _kind, result, error = event
                    complete(result, error)
                    completed = True
            if not completed and self.winfo_exists():
                self.after(50, poll_events)

        thread = threading.Thread(target=run, name=f"USBFileLocker-{label}", daemon=False)
        thread.start()
        self.after(50, poll_events)
        return True

    def try_load_last_key(self):
        last_path = self.settings.get("last_key_path")
        if last_path and Path(last_path).exists():
            try:
                self.set_key(load_key_file(last_path))
                return
            except Exception:
                pass
        for candidate in bundled_key_candidates():
            try:
                self.set_key(load_key_file(candidate))
                return
            except Exception:
                continue

    def set_key(self, key):
        allowed, message = owner_key_allowed(key, self.owner_policy)
        if not allowed:
            raise ValueError(message)
        self.key = key
        remember_recent_key_path(self.settings, key["path"])
        save_settings(self.settings)
        self.apply_access_state()
        self.status.set(f"Loaded master key from {key_location_summary(key)}")
        log_event("login", key.get("path", ""), "ok")

    def create_key(self):
        if self.owner_policy:
            messagebox.showerror("Owner USB mode on", "Turn off owner USB mode before creating a different master key on this PC.")
            return
        path = filedialog.asksaveasfilename(
            title="Save master USB key",
            initialfile="master_usb_file_locker.key",
            defaultextension=".key",
            filetypes=[("USB locker key", "*.key"), ("All files", "*.*")],
        )
        if not path:
            self.status.set("Key creation canceled.")
            return
        try:
            key_data = create_key_file(path)
            self.set_key(load_key_file(path))
            created_origin = self.key.get("origin")
            location_note = ""
            if created_origin:
                location_note = f"\n\nSaved on {created_origin['root']} {created_origin['label']} [{created_origin['drive_type_name']}]."
            messagebox.showinfo(
                "Master key created",
                "Master USB key created.\n\nKeep it private and make a backup. If you lose it, locked files cannot be unlocked."
                + location_note,
            )
            log_event("create_key", path, "ok", key_data["key_id"])
        except Exception as exc:
            log_event("create_key", path, "failed", str(exc))
            self.status.set("Could not create key.")
            messagebox.showerror("Key failed", str(exc))

    def load_key(self):
        path = filedialog.askopenfilename(
            title="Load master USB key",
            filetypes=[("USB locker key", "*.key"), ("All files", "*.*")],
        )
        if not path:
            self.status.set("Load key canceled.")
            return
        try:
            self.set_key(load_key_file(path))
            log_event("load_key", path, "ok", self.key["key_id"])
        except Exception as exc:
            log_event("login", path, "failed", str(exc))
            self.status.set("Could not load key.")
            messagebox.showerror("Bad key", str(exc))

    def require_key(self):
        if not self.key:
            log_event("failed_access", "no_usb_key", "failed")
            messagebox.showerror("No USB key", "Load or create your master USB key first.")
            return False
        if self.owner_policy and not self.active_key_matches_owner_policy():
            log_event("failed_access", "owner_usb_required", "failed")
            messagebox.showerror("Owner USB required", "Load the registered owner USB key first.")
            return False
        return True

    def register_association_from_gui(self):
        try:
            register_locked_file_association()
            log_event("configuration_change", "locked_file_association", "ok")
            self.status.set(".locked files now open with USB File Locker.")
            messagebox.showinfo("Registered", "Double-clicking .locked files will now open the USB File Locker unlock prompt.")
        except Exception as exc:
            log_event("configuration_change", "locked_file_association", "failed", str(exc))
            self.status.set("Could not register .locked file type.")
            messagebox.showerror("Register failed", str(exc))

    def add_files(self):
        paths = filedialog.askopenfilenames(title="Choose files to lock or unlock")
        for path in paths:
            if path not in self.file_list.get(0, "end"):
                self.file_list.insert("end", path)
        if paths:
            self.status.set(f"Added {len(paths)} file(s).")

    def add_folder(self):
        path = filedialog.askdirectory(title="Choose a folder to lock")
        if not path:
            self.status.set("Add folder canceled.")
            return
        if path not in self.file_list.get(0, "end"):
            self.file_list.insert("end", path)
        self.status.set("Added 1 folder.")

    def add_perm_unlock_items(self):
        if not ensure_license_feature("perm-unlock", parent=self):
            self.status.set("PERM UNLOCK needs an active Plus license.")
            return
        try:
            folder = ensure_perm_unlock_folder()
            entries = sorted(folder.iterdir(), key=lambda path: (path.is_file(), path.name.lower()))
        except Exception as exc:
            log_event("add_perm_unlock_items", "perm_unlock_folder", "failed", str(exc))
            self.status.set("Could not open the PERM UNLOCK folder.")
            messagebox.showerror("Could not read folder", str(exc))
            return
        if not entries:
            self.status.set("PERM UNLOCK folder is empty.")
            if messagebox.askyesno("PERM UNLOCK is empty", f"No files are in:\n{folder}\n\nOpen the folder anyway?"):
                try:
                    os.startfile(folder)
                    self.status.set("Opened the PERM UNLOCK folder.")
                except Exception as exc:
                    self.status.set("Could not open the PERM UNLOCK folder.")
                    messagebox.showerror("Could not open folder", str(exc))
            return
        existing = set(self.file_list.get(0, "end"))
        added = 0
        for entry in entries:
            entry_text = str(entry)
            if entry_text not in existing:
                self.file_list.insert("end", entry_text)
                existing.add(entry_text)
                added += 1
        log_event("add_perm_unlock_items", folder, "ok", f"added={added} total={len(entries)}")
        self.status.set(f"Added {added} item(s) from the PERM UNLOCK folder.")

    def check_locked_compatibility(self):
        paths = self.selected_or_all_files()
        locked_paths = [Path(path) for path in paths if is_locked_path(path)]
        if not locked_paths:
            messagebox.showinfo("Lock format", "Select one or more .locked files first.")
            return
        portable = 0
        legacy = 0
        wrong_key = 0
        problems = []
        for path in locked_paths:
            try:
                info = locked_file_info(path)
                if info["portable"]:
                    portable += 1
                else:
                    legacy += 1
                locked_key = info["header"].get("key_id")
                if self.key and locked_key and locked_key != self.key["key_id"]:
                    wrong_key += 1
            except Exception as exc:
                problems.append(f"{path.name}: {exc}")
        details = [
            f"Portable, works on another Windows PC: {portable}",
            f"Old Windows-bound format: {legacy}",
            f"Loaded USB key does not match: {wrong_key}",
            f"Unreadable or damaged: {len(problems)}",
        ]
        if legacy:
            details.append(
                "\nOld locks must be opened on the original Windows account. "
                "Select them there and click UPGRADE OLD LOCKS."
            )
        if problems:
            details.append("\n" + "\n".join(problems[:5]))
        log_event("check_lock_format", "selected_locked_files", "ok", f"portable={portable} legacy={legacy}")
        messagebox.showinfo("Lock format check", "\n".join(details))

    def upgrade_legacy_selected(self):
        if not self.require_key():
            return
        paths = self.selected_or_all_files()
        locked_paths = [Path(path) for path in paths if is_locked_path(path)]
        if not locked_paths:
            messagebox.showinfo("Upgrade old locks", "Select one or more old .locked files first.")
            return
        if not messagebox.askyesno(
            "Upgrade old locks",
            "This creates new portable .locked copies and keeps every old locked file.\n\n"
            "It only works on the original Windows account that created an old lock.\n\nContinue?",
        ):
            return
        pin = self.pin_entry.get()
        upgraded = []
        skipped = 0
        errors = []
        for path in locked_paths:
            try:
                info = locked_file_info(path)
                if info["portable"]:
                    skipped += 1
                    continue
                output = upgrade_legacy_locked(path, self.key, pin)
                upgraded.append(str(output))
                log_event("upgrade_legacy_lock", path, "ok")
            except Exception as exc:
                errors.append(f"{path.name}: {exc}")
                log_event("upgrade_legacy_lock", path, "failed", str(exc))
        for output in upgraded:
            if output not in self.file_list.get(0, "end"):
                self.file_list.insert("end", output)
        self.status.set(f"Upgraded {len(upgraded)} old lock(s). Skipped {skipped}. Failed {len(errors)}.")
        text = f"Portable copies created: {len(upgraded)}\nAlready portable: {skipped}\nFailed: {len(errors)}"
        if errors:
            text += "\n\n" + "\n".join(errors[:5])
        messagebox.showinfo("Upgrade complete", text)

    def open_recovery_center(self):
        recovery = tk.Toplevel(self)
        self.register_secondary_window(recovery)
        recovery.title("Recovery Center")
        recovery.geometry("650x460")
        recovery.resizable(False, False)
        recovery.configure(bg=BG)

        tk.Label(recovery, text="Recovery Center", bg=BG, fg=TEXT, font=("Segoe UI", 22, "bold")).pack(anchor="w", padx=20, pady=(18, 2))
        key_text = f"Loaded key ID: {self.key['key_id']}" if self.key else "No master USB key loaded"
        tk.Label(recovery, text=key_text, bg=BG, fg=YELLOW if not self.key else GREEN, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=20)
        tk.Label(
            recovery,
            text="Test recovery before deleting originals. Key backups contain the full unlocking secret and must stay private.",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 10),
            wraplength=600,
            justify="left",
        ).pack(anchor="w", padx=20, pady=(6, 16))

        panel = tk.Frame(recovery, bg=PANEL)
        panel.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        def recovery_button(text, command, row, color="#252936", foreground=TEXT):
            button = tk.Button(panel, text=text, command=command, bg=color, fg=foreground, relief="flat", font=("Segoe UI", 10, "bold"))
            button.grid(row=row, column=0, sticky="ew", padx=16, pady=(14 if row == 0 else 8, 0), ipady=9)
            return button

        recovery_button("RUN KEY + PIN RECOVERY TEST", self.run_recovery_test_gui, 0, GREEN, BLACK)
        recovery_button("VERIFY SELECTED LOCKS", self.verify_selected_locks_gui, 1)
        recovery_button("BACK UP LOADED USB KEY", self.backup_loaded_key, 2, YELLOW, BLACK)
        recovery_button("COMPARE A BACKUP KEY", self.compare_backup_key, 3)
        recovery_button("CHECK SELECTED LOCK FORMAT", self.check_locked_compatibility, 4)
        recovery_button("CLOSE", recovery.destroy, 5)
        panel.columnconfigure(0, weight=1)

    def run_recovery_test_gui(self):
        if not self.require_key():
            return
        pin = self.confirmed_lock_pin()
        if pin is None:
            return

        def worker(report, _cancel):
            result = run_portable_recovery_test(self.key, pin)
            report(1, "Recovery test complete")
            return result

        def finished(result):
            log_event("recovery_self_test", "portable_test", "ok")
            self.status.set("Portable key + PIN recovery test passed.")
            messagebox.showinfo(
                "Recovery test passed",
                "Portable lock and unlock succeeded.\n\n"
                f"Key ID: {result['key_id']}\n"
                f"Bytes tested: {result['bytes_tested']:,}\n"
                "No test plaintext or lock was kept.",
            )

        self.start_background_job("Recovery test", 1, worker, finished)

    def verify_selected_locks_gui(self):
        if not self.require_key():
            return
        paths = [Path(path) for path in self.selected_or_all_files() if is_locked_path(path)]
        if not paths:
            messagebox.showinfo("Verify locks", "Select one or more .locked files first.")
            return
        pin = self.pin_entry.get()

        def worker(report, cancel):
            passed = []
            errors = []
            for index, path in enumerate(paths, 1):
                if cancel.is_set():
                    break
                try:
                    result = verify_locked_health(path, self.key, pin)
                    passed.append((path.name, result))
                    log_event("verify_locked_health", path, "ok", result["format"])
                except Exception as exc:
                    errors.append(f"{path.name}: {exc}")
                    log_event("verify_locked_health", path, "failed", str(exc))
                report(index, f"Verified {index}/{len(paths)}")
            return {"passed": passed, "errors": errors, "canceled": cancel.is_set()}

        def finished(result):
            self.status.set(f"Verified {len(result['passed'])} lock(s). Failed {len(result['errors'])}.")
            text = (
                f"Healthy locks: {len(result['passed'])}\n"
                f"Failed verification: {len(result['errors'])}\n"
                f"Canceled: {'yes' if result['canceled'] else 'no'}"
            )
            if result["errors"]:
                text += "\n\n" + "\n".join(result["errors"][:5])
            messagebox.showinfo("Lock verification complete", text)

        self.start_background_job("Verify locks", len(paths), worker, finished)

    def backup_loaded_key(self):
        if not self.require_key():
            return
        source = Path(self.key["path"])
        if not source.exists():
            messagebox.showerror("Missing key", "The loaded master key file is no longer available.")
            return
        if not messagebox.askyesno(
            "Back up master key",
            "A backup key can unlock everything protected by this master key.\n\n"
            "Store it on a separate private USB drive. Never upload it to GitHub, email, or chat.\n\nContinue?",
        ):
            return
        destination = filedialog.asksaveasfilename(
            title="Save backup master USB key",
            initialfile=f"master_usb_file_locker_backup_{self.key['key_id']}.key",
            defaultextension=".key",
            filetypes=[("USB locker key", "*.key"), ("All files", "*.*")],
        )
        if not destination:
            return
        destination = Path(destination)
        if destination.exists() and destination.is_dir():
            messagebox.showerror("Choose a file name", "Choose a backup key file name, not a folder.")
            return
        if destination.resolve() == source.resolve():
            messagebox.showerror("Choose another location", "The backup must not overwrite the loaded master key.")
            return
        try:
            shutil.copy2(source, destination)
            backup = load_key_file(destination)
            if backup["key_id"] != self.key["key_id"] or not hmac.compare_digest(backup["secret"], self.key["secret"]):
                destination.unlink(missing_ok=True)
                raise ValueError("The copied backup did not match the loaded key.")
            log_event("backup_master_key", "private_destination", "ok", self.key["key_id"])
            messagebox.showinfo("Backup verified", f"Backup key created and verified.\n\nKey ID: {self.key['key_id']}")
        except Exception as exc:
            log_event("backup_master_key", "private_destination", "failed", str(exc))
            messagebox.showerror("Backup failed", str(exc))

    def compare_backup_key(self):
        if not self.require_key():
            return
        path = filedialog.askopenfilename(
            title="Choose backup key to compare",
            filetypes=[("USB locker key", "*.key"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            backup = load_key_file(path)
            matches = backup["key_id"] == self.key["key_id"] and hmac.compare_digest(backup["secret"], self.key["secret"])
            log_event("compare_backup_key", "selected_key", "ok" if matches else "failed")
            if matches:
                messagebox.showinfo("Backup matches", f"This backup exactly matches key ID {self.key['key_id']}.")
            else:
                messagebox.showerror(
                    "Backup does not match",
                    f"Loaded key ID: {self.key['key_id']}\nSelected key ID: {backup['key_id']}",
                )
        except Exception as exc:
            log_event("compare_backup_key", "selected_key", "failed", str(exc))
            messagebox.showerror("Could not check backup", str(exc))

    def scan_personal_files(self):
        if not ensure_license_feature("portable-locking", parent=self):
            self.status.set("Scanning personal files needs an active Starter license.")
            return
        self.status.set("Scanning Desktop, Documents, and Downloads by filename...")
        self.update()
        paths = scan_personal_file_candidates()
        existing = set(self.file_list.get(0, "end"))
        added = 0
        for path in paths:
            if path not in existing:
                self.file_list.insert("end", path)
                existing.add(path)
                added += 1
        log_event("scan_personal_files", "common_user_dirs", "ok", f"found={len(paths)} added={added}")
        self.status.set(f"Found {len(paths)} personal-looking file(s). Added {added} new file(s) to the lock list.")
        if not paths:
            messagebox.showinfo("Scan complete", "No personal-looking files were found by filename in Desktop, Documents, or Downloads.")

    def find_locked_files_gui(self):
        self.status.set("Finding .locked files in Desktop, Documents, and Downloads...")
        self.update()
        paths = find_locked_files()
        existing = set(self.file_list.get(0, "end"))
        added = 0
        for path in paths:
            if path not in existing:
                self.file_list.insert("end", path)
                existing.add(path)
                added += 1
        log_event("find_locked_files", "common_user_dirs", "ok", f"found={len(paths)} added={added}")
        self.status.set(f"Found {len(paths)} locked file(s). Added {added} new file(s) to the list.")
        if not paths:
            messagebox.showinfo("Find locked complete", "No .locked files were found in Desktop, Documents, or Downloads.")

    def clear_files(self):
        self.file_list.delete(0, "end")
        self.status.set("File list cleared.")

    def selected_list_items(self):
        return [self.file_list.get(index) for index in self.file_list.curselection()]

    def remove_selected_files(self):
        selected = list(self.file_list.curselection())
        if not selected:
            self.status.set("No selected file or folder to remove.")
            return
        for index in reversed(selected):
            self.file_list.delete(index)
        self.status.set(f"Removed {len(selected)} selected item(s) from the list.")

    def open_selected_items(self):
        chosen = self.selected_list_items()
        if not chosen:
            self.status.set("Select one or more files or folders first.")
            return
        opened = 0
        missing = 0
        failures = []
        for item in chosen[:12]:
            path = Path(item)
            if not path.exists():
                missing += 1
                continue
            try:
                os.startfile(path)
                opened += 1
            except Exception as exc:
                failures.append(str(exc))
        if failures:
            self.status.set("Could not open one or more selected items.")
            messagebox.showerror("Could not open selected items", failures[0])
            return
        self.status.set(f"Opened {opened} selected item(s)." + (f" Missing: {missing}." if missing else ""))

    def open_selected_item_folders(self):
        chosen = self.selected_list_items()
        if not chosen:
            self.status.set("Select one or more files or folders first.")
            return
        targets = []
        seen = set()
        for item in chosen:
            path = Path(item)
            target = path if path.is_dir() else path.parent
            marker = os.path.normcase(str(target))
            if marker in seen:
                continue
            seen.add(marker)
            targets.append(target)
        opened = 0
        missing = 0
        failures = []
        for target in targets[:10]:
            if not target.exists():
                missing += 1
                continue
            try:
                os.startfile(target)
                opened += 1
            except Exception as exc:
                failures.append(str(exc))
        if failures:
            self.status.set("Could not open one or more selected folders.")
            messagebox.showerror("Could not open selected folders", failures[0])
            return
        self.status.set(f"Opened {opened} folder(s)." + (f" Missing: {missing}." if missing else ""))

    def remove_missing_files(self):
        items = list(self.file_list.get(0, "end"))
        kept = [item for item in items if Path(item).exists()]
        removed = len(items) - len(kept)
        self.file_list.delete(0, "end")
        for item in kept:
            self.file_list.insert("end", item)
        self.status.set(f"Removed {removed} missing item(s)." if removed else "No missing items were found in the list.")

    def sort_file_list(self):
        items = list(dict.fromkeys(self.file_list.get(0, "end")))
        items.sort(key=lambda item: item.lower())
        self.file_list.delete(0, "end")
        for item in items:
            self.file_list.insert("end", item)
        self.status.set(f"Sorted {len(items)} item(s).")

    def save_file_list(self):
        items = list(self.file_list.get(0, "end"))
        if not items:
            self.status.set("No file list to save yet.")
            messagebox.showinfo("Nothing to save", "Add some files or folders first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save file queue",
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("List file", "*.list"), ("All files", "*.*")],
            initialfile="usb_file_locker_queue.txt",
        )
        if not path:
            self.status.set("Save list canceled.")
            return
        try:
            write_text_atomic(path, "\n".join(items) + "\n")
            self.status.set(f"Saved {len(items)} queued item(s).")
        except Exception as exc:
            self.status.set("Could not save the file list.")
            messagebox.showerror("Could not save list", str(exc))

    def load_file_list(self):
        path = filedialog.askopenfilename(
            title="Load file queue",
            filetypes=[("Text file", "*.txt *.list"), ("All files", "*.*")],
        )
        if not path:
            self.status.set("Load list canceled.")
            return
        try:
            lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception as exc:
            self.status.set("Could not load the file list.")
            messagebox.showerror("Could not load list", str(exc))
            return
        incoming = []
        for line in lines:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            incoming.append(value)
        existing = list(self.file_list.get(0, "end"))
        final_items = list(dict.fromkeys(existing + incoming))
        self.file_list.delete(0, "end")
        for item in final_items:
            self.file_list.insert("end", item)
        added = len(final_items) - len(existing)
        self.status.set(f"Loaded {len(incoming)} list item(s). Added {added} new item(s).")

    def replace_list_items(self, remove_paths, add_paths, select_added=False):
        remove_set = {str(path) for path in remove_paths}
        existing = [item for item in self.file_list.get(0, "end") if item not in remove_set]
        final_items = []
        seen = set()
        for item in existing + [str(path) for path in add_paths]:
            if item not in seen:
                seen.add(item)
                final_items.append(item)
        self.file_list.delete(0, "end")
        for item in final_items:
            self.file_list.insert("end", item)
        if select_added:
            added_set = {str(path) for path in add_paths}
            self.file_list.selection_clear(0, "end")
            for index, item in enumerate(final_items):
                if item in added_set:
                    self.file_list.selection_set(index)
                    self.file_list.see(index)

    def selected_or_all_files(self):
        selected = self.file_list.curselection()
        if selected:
            return [self.file_list.get(index) for index in selected]
        return list(self.file_list.get(0, "end"))

    def lock_selected(self):
        if not ensure_license_feature("portable-locking", parent=self):
            self.status.set("Locking new files needs an active Starter license.")
            return
        if not self.require_key():
            return
        paths = self.selected_or_all_files()
        if not paths:
            self.status.set("Add files or folders first.")
            return
        pin = self.confirmed_lock_pin()
        if pin is None:
            return
        key = self.key

        def worker(report, cancel):
            outputs = []
            errors = []
            for index, path in enumerate(paths, 1):
                if cancel.is_set():
                    break
                try:
                    original = Path(path)
                    if is_locked_path(original):
                        raise ValueError("Choose an unlocked file or folder, not an existing .locked file.")
                    out_path = lock_file(path, key, pin)
                    outputs.append(str(out_path))
                    log_event("lock", path, "ok", str(out_path))
                except Exception as exc:
                    errors.append(f"{Path(path).name}: {exc}")
                    log_event("lock", path, "failed", str(exc))
                report(index, f"Locked {index}/{len(paths)}")
            return {"outputs": outputs, "errors": errors, "canceled": cancel.is_set()}

        def finished(result):
            self.status.set(f"Locked {len(result['outputs'])} item(s). Failed {len(result['errors'])}.")
            text = (
                f"Portable locks created: {len(result['outputs'])}\n"
                f"Failed: {len(result['errors'])}\n"
                f"Canceled: {'yes' if result['canceled'] else 'no'}"
            )
            if result["errors"]:
                text += "\n\n" + "\n".join(result["errors"][:5])
            messagebox.showinfo("Lock complete", text)

        self.start_background_job("Lock copy", len(paths), worker, finished)

    def lock_and_remove_selected(self):
        if not ensure_license_feature("portable-locking", parent=self):
            self.status.set("Locking new files needs an active Starter license.")
            return
        if not self.require_key():
            return
        paths = self.selected_or_all_files()
        if not paths:
            self.status.set("Add files or folders first.")
            return
        folder_count = sum(Path(path).is_dir() for path in paths)
        if not messagebox.askyesno(
            "Lock and remove originals",
            "This creates and verifies each portable .locked item, then permanently removes the readable original.\n\n"
            + (f"This selection includes {folder_count} folder(s) and everything inside them.\n\n" if folder_count else "")
            + "Use LOCK COPY instead if you want to keep the originals.\n\nContinue?",
        ):
            self.status.set("Private lock canceled.")
            return

        pin = self.confirmed_lock_pin()
        if pin is None:
            return
        key = self.key

        def worker(report, cancel):
            new_items = []
            errors = []
            for index, path in enumerate(paths, 1):
                if cancel.is_set():
                    break
                out_path = None
                try:
                    original = Path(path)
                    if is_locked_path(original):
                        raise ValueError("Choose a normal file or folder, not an existing .locked file.")
                    out_path = lock_file(original, key, pin)
                    if not verify_locked_file(out_path, original, key, pin):
                        out_path.unlink(missing_ok=True)
                        raise ValueError("The encrypted copy did not pass verification. The original was kept.")
                    if original.is_dir():
                        shutil.rmtree(original)
                    else:
                        original.unlink()
                    new_items.append(str(out_path))
                    log_event("lock_remove_original", path, "ok")
                except Exception as exc:
                    errors.append(f"{Path(path).name}: {exc}")
                    log_event("lock_remove_original", path, "failed", str(exc))
                report(index, f"Verified {index}/{len(paths)}")
            return {"new_items": new_items, "errors": errors, "canceled": cancel.is_set()}

        def finished(result):
            remaining = [item for item in self.file_list.get(0, "end") if item not in paths]
            self.file_list.delete(0, "end")
            for item in remaining + result["new_items"]:
                self.file_list.insert("end", item)
            self.status.set(f"Privately locked {len(result['new_items'])} item(s). Failed {len(result['errors'])}.")
            text = (
                f"Locked and verified: {len(result['new_items'])}\n"
                f"Failed and kept readable: {len(result['errors'])}\n"
                f"Canceled: {'yes' if result['canceled'] else 'no'}"
            )
            if result["errors"]:
                text += "\n\n" + "\n".join(result["errors"][:5])
            messagebox.showinfo("Private lock complete", text)

        self.start_background_job("Lock and verify", len(paths), worker, finished)

    def unlock_selected(self, output_dir=None):
        if not self.require_key():
            return
        paths = self.selected_or_all_files()
        if not paths:
            self.status.set("Add .locked files first.")
            return
        pin = self.pin_entry.get()
        key = self.key

        def worker(report, cancel):
            outputs = []
            errors = []
            for index, path in enumerate(paths, 1):
                if cancel.is_set():
                    break
                try:
                    unlock_target = resolve_unlock_target(path)
                    if not unlock_target:
                        raise ValueError(f"{Path(path).name} is not locked. Pick a .locked file, or lock it first.")
                    out_path = unlock_file(unlock_target, key, pin, output_dir)
                    outputs.append(str(out_path))
                    log_event("unlock", unlock_target, "ok", str(out_path))
                except Exception as exc:
                    errors.append(f"{Path(path).name}: {exc}")
                    log_event("unlock", path, "failed", str(exc))
                report(index, f"Unlocked {index}/{len(paths)}")
            return {"outputs": outputs, "errors": errors, "canceled": cancel.is_set()}

        def finished(result):
            temp_count = 0
            for output in result["outputs"]:
                out_path = Path(output)
                if output_dir is None and should_auto_delete_unlocked(out_path):
                    if open_temp_then_delete(out_path, self):
                        temp_count += 1
            editable_count = 0
            if output_dir is not None and result["outputs"]:
                self.replace_list_items(paths, result["outputs"], select_added=True)
                editable_count = len(result["outputs"])
            self.status.set(f"Unlocked {len(result['outputs'])} item(s). Failed {len(result['errors'])}.")
            extra = f"\nOpened {temp_count} temporary file(s); unlocked copies will be deleted." if temp_count else ""
            if editable_count:
                extra += (
                    f"\nAdded {editable_count} unlocked item(s) back into the list, ready to edit and lock again."
                    "\nThe original .locked files stay safe on disk."
                )
            text = (
                f"Unlocked {len(result['outputs'])} item(s).\n"
                f"Failed: {len(result['errors'])}."
                f"{extra}\nCanceled: {'yes' if result['canceled'] else 'no'}"
            )
            if result["errors"]:
                text += "\n\n" + "\n".join(result["errors"][:5])
            messagebox.showinfo("Unlock complete", text)

        self.start_background_job("Unlock", len(paths), worker, finished)

    def unlock_selected_to_folder(self):
        output_dir = filedialog.askdirectory(title="Choose folder for unlocked files")
        if not output_dir:
            self.status.set("Unlock to folder canceled.")
            return
        self.unlock_selected(output_dir)

    def perm_unlock_selected(self):
        if not ensure_license_feature("perm-unlock", parent=self):
            self.status.set("PERM UNLOCK needs an active Plus license.")
            return
        output_dir = filedialog.askdirectory(title="Choose folder for permanently unlocked files")
        if not output_dir:
            self.status.set("Permanent unlock canceled.")
            return
        self.status.set("Permanent unlock keeps the unlocked copy in the folder you chose.")
        self.unlock_selected(output_dir)

    def perm_unlock_selected_to_perm_folder(self):
        if not ensure_license_feature("perm-unlock", parent=self):
            self.status.set("PERM UNLOCK needs an active Plus license.")
            return
        try:
            output_dir = ensure_perm_unlock_folder()
            self.status.set(f"Permanent unlock folder ready: {output_dir}")
            self.unlock_selected(str(output_dir))
        except Exception as exc:
            self.status.set("Could not use the PERM UNLOCK folder.")
            messagebox.showerror("PERM UNLOCK folder error", str(exc))

    def lock_text_note(self):
        if not ensure_license_feature("quick-lock-note", parent=self):
            self.status.set("Quick lock notes need an active Starter license.")
            return
        if not self.require_key():
            return
        note = tk.Toplevel(self)
        self.register_secondary_window(note)
        note.title("Lock A Text Note")
        note.geometry("520x420")
        note.configure(bg=BG)
        tk.Label(note, text="Text Note", bg=BG, fg=TEXT, font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=18, pady=(16, 6))
        text = tk.Text(note, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 11), wrap="word")
        text.pack(fill="both", expand=True, padx=18, pady=(0, 12))

        def save_note():
            content = text.get("1.0", "end").strip()
            if not content:
                messagebox.showerror("Empty note", "Type something first.")
                return
            path = filedialog.asksaveasfilename(
                title="Save locked note",
                initialfile="locked_note.txt.locked",
                defaultextension=".locked",
                filetypes=[("Locked file", "*.locked"), ("All files", "*.*")],
            )
            if not path:
                return
            pin = self.confirmed_lock_pin()
            if pin is None:
                return
            temp_path = None
            locked_temp_path = None
            try:
                handle, temp_name = secure_mkstemp(prefix="usb-locker-note-", suffix=".txt")
                os.close(handle)
                temp_path = Path(temp_name)
                final_path = Path(path)
                final_path.parent.mkdir(parents=True, exist_ok=True)
                if final_path.exists():
                    if final_path.is_dir():
                        raise ValueError("Choose a file name, not a folder.")
                    final_path.unlink()
                temp_path.write_text(content + "\n", encoding="utf-8")
                locked_temp_path = lock_file(temp_path, self.key, pin)
                locked_temp_path.replace(final_path)
                if str(final_path) not in self.file_list.get(0, "end"):
                    self.file_list.insert("end", str(final_path))
                log_event("lock_note", final_path, "ok")
                self.status.set(f"Locked note saved: {final_path}")
                note.destroy()
            except Exception as exc:
                log_event("lock_note", path, "failed", str(exc))
                messagebox.showerror("Note failed", str(exc))
            finally:
                if temp_path is not None:
                    temp_path.unlink(missing_ok=True)
                if locked_temp_path is not None and locked_temp_path.exists():
                    locked_temp_path.unlink(missing_ok=True)

        tk.Button(note, text="LOCK NOTE", command=save_note, bg=GREEN, fg=BLACK, relief="flat", font=("Segoe UI", 10, "bold")).pack(pady=(0, 16), ipadx=18, ipady=10)

    def open_personal_vault(self):
        if not ensure_license_feature("personal-vault", parent=self):
            self.status.set("Personal Vault needs an active Plus license.")
            return
        if not self.require_key():
            return
        pin = self.pin_entry.get()
        if not VAULT_FILE.exists() and pin:
            pin = self.confirmed_lock_pin()
            if pin is None:
                return
        try:
            entries = load_personal_vault(self.key, pin)
            log_event("vault_open", VAULT_FILE, "ok")
        except Exception as exc:
            log_event("vault_open", VAULT_FILE, "failed", str(exc))
            messagebox.showerror("Vault locked", f"Could not open personal vault.\n\nUse the same USB key and optional PIN used to save it.\n\n{exc}")
            return

        vault = tk.Toplevel(self)
        self.register_secondary_window(vault)
        vault.title("Personal Vault")
        vault.geometry("980x640")
        vault.minsize(900, 600)
        vault.configure(bg=BG)

        selected_entry_id = {"value": None}
        visible_indices = []
        clipboard_job = {"value": None}
        type_var = tk.StringVar(value=PERSONAL_TYPES[0])
        search_var = tk.StringVar(value="")
        list_status = tk.StringVar(value="")
        protection_text = "This vault is protected by this USB key" + (" and the current PIN." if pin else " with no extra PIN.")
        vault_status = tk.StringVar(value=protection_text)
        loaded_pin = pin
        loaded_key_id = self.key.get("key_id")

        tk.Label(vault, text="Personal Vault", bg=BG, fg=TEXT, font=("Segoe UI", 22, "bold")).pack(anchor="w", padx=18, pady=(16, 2))
        tk.Label(vault, textvariable=vault_status, bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", padx=18, pady=(0, 12))

        body = tk.Frame(vault, bg=BG)
        body.pack(fill="both", expand=True, padx=18, pady=(0, 14))

        left = tk.Frame(body, bg=PANEL)
        left.pack(side="left", fill="both", expand=False, padx=(0, 12))
        tk.Label(left, text="SAVED PERSONAL STUFF", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=12, pady=(12, 6))
        search_row = tk.Frame(left, bg=PANEL)
        search_row.pack(fill="x", padx=12, pady=(0, 8))
        search_entry = tk.Entry(search_row, textvariable=search_var, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 10))
        search_entry.pack(fill="x", ipady=7)
        item_list = tk.Listbox(
            left,
            width=38,
            bg=FIELD,
            fg=TEXT,
            selectbackground=GREEN,
            selectforeground=BLACK,
            highlightthickness=1,
            highlightcolor="#343946",
            highlightbackground="#343946",
            bd=0,
            font=("Segoe UI", 10),
        )
        item_list.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        tk.Label(left, textvariable=list_status, bg=PANEL, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w", padx=12, pady=(0, 12))

        right = tk.Frame(body, bg=PANEL)
        right.pack(side="left", fill="both", expand=True)

        def field_label(text, row, column=0):
            tk.Label(right, text=text, bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).grid(row=row, column=column, sticky="w", padx=14, pady=(12, 4))

        quick_row = tk.Frame(right, bg=PANEL)
        quick_row.grid(row=0, column=0, columnspan=2, sticky="ew", padx=14, pady=(12, 0))
        tk.Label(quick_row, text="QUICK TYPES", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")

        def set_quick_type(kind):
            type_var.set(kind)

        for index, label in enumerate(["Passcode", "Recovery code", "Account", "Client record", "Private note"]):
            tk.Button(
                quick_row,
                text=label.upper(),
                command=lambda value=label: set_quick_type(value),
                bg="#252936",
                fg=TEXT,
                relief="flat",
                font=("Segoe UI", 8, "bold"),
            ).pack(side="left", padx=(8 if index else 10, 0), ipadx=8, ipady=5)

        field_label("TYPE", 1, 0)
        type_menu = tk.OptionMenu(right, type_var, *PERSONAL_TYPES)
        type_menu.config(bg=FIELD, fg=TEXT, activebackground="#252936", activeforeground=TEXT, highlightthickness=0, bd=0, font=("Segoe UI", 10))
        type_menu["menu"].config(bg=FIELD, fg=TEXT)
        type_menu.grid(row=2, column=0, sticky="ew", padx=14)

        field_label("NAME / LABEL", 1, 1)
        label_entry = tk.Entry(right, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 11))
        label_entry.grid(row=2, column=1, sticky="ew", padx=(0, 14), ipady=7)

        field_label("ACCOUNT / USERNAME / SITE", 3, 0)
        account_entry = tk.Entry(right, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 11))
        account_entry.grid(row=4, column=0, columnspan=2, sticky="ew", padx=14, ipady=7)

        field_label("SECRET / PASSCODE / RECOVERY CODE", 5, 0)
        secret_text = tk.Text(right, height=4, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 11), wrap="word")
        secret_text.grid(row=6, column=0, columnspan=2, sticky="ew", padx=14)

        secret_row = tk.Frame(right, bg=PANEL)
        secret_row.grid(row=7, column=0, columnspan=2, sticky="ew", padx=14, pady=(8, 0))

        def copy_temporarily(text_value, label):
            if not text_value.strip():
                self.status.set(f"No {label.lower()} to copy.")
                return
            self.clipboard_clear()
            self.clipboard_append(text_value)
            self.update()
            if clipboard_job["value"] is not None:
                self.after_cancel(clipboard_job["value"])

            def clear_if_same(expected=text_value):
                try:
                    current = self.clipboard_get()
                except Exception:
                    current = None
                if current == expected:
                    self.clipboard_clear()
                    self.status.set("Clipboard cleared automatically.")

            clipboard_job["value"] = self.after(45000, clear_if_same)
            self.status.set(f"Copied {label.lower()}. Clipboard will clear in 45 seconds.")

        tk.Button(secret_row, text="COPY SECRET", command=lambda: copy_temporarily(secret_text.get('1.0', 'end').strip(), "Secret"), bg=WHITE, fg=BLACK, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", ipadx=10, ipady=6)
        tk.Button(secret_row, text="COPY ACCOUNT", command=lambda: copy_temporarily(account_entry.get().strip(), "Account"), bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        tk.Button(secret_row, text="COPY NOTES", command=lambda: copy_temporarily(notes_text.get('1.0', 'end').strip(), "Notes"), bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(8, 0), ipadx=10, ipady=6)

        field_label("PRIVATE NOTES", 8, 0)
        notes_text = tk.Text(right, height=5, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 11), wrap="word")
        notes_text.grid(row=9, column=0, columnspan=2, sticky="nsew", padx=14)

        right.columnconfigure(0, weight=1)
        right.columnconfigure(1, weight=1)
        right.rowconfigure(9, weight=1)

        def entry_summary(entry):
            kind = entry.get("type", "Other")
            label = entry.get("label", "(no label)")
            account = entry.get("account", "").strip()
            return f"{kind}: {label}" + (f" - {account}" if account else "")

        def clone_entries():
            return [dict(entry) for entry in entries]

        def sort_entries():
            entries.sort(key=lambda entry: (entry.get("updated_at", ""), entry.get("label", "")), reverse=True)

        def refresh_items(select_entry_id=None):
            visible_indices[:] = []
            item_list.delete(0, "end")
            query = search_var.get().strip().lower()
            for index, entry in enumerate(entries):
                haystack = " ".join(
                    str(entry.get(field, ""))
                    for field in ("type", "label", "account", "secret", "notes")
                ).lower()
                if query and query not in haystack:
                    continue
                visible_indices.append(index)
                item_list.insert("end", entry_summary(entry))
            total = len(entries)
            shown = len(visible_indices)
            list_status.set(f"Showing {shown} of {total} item(s).")
            desired_id = select_entry_id if select_entry_id is not None else selected_entry_id["value"]
            matched_selection = False
            if desired_id is not None:
                for list_index, entry_index in enumerate(visible_indices):
                    if entries[entry_index].get("id") == desired_id:
                        item_list.selection_clear(0, "end")
                        item_list.selection_set(list_index)
                        item_list.see(list_index)
                        fill_fields(entry_index)
                        matched_selection = True
                        break
            if not matched_selection and visible_indices:
                item_list.selection_clear(0, "end")
                item_list.selection_set(0)
                fill_fields(visible_indices[0])
            elif not visible_indices:
                clear_fields(preserve_status=True)

        def clear_fields(preserve_status=False):
            selected_entry_id["value"] = None
            type_var.set(PERSONAL_TYPES[0])
            label_entry.delete(0, "end")
            account_entry.delete(0, "end")
            secret_text.delete("1.0", "end")
            notes_text.delete("1.0", "end")
            if not preserve_status:
                self.status.set("Ready for a new vault item.")

        def fill_fields(index):
            if index < 0 or index >= len(entries):
                return
            entry = entries[index]
            selected_entry_id["value"] = entry.get("id")
            type_var.set(entry.get("type", PERSONAL_TYPES[0]))
            label_entry.delete(0, "end")
            label_entry.insert(0, entry.get("label", ""))
            account_entry.delete(0, "end")
            account_entry.insert(0, entry.get("account", ""))
            secret_text.delete("1.0", "end")
            secret_text.insert("1.0", entry.get("secret", ""))
            notes_text.delete("1.0", "end")
            notes_text.insert("1.0", entry.get("notes", ""))

        def on_select(_event=None):
            selection = item_list.curselection()
            if selection:
                fill_fields(visible_indices[selection[0]])

        def ensure_loaded_write_context():
            current_pin = self.pin_entry.get()
            if current_pin != loaded_pin:
                raise ValueError(
                    "The PIN box changed after the vault was opened.\n\n"
                    "Open Personal Vault again with the exact USB key and PIN before saving changes."
                )
            if loaded_key_id and self.key.get("key_id") != loaded_key_id:
                raise ValueError("The loaded vault session no longer matches the original USB key.")
            return current_pin

        def confirmed_current_pin_if_needed():
            current_pin = self.pin_entry.get()
            if not current_pin:
                return ""
            confirmation = simpledialog.askstring(
                "Confirm export PIN",
                "Re-enter the exact PIN for this locked export.\n\nIf you forget it, the exported file cannot be opened.",
                show="*",
                parent=vault,
            )
            if confirmation is None:
                self.status.set("Locked export canceled before PIN confirmation.")
                return None
            if confirmation != current_pin:
                messagebox.showerror("PINs do not match", "The two PIN entries were different. Nothing was exported.")
                self.status.set("PIN confirmation failed. Nothing was exported.")
                return None
            return current_pin

        def save_entries():
            current_pin = ensure_loaded_write_context()
            out_path = save_personal_vault(entries, self.key, current_pin)
            log_event("save_personal_vault", out_path, "ok", f"{len(entries)} entries")
            self.status.set(f"Personal vault saved with {len(entries)} item(s).")
            vault_status.set(protection_text + f" Saved items: {len(entries)}.")

        def add_or_update():
            backup_entries = clone_entries()
            backup_selected_id = selected_entry_id["value"]
            label = label_entry.get().strip()
            secret = secret_text.get("1.0", "end").strip()
            notes = notes_text.get("1.0", "end").strip()
            account = account_entry.get().strip()
            if not label and not secret and not notes and not account:
                messagebox.showerror("Empty item", "Type something to save first.")
                return
            entry = {
                "id": secrets.token_hex(6),
                "type": type_var.get(),
                "label": label or "(no label)",
                "account": account,
                "secret": secret,
                "notes": notes,
                "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            selected_id = selected_entry_id["value"]
            target_index = next((index for index, current in enumerate(entries) if current.get("id") == selected_id), None)
            if target_index is None:
                entries.append(entry)
                selected_entry_id["value"] = entry["id"]
            else:
                entry["id"] = entries[target_index].get("id", entry["id"])
                entries[target_index] = entry
                selected_entry_id["value"] = entry["id"]
            sort_entries()
            try:
                save_entries()
                refresh_items(selected_entry_id["value"])
            except Exception as exc:
                entries[:] = backup_entries
                selected_entry_id["value"] = backup_selected_id
                log_event("save_personal_vault", VAULT_FILE, "failed", str(exc))
                messagebox.showerror("Save failed", str(exc))
                self.status.set("Save failed.")

        def delete_selected():
            selection = item_list.curselection()
            if not selection:
                messagebox.showerror("Nothing selected", "Pick an item to delete.")
                return
            if not messagebox.askyesno("Delete item", "Delete this personal vault item?"):
                return
            backup_entries = clone_entries()
            backup_selected_id = selected_entry_id["value"]
            del entries[visible_indices[selection[0]]]
            try:
                clear_fields()
                save_entries()
                log_event("vault_delete_item", VAULT_FILE, "ok")
                refresh_items()
            except Exception as exc:
                entries[:] = backup_entries
                selected_entry_id["value"] = backup_selected_id
                log_event("vault_delete_item", VAULT_FILE, "failed", str(exc))
                refresh_items(backup_selected_id)
                messagebox.showerror("Delete failed", str(exc))
                self.status.set("Delete failed.")

        def duplicate_selected():
            selection = item_list.curselection()
            if not selection:
                messagebox.showerror("Nothing selected", "Pick an item to duplicate.")
                return
            backup_entries = clone_entries()
            backup_selected_id = selected_entry_id["value"]
            source = dict(entries[visible_indices[selection[0]]])
            source["id"] = secrets.token_hex(6)
            source["label"] = f"{source.get('label', '(no label)')} copy"
            source["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            entries.append(source)
            sort_entries()
            try:
                save_entries()
                refresh_items(source["id"])
                self.status.set("Duplicated personal vault item.")
            except Exception as exc:
                entries[:] = backup_entries
                selected_entry_id["value"] = backup_selected_id
                log_event("vault_duplicate_item", VAULT_FILE, "failed", str(exc))
                refresh_items(backup_selected_id)
                messagebox.showerror("Duplicate failed", str(exc))
                self.status.set("Duplicate failed.")

        def export_selected_locked_text():
            selection = item_list.curselection()
            if not selection:
                messagebox.showerror("Nothing selected", "Pick an item to export.")
                return
            entry = entries[visible_indices[selection[0]]]
            path = filedialog.asksaveasfilename(
                title="Save locked vault item",
                initialfile=f"{safe_filename_piece(entry.get('label', 'vault_item'))}.txt.locked",
                defaultextension=".locked",
                filetypes=[("Locked file", "*.locked"), ("All files", "*.*")],
            )
            if not path:
                return
            export_pin = confirmed_current_pin_if_needed()
            if export_pin is None:
                return
            content = "\n".join(
                [
                    f"Type: {entry.get('type', '')}",
                    f"Label: {entry.get('label', '')}",
                    f"Account: {entry.get('account', '')}",
                    "",
                    "Secret:",
                    entry.get("secret", ""),
                    "",
                    "Notes:",
                    entry.get("notes", ""),
                ]
            ).strip() + "\n"
            temp_path = None
            locked_temp_path = None
            try:
                handle, temp_name = secure_mkstemp(prefix="vault-export-", suffix=".txt")
                os.close(handle)
                temp_path = Path(temp_name)
                temp_path.write_text(content, encoding="utf-8")
                locked_temp_path = lock_file(temp_path, self.key, export_pin)
                final_path = Path(path)
                final_path.parent.mkdir(parents=True, exist_ok=True)
                if final_path.exists():
                    if final_path.is_dir():
                        raise ValueError("Choose a file name, not a folder.")
                    final_path.unlink()
                locked_temp_path.replace(final_path)
                log_event("vault_export_locked", final_path, "ok")
                self.status.set(f"Exported locked vault item: {final_path.name}")
                if str(final_path) not in self.file_list.get(0, "end"):
                    self.file_list.insert("end", str(final_path))
                messagebox.showinfo("Locked export complete", f"Created locked file:\n{final_path}")
            except Exception as exc:
                log_event("vault_export_locked", path, "failed", str(exc))
                messagebox.showerror("Locked export failed", str(exc))
            finally:
                if temp_path is not None:
                    temp_path.unlink(missing_ok=True)
                if locked_temp_path is not None and locked_temp_path.exists():
                    locked_temp_path.unlink(missing_ok=True)

        def import_text_file():
            path = filedialog.askopenfilename(
                title="Import a text file into Personal Vault",
                filetypes=[
                    ("Text-like files", "*.txt *.csv *.json *.log *.md"),
                    ("All files", "*.*"),
                ],
            )
            if not path:
                return
            source = Path(path)
            try:
                try:
                    content = source.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    content = source.read_text(encoding="utf-16")
            except Exception as exc:
                messagebox.showerror("Import failed", f"Could not read that file as text:\n{exc}")
                return
            clear_fields()
            lowered_name = source.name.lower()
            if "pass" in lowered_name or "code" in lowered_name:
                type_var.set("Passcode")
            elif "recover" in lowered_name or "backup" in lowered_name:
                type_var.set("Recovery code")
            elif "account" in lowered_name or "login" in lowered_name:
                type_var.set("Account")
            else:
                type_var.set("Private note")
            label_entry.insert(0, source.stem)
            notes_text.insert("1.0", content)
            log_event("vault_import_text", source, "ok")
            self.status.set(f"Imported text from {source.name}. Click SAVE ITEM to encrypt it.")

        item_list.bind("<<ListboxSelect>>", on_select)
        search_var.trace_add("write", lambda *_args: refresh_items())
        sort_entries()
        refresh_items()
        if not entries:
            vault_status.set(protection_text + " Save your first item to create the vault file.")
            self.status.set("Personal vault is ready for the first item.")

        buttons = tk.Frame(right, bg=PANEL)
        buttons.grid(row=10, column=0, columnspan=2, sticky="ew", padx=14, pady=14)
        tk.Button(buttons, text="NEW", command=clear_fields, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=14, ipady=8)
        tk.Button(buttons, text="SAVE ITEM", command=add_or_update, bg=GREEN, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(8, 0), ipadx=14, ipady=8)
        tk.Button(buttons, text="DUPLICATE", command=duplicate_selected, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(8, 0), ipadx=14, ipady=8)
        tk.Button(buttons, text="IMPORT TEXT FILE", command=import_text_file, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(8, 0), ipadx=14, ipady=8)
        tk.Button(buttons, text="EXPORT LOCKED TXT", command=export_selected_locked_text, bg=YELLOW, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(8, 0), ipadx=14, ipady=8)
        tk.Button(buttons, text="DELETE", command=delete_selected, bg=RED, fg=WHITE, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=14, ipady=8)
        search_entry.focus_set()

    def open_log(self):
        log_event("audit_log_view", LOG_FILE, "ok")
        audit = tk.Toplevel(self)
        self.register_secondary_window(audit)
        audit.title("Audit Log")
        audit.geometry("860x540")
        audit.minsize(760, 460)
        audit.configure(bg=BG)

        tk.Label(audit, text="Audit Log", bg=BG, fg=TEXT, font=("Segoe UI", 23, "bold")).pack(anchor="w", padx=18, pady=(16, 2))
        tk.Label(
            audit,
            text="Privacy-safe activity history. No keystrokes, passwords, PINs, USB secrets, file contents, client names, or full paths are recorded.",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 9),
            wraplength=800,
            justify="left",
        ).pack(anchor="w", padx=18, pady=(0, 12))

        status = tk.StringVar(value="")
        tk.Label(audit, textvariable=status, bg=BG, fg=GREEN, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=18, pady=(0, 8))

        frame = tk.Frame(audit, bg=PANEL)
        frame.pack(fill="both", expand=True, padx=18)
        scroll = tk.Scrollbar(frame)
        scroll.pack(side="right", fill="y")
        text = tk.Text(
            frame,
            bg=FIELD,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            font=("Consolas", 10),
            wrap="none",
            yscrollcommand=scroll.set,
        )
        text.pack(fill="both", expand=True, padx=10, pady=10)
        scroll.config(command=text.yview)

        def read_audit_lines():
            lines = ["SEQ     UTC TIME              EVENT ID          ACTION                       RESULT", "-" * 86]
            paths = [audit_backup_path(index) for index in range(MAX_AUDIT_BACKUPS, 0, -1)] + [LOG_FILE]
            records = []
            for path in paths:
                try:
                    records.extend(load_audit_records(path))
                except Exception:
                    lines.append("Could not read one audit log file. Use VERIFY for details.")
                    return lines
            for record in records:
                lines.append(
                    f"{int(record.get('sequence', 0)):>6}  "
                    f"{record.get('time_utc', ''):<20}  "
                    f"{record.get('event_id', ''):<16}  "
                    f"{record.get('action', ''):<27}  "
                    f"{record.get('result', '')}"
                )
            if len(lines) == 2:
                lines.append("No audit events yet.")
            return lines

        def refresh():
            try:
                valid, count, message = verify_audit_logs()
                status.set(("VALID: " if valid else "WARNING: ") + f"{count} event(s). {message}")
                text.configure(state="normal")
                text.delete("1.0", "end")
                text.insert("1.0", "\n".join(read_audit_lines()))
                text.configure(state="disabled")
            except Exception as exc:
                status.set(f"WARNING: Audit log could not be verified. {exc}")

        def export_logs():
            destination = filedialog.askdirectory(title="Export Audit Log")
            if not destination:
                return
            try:
                copied, summary = export_audit_logs(destination)
                extra = ""
                if summary.get("already_present"):
                    extra = f"\nSkipped {summary['already_present']} file(s) that were already in that folder."
                log_event("audit_log_export", destination, "ok")
                messagebox.showinfo(
                    "Audit Log Exported",
                    f"Exported {copied} audit log file(s).{extra}\n\nVerification: {summary['verification']}",
                )
                refresh()
            except Exception as exc:
                log_event("audit_log_export", destination, "failed", str(exc))
                messagebox.showerror("Export failed", str(exc))

        def export_locked_logs():
            if not self.require_key():
                return
            pin = self.confirmed_lock_pin()
            if pin is None:
                return
            destination = filedialog.askdirectory(title="Save Locked Audit Report")
            if not destination:
                return
            try:
                out_path, report = export_locked_audit_report(destination, self.key, pin)
                log_event("export_locked_audit_report", out_path, "ok")
                messagebox.showinfo(
                    "Locked Audit Report Exported",
                    "Created locked audit report:\n"
                    f"{out_path}\n\n"
                    f"USB File Locker events: {report['usb_file_locker_audit']['event_count']}\n"
                    f"PC Safety Check events: {report['pc_safety_check_audit']['event_count']}\n\n"
                    f"Protection: {'USB key only' if not pin else 'USB key and that PIN'}.",
                )
                refresh()
            except Exception as exc:
                log_event("export_locked_audit_report", destination, "failed", str(exc))
                messagebox.showerror("Locked export failed", str(exc))

        def open_log_folder():
            try:
                os.startfile(APP_DIR)
                status.set("Opened audit log folder.")
            except Exception as exc:
                status.set("Could not open the audit log folder.")
                messagebox.showerror("Could not open log folder", str(exc))

        row = tk.Frame(audit, bg=BG)
        row.pack(fill="x", padx=18, pady=14)
        tk.Button(row, text="VERIFY", command=refresh, bg=GREEN, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=16, ipady=8)
        tk.Button(row, text="EXPORT RAW", command=export_logs, bg=WHITE, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(row, text="EXPORT LOCKED LOGS", command=export_locked_logs, bg=YELLOW, fg=BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(row, text="OPEN LOG FOLDER", command=open_log_folder, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(row, text="CLOSE", command=audit.destroy, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=16, ipady=8)
        refresh()


class LockedFileUnlocker(tk.Tk):
    def __init__(self, locked_path):
        super().__init__()
        cleanup_stale_secure_temp()
        self.locked_path = Path(locked_path)
        self.settings = load_settings()
        self.owner_policy = load_owner_policy(self.settings)
        self.title("Unlock Locked File")
        self.geometry("680x410")
        self.resizable(False, False)
        self.configure(bg=BG)
        self.status = tk.StringVar(value="Choose your USB key and type the exact PIN used when locking.")
        recent_paths = recent_key_paths_from_settings(self.settings)
        key_path = recent_paths[0] if recent_paths else ""
        if not key_path:
            for candidate in bundled_key_candidates():
                key_path = str(candidate)
                break
        self.key_path = tk.StringVar(value=key_path)
        self.output_dir = tk.StringVar(value="")
        self.build_ui()

    def build_ui(self):
        wrap = tk.Frame(self, bg=BG)
        wrap.pack(fill="both", expand=True, padx=18, pady=16)

        header = tk.Frame(wrap, bg=BG)
        header.pack(fill="x")
        tk.Label(header, text="Unlock File", bg=BG, fg=TEXT, font=("Segoe UI", 22, "bold")).pack(side="left")
        tk.Button(
            header,
            text="PERM UNLOCK FOLDER",
            command=self.perm_unlock_default_folder_now,
            bg="#252936",
            fg=TEXT,
            relief="flat",
            font=("Segoe UI", 11, "bold"),
        ).pack(side="right", padx=(0, 10), ipadx=16, ipady=10)
        tk.Button(
            header,
            text="PERM UNLOCK",
            command=self.perm_unlock_now,
            bg=YELLOW,
            fg=BLACK,
            relief="flat",
            font=("Segoe UI", 11, "bold"),
        ).pack(side="right", padx=(0, 10), ipadx=18, ipady=10)
        tk.Button(
            header,
            text="UNLOCK HERE",
            command=self.unlock_now,
            bg=GREEN,
            fg=BLACK,
            relief="flat",
            font=("Segoe UI", 11, "bold"),
        ).pack(side="right", ipadx=22, ipady=10)
        tk.Label(
            wrap,
            text=str(self.locked_path),
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 9),
            wraplength=570,
            justify="left",
        ).pack(anchor="w", pady=(4, 12))

        panel = tk.Frame(wrap, bg=PANEL)
        panel.pack(fill="both", expand=True)

        tk.Label(panel, text="MASTER USB KEY", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 4))
        key_entry = tk.Entry(panel, textvariable=self.key_path, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 10))
        key_entry.grid(row=1, column=0, sticky="ew", padx=14, ipady=7)
        tk.Button(panel, text="BROWSE", command=self.browse_key, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).grid(row=1, column=1, padx=(0, 14), ipady=5, ipadx=10)

        tk.Label(panel, text="OPTIONAL PIN", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).grid(row=2, column=0, sticky="w", padx=14, pady=(12, 4))
        self.pin_entry = tk.Entry(panel, show="*", bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 10))
        self.pin_entry.grid(row=3, column=0, sticky="ew", padx=14, ipady=7)
        tk.Button(panel, text="CANCEL", command=self.destroy, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).grid(row=3, column=1, padx=(0, 14), ipady=6, ipadx=18, sticky="ew")

        tk.Label(panel, text="OUTPUT FOLDER, OPTIONAL", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).grid(row=4, column=0, sticky="w", padx=14, pady=(12, 4))
        output_entry = tk.Entry(panel, textvariable=self.output_dir, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 10))
        output_entry.grid(row=5, column=0, sticky="ew", padx=14, ipady=7)
        tk.Button(panel, text="BROWSE", command=self.browse_output, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).grid(row=5, column=1, padx=(0, 14), ipady=5, ipadx=10)
        tk.Label(panel, textvariable=self.status, bg=PANEL, fg=MUTED, font=("Segoe UI", 9), wraplength=620, justify="left").grid(row=6, column=0, columnspan=2, sticky="w", padx=14, pady=(12, 10))

        panel.columnconfigure(0, weight=1)
        self.bind("<Return>", lambda _event: self.unlock_now())
        self.pin_entry.focus_set()

        if not self.locked_path.exists():
            self.status.set("That file does not exist.")
        elif not is_locked_path(self.locked_path) and not resolve_unlock_target(self.locked_path):
            self.status.set("This is a normal file. Choose the .locked version or lock it first.")
        else:
            try:
                info = locked_file_info(resolve_unlock_target(self.locked_path) or self.locked_path)
                if info["portable"]:
                    self.status.set(
                        f"PORTABLE {info['kind'].upper()} LOCK - works on another Windows PC "
                        "with the same USB key and exact PIN."
                    )
                else:
                    self.status.set(
                        "OLD WINDOWS-BOUND LOCK - unlock on the original Windows account, "
                        "then use UPGRADE OLD LOCKS."
                    )
                if self.owner_policy:
                    self.status.set(self.status.get() + f"\n\nThis PC also requires the owner USB: {owner_policy_description(self.owner_policy)}")
            except Exception as exc:
                self.status.set(f"Could not read lock information: {exc}")

    def browse_key(self):
        path = filedialog.askopenfilename(
            title="Load master USB key",
            filetypes=[("USB locker key", "*.key"), ("All files", "*.*")],
        )
        if path:
            self.key_path.set(path)

    def browse_output(self):
        path = filedialog.askdirectory(title="Choose folder for unlocked output")
        if path:
            self.output_dir.set(path)

    def unlock_now(self):
        self.run_unlock()

    def perm_unlock_now(self):
        chosen = filedialog.askdirectory(title="Choose folder for permanently unlocked output")
        if not chosen:
            self.status.set("Permanent unlock canceled.")
            return
        self.output_dir.set(chosen)
        self.run_unlock(chosen)

    def perm_unlock_default_folder_now(self):
        try:
            chosen = ensure_perm_unlock_folder()
            self.output_dir.set(str(chosen))
            self.status.set(f"Using PERM UNLOCK folder: {chosen}")
            self.run_unlock(str(chosen))
        except Exception as exc:
            self.status.set("Could not use the PERM UNLOCK folder.")
            messagebox.showerror("PERM UNLOCK folder error", str(exc))

    def run_unlock(self, chosen_output_override=None):
        if not self.locked_path.exists():
            messagebox.showerror("Missing file", "That file does not exist.")
            return
        unlock_target = resolve_unlock_target(self.locked_path)
        if not unlock_target:
            messagebox.showerror("Not locked", "This is a normal file. Choose the .locked version, or lock it first in the main app.")
            return
        key_file = self.key_path.get().strip()
        if not key_file:
            messagebox.showerror("No USB key", "Choose your master USB key file.")
            return
        try:
            key = load_key_file(key_file)
            allowed, message = owner_key_allowed(key, self.owner_policy)
            if not allowed:
                raise ValueError(message)
            remember_recent_key_path(self.settings, key_file)
            save_settings(self.settings)
            chosen_output = chosen_output_override if chosen_output_override is not None else (self.output_dir.get().strip() or None)
            output = unlock_file(unlock_target, key, self.pin_entry.get(), chosen_output)
            log_event("unlock_double_click", unlock_target, "ok", str(output))
            if chosen_output is None and should_auto_delete_unlocked(output):
                opened_temp = open_temp_then_delete(output, self, close_master_when_done=True)
                if not opened_temp:
                    self.status.set("Could not open the temporary file. The unlocked copy will still be deleted.")
                    return
                self.status.set("Opened temporary file. The unlocked copy will be deleted.")
                if output.suffix.lower() in TEXT_VIEW_EXTS:
                    messagebox.showinfo(
                        "Opened temporary file",
                        f"Opened temporary unlocked file:\n{output}\n\nClose the viewer when done. The unlocked copy will be deleted after the viewer closes.\n\nThe .locked file stays safe.",
                    )
                    self.destroy()
                else:
                    self.withdraw()
                return
            if chosen_output is None:
                self.status.set(f"Unlocked to {output}")
            else:
                self.status.set(f"Permanent unlocked copy saved to {output}")
            if messagebox.askyesno("Unlocked", f"Unlocked file:\n{output}\n\nOpen the folder?"):
                try:
                    os.startfile(output.parent)
                except Exception as exc:
                    self.status.set(f"Unlocked to {output} but could not open the folder.")
                    messagebox.showerror("Could not open folder", str(exc))
            self.destroy()
        except Exception as exc:
            log_event("unlock_double_click", self.locked_path, "failed", str(exc))
            self.status.set("Unlock failed.")
            messagebox.showerror("Unlock failed", f"Could not unlock this file.\n\nCheck the USB key and optional PIN.\n\n{exc}")


if __name__ == "__main__":
    if not sys.platform.startswith("win"):
        raise SystemExit("USB File Locker uses Windows DPAPI and only runs on Windows.")
    args = sys.argv[1:]
    if args and args[0] == "--unlock" and len(args) >= 2:
        app = LockedFileUnlocker(args[1])
    elif args and Path(args[0]).suffix.lower() in {".locked", ".lookeed"}:
        app = LockedFileUnlocker(args[0])
    elif args and args[0] == "--associate":
        register_locked_file_association()
        raise SystemExit(0)
    else:
        app = USBFileLocker()
    app.mainloop()
