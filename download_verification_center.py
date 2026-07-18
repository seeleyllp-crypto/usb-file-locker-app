from datetime import datetime, timezone
import base64
import hashlib
from itertools import islice
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import zipfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import usb_file_locker as locker


MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
MAX_RECEIPT_BYTES = 256 * 1024
MAX_RECEIPT_FOLDER_BYTES = 32 * 1024 * 1024
MAX_RECEIPT_FOLDER_ENTRIES = 1000
MAX_RECEIPT_FOLDER_JSON_FILES = 250
MAX_RECEIPT_REVIEW_HISTORY = 100
RECEIPT_REVIEW_SEARCH_DEBOUNCE_MS = 180
MAX_PROTECTED_RECEIPT_KEY_BYTES = 4096
HASH_CHUNK_BYTES = 1024 * 1024
DEFENDER_TIMEOUT_SECONDS = 10 * 60
SIGNATURE_TIMEOUT_SECONDS = 30
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
MAX_ARCHIVE_ENTRIES = 10_000
MAX_ARCHIVE_DECLARED_BYTES = 50 * 1024 * 1024 * 1024
HIGH_COMPRESSION_RATIO = 200
HIGH_COMPRESSION_MIN_BYTES = 100 * 1024 * 1024
RISKY_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".cpl",
    ".dll",
    ".exe",
    ".hta",
    ".jar",
    ".js",
    ".jse",
    ".lnk",
    ".msi",
    ".ocx",
    ".ps1",
    ".reg",
    ".scr",
    ".sys",
    ".vbe",
    ".vbs",
    ".wsf",
}
DECOY_EXTENSIONS = {
    ".csv",
    ".doc",
    ".docx",
    ".gif",
    ".jpg",
    ".jpeg",
    ".md",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".ppt",
    ".pptx",
    ".rtf",
    ".txt",
    ".xls",
    ".xlsx",
    ".zip",
}
NESTED_ARCHIVE_EXTENSIONS = {
    ".7z",
    ".apk",
    ".gz",
    ".iso",
    ".jar",
    ".rar",
    ".tar",
    ".tgz",
    ".xz",
    ".zip",
}
TYPE_EXTENSIONS = {
    "windows_pe": {".cpl", ".dll", ".exe", ".ocx", ".scr", ".sys"},
    "windows_shortcut": {".lnk"},
    "zip_archive": {".apk", ".docm", ".docx", ".jar", ".pptm", ".pptx", ".vsix", ".xlsm", ".xlsx", ".zip"},
    "pdf": {".pdf"},
    "png": {".png"},
    "jpeg": {".jpeg", ".jpg"},
    "gif": {".gif"},
    "seven_zip": {".7z"},
    "rar": {".rar"},
    "gzip": {".gz", ".tgz"},
    "elf": {".elf", ".so"},
    "ole_compound": {".doc", ".msi", ".ppt", ".xls"},
    "text": {".bat", ".cfg", ".cmd", ".csv", ".ini", ".js", ".json", ".md", ".ps1", ".reg", ".txt", ".vbs", ".xml", ".yaml", ".yml"},
}
PE_ARCHITECTURES = {
    0x014C: "x86",
    0x0200: "Itanium",
    0x8664: "x64",
    0xAA64: "ARM64",
}
WINDOWS_SHORTCUT_HEADER = bytes.fromhex("4c0000000114020000000000c000000000000046")
WARNING_LABELS = {
    "archive_declared_size_over_50gb": "Archive declares more than 50 GB of expanded data",
    "archive_encrypted_entries": "Archive contains encrypted entries that were not readable",
    "archive_entry_review_truncated": "Archive has more than 10,000 entries; review was truncated",
    "archive_executable_entries": "Archive contains executable or script extensions",
    "archive_extreme_compression": "Archive contains an extreme compression-ratio entry",
    "archive_links": "Archive contains link entries",
    "archive_nested_archives": "Archive contains nested archive extensions",
    "archive_office_macros": "Archive contains an Office macro project name",
    "archive_traversal_paths": "Archive contains absolute or parent-traversal paths",
    "archive_zero_compressed_size": "Archive declares expanded data with zero compressed bytes",
    "executable_or_script_extension": "Selected file uses an executable or script extension",
    "extension_header_mismatch": "Filename extension does not match the detected header",
    "macro_enabled_office_extension": "Selected file uses a macro-enabled Office extension",
    "malformed_pe_header": "File starts with MZ but has an invalid PE header",
    "misleading_double_extension": "Filename combines a document/media extension with an executable extension",
    "windows_shortcut": "Selected file is a Windows shortcut",
}
COMPARISON_LABELS = {
    "archive_summary_changed": "ZIP aggregate summary changed",
    "defender_state_changed": "Defender state changed",
    "detected_type_changed": "Detected file type changed",
    "extension_changed": "Filename extension changed",
    "extension_header_match_changed": "Extension/header match state changed",
    "pe_architecture_changed": "PE architecture changed",
    "sha256_changed": "Calculated SHA-256 changed",
    "signature_state_changed": "Digital-signature state changed",
    "signer_changed": "Signer identity changed",
    "size_band_changed": "Coarse file-size band changed",
    "warning_ids_changed": "Structural warning set changed",
}
INTEGRITY_LABELS = {
    "unsealed_legacy": "UNSEALED LEGACY RECEIPT",
    "valid_other_profile": "VALID SEAL FROM ANOTHER WINDOWS PROFILE",
    "valid_this_profile": "VALID LOCAL INTEGRITY SEAL",
}
FOLDER_REVIEW_STATUS_LABELS = {
    "byte_limit_not_inspected": "Not inspected: byte limit reached",
    "candidate_limit_not_inspected": "Not inspected: candidate limit reached",
    "invalid_or_tampered": "Invalid, unsupported, changed, or tampered",
    "link_or_junction_skipped": "Skipped link or junction",
    "non_json_skipped": "Skipped non-JSON entry",
    "oversized_skipped": "Skipped receipt over 256 KB",
    "read_error": "Could not read receipt",
    "subfolder_skipped": "Skipped subfolder",
    "unsealed_legacy": "Unsealed legacy receipt",
    "valid_other_profile": "Valid seal from another Windows profile",
    "valid_this_profile": "Valid local integrity seal",
}
FOLDER_REVIEW_TRIAGE = {
    "byte_limit_not_inspected": {
        "level": "review",
        "level_label": "REVIEW",
        "meaning": "The folder audit stopped before reading this receipt because its cumulative byte limit was reached.",
        "next_action": "Audit a smaller folder containing this receipt, or inspect this receipt by itself.",
    },
    "candidate_limit_not_inspected": {
        "level": "review",
        "level_label": "REVIEW",
        "meaning": "The folder audit stopped before reading this receipt because its JSON candidate limit was reached.",
        "next_action": "Audit a smaller folder containing this receipt, or inspect this receipt by itself.",
    },
    "invalid_or_tampered": {
        "level": "critical",
        "level_label": "ACTION REQUIRED",
        "meaning": "The receipt is malformed, unsupported, changed, or has an invalid integrity seal.",
        "next_action": "Do not rely on this receipt. Verify the original download again and export a new sealed receipt.",
    },
    "link_or_junction_skipped": {
        "level": "review",
        "level_label": "REVIEW",
        "meaning": "The entry redirects to another location, so the bounded folder audit did not follow it.",
        "next_action": "Open the real folder location yourself and audit that ordinary folder separately.",
    },
    "non_json_skipped": {
        "level": "info",
        "level_label": "INFO",
        "meaning": "The entry is not a JSON receipt candidate.",
        "next_action": "No receipt action is needed unless this file was expected to be a VaultLink JSON receipt.",
    },
    "oversized_skipped": {
        "level": "review",
        "level_label": "REVIEW",
        "meaning": "The JSON file is larger than the 256 KB receipt inspection limit.",
        "next_action": "Do not treat it as verified. Inspect its source and verify the original download again if needed.",
    },
    "read_error": {
        "level": "critical",
        "level_label": "ACTION REQUIRED",
        "meaning": "Windows could not read the receipt during the bounded audit.",
        "next_action": "Check file access and storage health, then inspect the receipt by itself.",
    },
    "subfolder_skipped": {
        "level": "info",
        "level_label": "INFO",
        "meaning": "The audit is intentionally non-recursive and did not enter this subfolder.",
        "next_action": "Audit that subfolder separately only if it contains receipts you want to review.",
    },
    "unsealed_legacy": {
        "level": "review",
        "level_label": "REVIEW",
        "meaning": "This older receipt has no integrity seal and may have been edited after export.",
        "next_action": "Verify the original download again and export a new locally sealed receipt.",
    },
    "valid_other_profile": {
        "level": "review",
        "level_label": "REVIEW",
        "meaning": "The integrity seal is valid, but it was created by another Windows profile.",
        "next_action": "Confirm the receipt came from a trusted profile, or re-verify the original file on this profile.",
    },
    "valid_this_profile": {
        "level": "good",
        "level_label": "VALID",
        "meaning": "The receipt has a valid integrity seal created by this Windows profile.",
        "next_action": "Keep it with the matching download and verify again if the original file changes.",
    },
}
FOLDER_REVIEW_NEEDS_REVIEW_STATUSES = frozenset(
    status
    for status, guidance in FOLDER_REVIEW_TRIAGE.items()
    if guidance["level"] in {"critical", "review"}
)
FOLDER_REVIEW_TRIAGE_PRIORITY = {
    "critical": 0,
    "review": 1,
    "info": 2,
    "good": 3,
}
FOLDER_REVIEW_LEVELS = frozenset({"all", *FOLDER_REVIEW_TRIAGE_PRIORITY})
FOLDER_REVIEW_SESSION_STATES = frozenset({"all", "pending", "reviewed"})
FOLDER_REVIEW_FILTER_STATUSES = {
    "all": frozenset(FOLDER_REVIEW_STATUS_LABELS),
    "needs_review": FOLDER_REVIEW_NEEDS_REVIEW_STATUSES,
    "problems": frozenset({"invalid_or_tampered", "read_error"}),
    "valid": frozenset({"valid_other_profile", "valid_this_profile"}),
    "legacy": frozenset({"unsealed_legacy"}),
    "skipped": frozenset(
        {
            "link_or_junction_skipped",
            "non_json_skipped",
            "oversized_skipped",
            "subfolder_skipped",
        }
    ),
    "limits": frozenset(
        {"byte_limit_not_inspected", "candidate_limit_not_inspected"}
    ),
}
FOLDER_REVIEW_SORT_MODES = frozenset({"filename", "priority", "result"})
RECEIPT_STRING_STATES = {
    "hash_comparison": {"match", "mismatch", "not_provided"},
    "signature_state": {"attention", "unknown", "unsigned", "valid"},
    "defender_state": {"attention", "inconclusive", "no_threats", "not_run"},
    "extension_header_match": {"match", "mismatch", "not_mapped"},
}
RECEIPT_SIZE_BANDS = {
    "under 1 MB",
    "1 MB to under 10 MB",
    "10 MB to under 100 MB",
    "100 MB to under 500 MB",
    "500 MB to under 2 GB",
    "2 GB to 8 GB",
    "unknown",
}
RECEIPT_ARCHIVE_SIZE_BANDS = RECEIPT_SIZE_BANDS | {
    "over 8 GB to 50 GB",
    "over 50 GB",
}
RECEIPT_PE_ARCHITECTURES = {
    "ARM64",
    "Itanium",
    "not_applicable",
    "unknown",
    "x64",
    "x86",
}
RECEIPT_SIGNING_KEY_FILE = locker.APP_DIR / "download_receipt_signing_key.dpapi"
RECEIPT_SIGNING_ENTROPY = hashlib.sha256(
    b"VaultLink-Download-Receipt-Integrity-Key-v1"
).digest()
RECEIPT_INTEGRITY_SCHEME = "ed25519-dpapi-local-v1"


def normalize_expected_sha256(value):
    text = str(value or "").strip()
    if not text:
        return ""
    text = re.sub(r"(?i)^\s*sha-?256\s*[:=]\s*", "", text)
    text = "".join(text.split()).lower()
    if not SHA256_RE.fullmatch(text):
        raise ValueError("Expected SHA-256 must contain exactly 64 hexadecimal characters.")
    return text


def size_band(size_bytes):
    size = max(0, int(size_bytes or 0))
    mib = 1024 * 1024
    gib = 1024 * mib
    if size < mib:
        return "under 1 MB"
    if size < 10 * mib:
        return "1 MB to under 10 MB"
    if size < 100 * mib:
        return "10 MB to under 100 MB"
    if size < 500 * mib:
        return "100 MB to under 500 MB"
    if size < 2 * gib:
        return "500 MB to under 2 GB"
    return "2 GB to 8 GB"


def archive_size_band(size_bytes):
    size = max(0, int(size_bytes or 0))
    if size > MAX_ARCHIVE_DECLARED_BYTES:
        return "over 50 GB"
    if size > MAX_FILE_BYTES:
        return "over 8 GB to 50 GB"
    return size_band(size)


def warning_labels(warning_ids):
    return [
        WARNING_LABELS.get(str(warning_id), str(warning_id).replace("_", " ").title())
        for warning_id in warning_ids or []
    ]


def _bounded_receipt_count(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return min(1_000_000, max(0, number))


def _clean_receipt_token(value, fallback, limit=80):
    text = "".join(
        character
        for character in str(value or "")
        if character in {" ", "-", "_", ".", "[", "]"} or character.isalnum()
    ).strip()
    return (text[:limit] or fallback)


def _normalized_warning_ids(values):
    if not isinstance(values, (list, tuple)):
        return []
    normalized = []
    for value in values[:50]:
        warning_id = str(value or "").strip()
        if warning_id in WARNING_LABELS:
            normalized.append(warning_id)
        elif warning_id:
            normalized.append("unrecognized_warning_id")
    return sorted(set(normalized))[:20]


def _base64url_encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value, expected_bytes, label):
    text = str(value or "").strip()
    if not text or len(text) > 256 or not re.fullmatch(r"[A-Za-z0-9_-]+", text):
        raise ValueError(f"The receipt integrity {label} is malformed.")
    try:
        raw = base64.urlsafe_b64decode(text + ("=" * (-len(text) % 4)))
    except Exception as exc:
        raise ValueError(f"The receipt integrity {label} is malformed.") from exc
    if len(raw) != expected_bytes:
        raise ValueError(f"The receipt integrity {label} has the wrong length.")
    return raw


def canonical_verification_receipt_bytes(payload):
    canonical = dict(payload or {})
    canonical.pop("integrity_seal", None)
    return json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def load_or_create_receipt_signing_key():
    key_path = Path(RECEIPT_SIGNING_KEY_FILE)
    if key_path.exists():
        if key_path.is_symlink() or not key_path.is_file():
            raise ValueError("The local receipt signing key is not a regular file.")
        protected = key_path.read_bytes()
        if not protected or len(protected) > MAX_PROTECTED_RECEIPT_KEY_BYTES:
            raise ValueError("The local receipt signing key is damaged.")
        try:
            raw_private_key = locker.dpapi_unprotect(
                protected,
                RECEIPT_SIGNING_ENTROPY,
            )
            if len(raw_private_key) != 32:
                raise ValueError("wrong key length")
            return Ed25519PrivateKey.from_private_bytes(raw_private_key)
        except Exception as exc:
            raise ValueError(
                "The local receipt signing key cannot be opened by this Windows user."
            ) from exc

    private_key = Ed25519PrivateKey.generate()
    protected = locker.dpapi_protect(
        private_key.private_bytes_raw(),
        RECEIPT_SIGNING_ENTROPY,
    )
    if not protected or len(protected) > MAX_PROTECTED_RECEIPT_KEY_BYTES:
        raise ValueError("Windows could not protect the local receipt signing key.")
    locker.write_bytes_atomic(key_path, protected)
    return private_key


def receipt_signing_key_id(private_key=None):
    key = private_key or load_or_create_receipt_signing_key()
    public_raw = key.public_key().public_bytes_raw()
    return hashlib.sha256(public_raw).hexdigest()[:16]


def seal_verification_receipt(receipt):
    if not isinstance(receipt, dict):
        raise ValueError("A verification receipt is required.")
    if receipt.get("schema_version") != 1:
        raise ValueError("Only a new schema-one verification receipt can be sealed.")
    sealed = dict(receipt)
    sealed["schema_version"] = 2
    sealed.pop("integrity_seal", None)
    sealed["integrity_note"] = (
        "The Ed25519 private key stays DPAPI-protected for this Windows user. "
        "Only the public key and receipt signature are embedded."
    )
    limitations = list(sealed.get("limitations") or [])
    limitations.extend(
        [
            "The local integrity seal detects receipt edits but is not a public code-signing certificate and does not prove the checked file is safe.",
            "The stable random public key can show that receipts were sealed by the same local signing key.",
        ]
    )
    sealed["limitations"] = limitations
    private_key = load_or_create_receipt_signing_key()
    public_raw = private_key.public_key().public_bytes_raw()
    signature = private_key.sign(canonical_verification_receipt_bytes(sealed))
    sealed["integrity_seal"] = {
        "scheme": RECEIPT_INTEGRITY_SCHEME,
        "key_id": hashlib.sha256(public_raw).hexdigest()[:16],
        "public_key": _base64url_encode(public_raw),
        "signature": _base64url_encode(signature),
    }
    return sealed


def verify_verification_receipt_integrity(payload):
    schema_version = payload.get("schema_version")
    seal = payload.get("integrity_seal")
    if schema_version == 1:
        if seal is not None:
            raise ValueError("A schema-one legacy receipt cannot contain an integrity seal.")
        return {"state": "unsealed_legacy"}
    if schema_version != 2:
        raise ValueError("That receipt schema version is not supported.")
    if not isinstance(seal, dict):
        raise ValueError("This sealed receipt is missing its integrity seal.")
    if seal.get("scheme") != RECEIPT_INTEGRITY_SCHEME:
        raise ValueError("The receipt uses an unsupported integrity-seal scheme.")
    public_raw = _base64url_decode(seal.get("public_key"), 32, "public key")
    signature = _base64url_decode(seal.get("signature"), 64, "signature")
    key_id = str(seal.get("key_id", "")).strip().lower()
    expected_key_id = hashlib.sha256(public_raw).hexdigest()[:16]
    if not re.fullmatch(r"[0-9a-f]{16}", key_id) or key_id != expected_key_id:
        raise ValueError("The receipt integrity key identifier does not match.")
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature,
            canonical_verification_receipt_bytes(payload),
        )
    except InvalidSignature as exc:
        raise ValueError(
            "The receipt integrity seal is invalid. The receipt may have been edited."
        ) from exc
    try:
        local_key_match = key_id == receipt_signing_key_id()
    except Exception:
        local_key_match = False
    return {
        "state": "valid_this_profile" if local_key_match else "valid_other_profile",
    }


def normalize_verification_receipt(payload):
    if not isinstance(payload, dict):
        raise ValueError("The selected receipt must be a JSON object.")
    if payload.get("report_type") != "vaultlink-download-verification":
        raise ValueError("That is not a supported VaultLink download-verification receipt.")
    integrity = verify_verification_receipt_integrity(payload)
    sha256 = str(payload.get("sha256", "")).strip().lower()
    if not SHA256_RE.fullmatch(sha256):
        raise ValueError("The receipt does not contain a valid calculated SHA-256.")
    structure = payload.get("structure") if isinstance(payload.get("structure"), dict) else {}
    archive = structure.get("archive") if isinstance(structure.get("archive"), dict) else None
    signature_state = str(payload.get("signature_state", "unknown")).strip().lower()
    defender_state = str(payload.get("defender_state", "not_run")).strip().lower()
    hash_comparison = str(payload.get("hash_comparison", "not_provided")).strip().lower()
    match_state = str(structure.get("extension_header_match", "not_mapped")).strip().lower()
    if signature_state not in RECEIPT_STRING_STATES["signature_state"]:
        signature_state = "unknown"
    if defender_state not in RECEIPT_STRING_STATES["defender_state"]:
        defender_state = "inconclusive"
    if hash_comparison not in RECEIPT_STRING_STATES["hash_comparison"]:
        hash_comparison = "not_provided"
    if match_state not in RECEIPT_STRING_STATES["extension_header_match"]:
        match_state = "not_mapped"
    signer_subject = str(payload.get("signer_subject", "")).strip()
    signer_fingerprint = hashlib.sha256(signer_subject.encode("utf-8")).hexdigest() if signer_subject else ""
    archive_summary = None
    if archive is not None:
        archive_summary = {
            field: _bounded_receipt_count(archive.get(field))
            for field in (
                "entry_count",
                "reviewed_entry_count",
                "traversal_entry_count",
                "link_entry_count",
                "encrypted_entry_count",
                "executable_entry_count",
                "nested_archive_count",
                "macro_entry_count",
                "high_compression_entry_count",
            )
        }
        archive_summary["declared_size_band"] = _clean_receipt_token(
            archive.get("declared_size_band"),
            "unknown",
            40,
        )
        archive_summary["review_truncated"] = bool(archive.get("review_truncated"))
        archive_summary["warning_ids"] = _normalized_warning_ids(archive.get("warning_ids"))
    return {
        "sha256": sha256,
        "size_band": _clean_receipt_token(payload.get("size_band"), "unknown", 40),
        "extension": _clean_receipt_token(payload.get("extension"), "[none]", 24).lower(),
        "hash_comparison": hash_comparison,
        "signature_state": signature_state,
        "signer_fingerprint": signer_fingerprint,
        "defender_state": defender_state,
        "integrity_state": integrity["state"],
        "structure": {
            "detected_type": _clean_receipt_token(structure.get("detected_type"), "unknown", 80).lower(),
            "extension_header_match": match_state,
            "pe_architecture": _clean_receipt_token(structure.get("pe_architecture"), "not_applicable", 40),
            "warning_ids": _normalized_warning_ids(structure.get("warning_ids")),
            "archive": archive_summary,
        },
    }


def load_verification_receipt(path):
    selected = Path(path)
    if selected.is_symlink():
        raise ValueError("Linked receipt files are not accepted.")
    if not selected.is_file() or selected.suffix.lower() != ".json":
        raise ValueError("Choose one VaultLink JSON verification receipt.")
    before = _file_identity(selected)
    if before["size"] > MAX_RECEIPT_BYTES:
        raise ValueError("That receipt is larger than the 256 KB import limit.")
    try:
        raw = selected.read_bytes()
    except OSError as exc:
        raise ValueError("The selected receipt could not be read.") from exc
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ValueError("That receipt is larger than the 256 KB import limit.")
    if before != _file_identity(selected):
        raise ValueError("The selected receipt changed while it was being inspected.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("The selected receipt is not valid UTF-8 JSON.") from exc
    return normalize_verification_receipt(payload)


def compare_verification_receipt(result, defender, prior_receipt):
    current = normalize_verification_receipt(build_privacy_safe_receipt(result, defender))
    prior = dict(prior_receipt or {})
    if not SHA256_RE.fullmatch(str(prior.get("sha256", ""))):
        raise ValueError("The prior receipt has not been safely normalized.")
    prior_integrity = str(prior.get("integrity_state", "")).strip()
    if prior_integrity not in INTEGRITY_LABELS:
        raise ValueError("The prior receipt integrity state is not recognized.")
    changes = []
    if current["sha256"] != prior["sha256"]:
        changes.append("sha256_changed")
    if current["size_band"] != prior.get("size_band"):
        changes.append("size_band_changed")
    if current["extension"] != prior.get("extension"):
        changes.append("extension_changed")
    if current["signature_state"] != prior.get("signature_state"):
        changes.append("signature_state_changed")
    if current["signer_fingerprint"] != prior.get("signer_fingerprint"):
        changes.append("signer_changed")
    if current["defender_state"] != prior.get("defender_state"):
        changes.append("defender_state_changed")
    current_structure = current["structure"]
    prior_structure = prior.get("structure") if isinstance(prior.get("structure"), dict) else {}
    if current_structure["detected_type"] != prior_structure.get("detected_type"):
        changes.append("detected_type_changed")
    if current_structure["extension_header_match"] != prior_structure.get("extension_header_match"):
        changes.append("extension_header_match_changed")
    if current_structure["pe_architecture"] != prior_structure.get("pe_architecture"):
        changes.append("pe_architecture_changed")
    current_warnings = set(current_structure["warning_ids"])
    prior_warnings = set(prior_structure.get("warning_ids") or [])
    if current_warnings != prior_warnings:
        changes.append("warning_ids_changed")
    if current_structure.get("archive") != prior_structure.get("archive"):
        changes.append("archive_summary_changed")
    same_sha256 = current["sha256"] == prior["sha256"]
    if not same_sha256:
        verdict = "different_file_bytes"
    elif changes:
        verdict = "same_bytes_signals_changed"
    else:
        verdict = "exact_fixed_field_match"
    return {
        "schema_version": 1,
        "report_type": "vaultlink-download-comparison",
        "created_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verdict": verdict,
        "same_sha256": same_sha256,
        "change_ids": sorted(set(changes)),
        "change_count": len(set(changes)),
        "warning_ids_added": sorted(current_warnings - prior_warnings),
        "warning_ids_removed": sorted(prior_warnings - current_warnings),
        "current_sha256": current["sha256"],
        "prior_sha256": prior["sha256"],
        "prior_receipt_integrity": prior_integrity,
        "privacy_note": "Comparison contains fixed fields and hashes only. It excludes both receipt paths, filenames, file contents, signer text, integrity public keys, and archive entry names.",
        "limitations": [
            "A valid local integrity seal detects receipt edits but is not a public code-signing certificate.",
            "An exact fixed-field match does not prove a file is safe.",
            "Comparison runs locally and is not uploaded automatically.",
        ],
    }


def comparison_summary(comparison):
    comparison = dict(comparison or {})
    verdict = str(comparison.get("verdict", "unknown")).replace("_", " ").upper()
    change_ids = comparison.get("change_ids") or []
    lines = [
        "VaultLink Verification Receipt Comparison",
        f"Result: {verdict}",
        f"Same calculated SHA-256: {'YES' if comparison.get('same_sha256') else 'NO'}",
        f"Prior receipt integrity: {INTEGRITY_LABELS.get(comparison.get('prior_receipt_integrity'), 'UNKNOWN')}",
        f"Changed fixed fields: {len(change_ids)}",
    ]
    for change_id in change_ids:
        lines.append(f"- {COMPARISON_LABELS.get(change_id, change_id)}")
    if not change_ids:
        lines.append("- none")
    lines.extend(
        [
            "",
            "A valid integrity seal detects receipt edits but is not a public code-signing certificate.",
            "An exact comparison does not prove a file is safe.",
        ]
    )
    return "\n".join(lines)


def _receipt_extension_category(extension):
    value = str(extension or "").strip().lower()
    if value == "[none]":
        return "none"
    if value in RISKY_EXTENSIONS:
        return "executable_or_script"
    if any(value in extensions for extensions in TYPE_EXTENSIONS.values()):
        return "recognized"
    return "other"


def build_receipt_inspection_report(receipt):
    receipt = dict(receipt or {})
    sha256 = str(receipt.get("sha256", "")).strip().lower()
    integrity_state = str(receipt.get("integrity_state", "")).strip()
    if not SHA256_RE.fullmatch(sha256):
        raise ValueError("The normalized receipt hash is invalid.")
    if integrity_state not in INTEGRITY_LABELS:
        raise ValueError("The normalized receipt integrity state is invalid.")
    size_value = str(receipt.get("size_band", "unknown"))
    size_value = size_value if size_value in RECEIPT_SIZE_BANDS else "unknown"
    signature_state = str(receipt.get("signature_state", "unknown"))
    if signature_state not in RECEIPT_STRING_STATES["signature_state"]:
        signature_state = "unknown"
    defender_state = str(receipt.get("defender_state", "inconclusive"))
    if defender_state not in RECEIPT_STRING_STATES["defender_state"]:
        defender_state = "inconclusive"
    structure = receipt.get("structure") if isinstance(receipt.get("structure"), dict) else {}
    detected_type = str(structure.get("detected_type", "unknown")).lower()
    if detected_type not in TYPE_EXTENSIONS and detected_type != "unknown":
        detected_type = "unknown"
    extension_match = str(structure.get("extension_header_match", "not_mapped"))
    if extension_match not in RECEIPT_STRING_STATES["extension_header_match"]:
        extension_match = "not_mapped"
    pe_architecture = str(structure.get("pe_architecture", "unknown"))
    if pe_architecture not in RECEIPT_PE_ARCHITECTURES:
        pe_architecture = "unknown"
    warnings = _normalized_warning_ids(structure.get("warning_ids"))
    archive = structure.get("archive") if isinstance(structure.get("archive"), dict) else None
    archive_report = None
    if archive is not None:
        declared_band = str(archive.get("declared_size_band", "unknown"))
        if declared_band not in RECEIPT_ARCHIVE_SIZE_BANDS:
            declared_band = "unknown"
        archive_report = {
            "entry_count": _bounded_receipt_count(archive.get("entry_count")),
            "reviewed_entry_count": _bounded_receipt_count(
                archive.get("reviewed_entry_count")
            ),
            "declared_size_band": declared_band,
            "warning_ids": _normalized_warning_ids(archive.get("warning_ids")),
            "review_truncated": bool(archive.get("review_truncated")),
        }
    return {
        "schema_version": 1,
        "report_type": "vaultlink-download-receipt-inspection",
        "inspected_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "integrity_state": integrity_state,
        "sha256": sha256,
        "size_band": size_value,
        "extension_category": _receipt_extension_category(receipt.get("extension")),
        "signature_state": signature_state,
        "defender_state": defender_state,
        "structure": {
            "detected_type": detected_type,
            "extension_header_match": extension_match,
            "pe_architecture": pe_architecture,
            "warning_ids": warnings,
            "archive": archive_report,
        },
        "privacy_note": "This fixed-field inspection excludes the receipt path, filename, unknown fields, signer text, signer fingerprint, integrity public key, archive entry names, and file contents.",
        "limitations": [
            "A valid integrity seal detects receipt edits but is not a public code-signing certificate.",
            "An unsealed legacy receipt may have been edited.",
            "Receipt inspection does not rescan the original file or prove that it is safe.",
            "Inspection runs locally and is not uploaded automatically.",
        ],
    }


def receipt_inspection_summary(report):
    report = dict(report or {})
    structure = report.get("structure") if isinstance(report.get("structure"), dict) else {}
    warning_ids = structure.get("warning_ids") or []
    archive = structure.get("archive") if isinstance(structure.get("archive"), dict) else None
    lines = [
        "VaultLink Verification Receipt Inspection",
        f"Inspected: {report.get('inspected_at_utc', 'unknown')}",
        f"Integrity: {INTEGRITY_LABELS.get(report.get('integrity_state'), 'UNKNOWN')}",
        f"SHA-256: {report.get('sha256', 'unknown')}",
        f"Size band: {report.get('size_band', 'unknown')}",
        f"Extension category: {str(report.get('extension_category', 'other')).replace('_', ' ').upper()}",
        f"Digital signature state: {str(report.get('signature_state', 'unknown')).replace('_', ' ').upper()}",
        f"Defender state: {str(report.get('defender_state', 'inconclusive')).replace('_', ' ').upper()}",
        f"Detected type: {str(structure.get('detected_type', 'unknown')).replace('_', ' ').upper()}",
        f"Fixed structural warnings: {len(warning_ids)}",
        f"Archive summary present: {'YES' if archive else 'NO'}",
        "",
        "This inspection did not rescan the original file and does not prove that it is safe.",
        "The receipt path, filename, signer text, public key, unknown fields, and file contents are excluded.",
    ]
    return "\n".join(lines)


def _is_link_or_junction(path):
    selected = Path(path)
    return selected.is_symlink() or (
        hasattr(selected, "is_junction") and selected.is_junction()
    )


def _local_receipt_display_name(value):
    text = "".join(
        character if character.isprintable() and character not in "\r\n\t" else " "
        for character in str(value or "")
    ).strip()
    return text[:180] or "[unnamed]"


def filter_receipt_folder_local_details(
    details,
    query="",
    category="all",
    level="all",
    sort_mode="filename",
    reviewed_ids=None,
    hide_reviewed=False,
    session_state="all",
):
    if category not in FOLDER_REVIEW_FILTER_STATUSES:
        raise ValueError("Choose a recognized local receipt-review filter.")
    if level not in FOLDER_REVIEW_LEVELS:
        raise ValueError("Choose a recognized local receipt-review priority level.")
    if sort_mode not in FOLDER_REVIEW_SORT_MODES:
        raise ValueError("Choose a recognized local receipt-review sort mode.")
    if not isinstance(hide_reviewed, bool):
        raise ValueError("Choose a recognized local receipt-review visibility mode.")
    if session_state not in FOLDER_REVIEW_SESSION_STATES:
        raise ValueError("Choose a recognized local receipt-review session state.")
    try:
        reviewed_iterator = iter(()) if reviewed_ids is None else iter(reviewed_ids)
    except TypeError as exc:
        raise ValueError("Review-session IDs must be a bounded iterable.") from exc
    safe_reviewed_ids = {
        value
        for value in islice(reviewed_iterator, MAX_RECEIPT_FOLDER_ENTRIES)
        if type(value) is int and 0 <= value < MAX_RECEIPT_FOLDER_ENTRIES
    }
    query_text = "".join(
        character if character.isprintable() and character not in "\r\n\t" else " "
        for character in str(query or "")[:80]
    ).strip().casefold()
    allowed_statuses = FOLDER_REVIEW_FILTER_STATUSES[category]
    filtered = []
    try:
        detail_iterator = iter(()) if details is None else iter(details)
    except TypeError as exc:
        raise ValueError("Local receipt-review rows must be a bounded iterable.") from exc
    for raw_detail in islice(detail_iterator, MAX_RECEIPT_FOLDER_ENTRIES):
        if not isinstance(raw_detail, dict):
            continue
        status = str(raw_detail.get("status", ""))
        if status not in FOLDER_REVIEW_STATUS_LABELS or status not in allowed_statuses:
            continue
        if level != "all" and FOLDER_REVIEW_TRIAGE[status]["level"] != level:
            continue
        name = _local_receipt_display_name(raw_detail.get("name"))
        if query_text and query_text not in name.casefold():
            continue
        filtered_detail = {"name": name, "status": status}
        review_id = raw_detail.get("review_id")
        is_reviewed = False
        if type(review_id) is int and 0 <= review_id < MAX_RECEIPT_FOLDER_ENTRIES:
            is_reviewed = review_id in safe_reviewed_ids
            filtered_detail["review_id"] = review_id
            filtered_detail["reviewed"] = is_reviewed
        if hide_reviewed and is_reviewed:
            continue
        if session_state == "pending" and is_reviewed:
            continue
        if session_state == "reviewed" and not is_reviewed:
            continue
        filtered.append(filtered_detail)
    if sort_mode == "priority":
        def sort_key(item):
            guidance = FOLDER_REVIEW_TRIAGE[item["status"]]
            return (
                FOLDER_REVIEW_TRIAGE_PRIORITY[guidance["level"]],
                item["name"].casefold(),
                FOLDER_REVIEW_STATUS_LABELS[item["status"]].casefold(),
            )
    elif sort_mode == "result":
        def sort_key(item):
            return (
                FOLDER_REVIEW_STATUS_LABELS[item["status"]].casefold(),
                item["name"].casefold(),
            )
    else:
        def sort_key(item):
            return (
                item["name"].casefold(),
                FOLDER_REVIEW_STATUS_LABELS[item["status"]].casefold(),
            )
    return sorted(filtered, key=sort_key)


def apply_receipt_folder_review_marks(reviewed_ids, review_ids, reviewed):
    if not isinstance(reviewed, bool):
        raise ValueError("Choose a recognized local receipt-review mark.")
    try:
        reviewed_iterator = iter(()) if reviewed_ids is None else iter(reviewed_ids)
        review_iterator = iter(()) if review_ids is None else iter(review_ids)
    except TypeError as exc:
        raise ValueError("Review-session IDs must be bounded iterables.") from exc
    safe_reviewed_ids = {
        value
        for value in islice(reviewed_iterator, MAX_RECEIPT_FOLDER_ENTRIES)
        if type(value) is int and 0 <= value < MAX_RECEIPT_FOLDER_ENTRIES
    }
    changes = []
    seen = set()
    for review_id in islice(review_iterator, MAX_RECEIPT_FOLDER_ENTRIES):
        if (
            type(review_id) is not int
            or not 0 <= review_id < MAX_RECEIPT_FOLDER_ENTRIES
            or review_id in seen
        ):
            continue
        seen.add(review_id)
        was_reviewed = review_id in safe_reviewed_ids
        if was_reviewed == reviewed:
            continue
        changes.append((review_id, was_reviewed))
        if reviewed:
            safe_reviewed_ids.add(review_id)
        else:
            safe_reviewed_ids.remove(review_id)
    return safe_reviewed_ids, tuple(changes)


def receipt_folder_review_triage(status):
    key = str(status or "")
    if key not in FOLDER_REVIEW_TRIAGE:
        raise ValueError("Choose a recognized local receipt-review result.")
    return dict(FOLDER_REVIEW_TRIAGE[key])


def receipt_folder_review_guidance_text(status):
    key = str(status or "")
    guidance = receipt_folder_review_triage(key)
    return "\n".join(
        (
            f"Priority: {guidance['level_label']}",
            f"Result: {FOLDER_REVIEW_STATUS_LABELS[key]}",
            f"Meaning: {guidance['meaning']}",
            f"Next safe step: {guidance['next_action']}",
        )
    )


def receipt_folder_review_session_summary(details, reviewed_ids=None):
    rows = filter_receipt_folder_local_details(
        details,
        reviewed_ids=reviewed_ids,
    )
    summary = {
        "total_results": len(rows),
        "reviewed": 0,
        "pending": 0,
        "action_required_pending": 0,
        "review_pending": 0,
        "info_pending": 0,
        "valid_pending": 0,
        "actionable_pending": 0,
    }
    for row in rows:
        if row.get("reviewed"):
            summary["reviewed"] += 1
            continue
        summary["pending"] += 1
        level = FOLDER_REVIEW_TRIAGE[row["status"]]["level"]
        if level == "critical":
            summary["action_required_pending"] += 1
            summary["actionable_pending"] += 1
        elif level == "review":
            summary["review_pending"] += 1
            summary["actionable_pending"] += 1
        elif level == "info":
            summary["info_pending"] += 1
        elif level == "good":
            summary["valid_pending"] += 1
    return summary


def _audit_receipt_folder_core(path, include_local_details):
    selected = Path(path)
    if _is_link_or_junction(selected):
        raise ValueError("Linked or junction receipt folders are not accepted.")
    if not selected.is_dir():
        raise ValueError("Choose one ordinary folder containing VaultLink receipts.")
    counts = {
        "entries_seen": 0,
        "json_candidates": 0,
        "receipts_inspected": 0,
        "valid_this_profile": 0,
        "valid_other_profile": 0,
        "unsealed_legacy": 0,
        "invalid_or_tampered": 0,
        "links_or_junctions_skipped": 0,
        "oversized_receipts_skipped": 0,
        "other_entries_skipped": 0,
    }
    local_details = []

    def add_detail(child, status):
        if include_local_details:
            local_details.append(
                {
                    "name": _local_receipt_display_name(child.name),
                    "status": status,
                }
            )

    bytes_considered = 0
    entry_limit_reached = False
    candidate_limit_reached = False
    byte_limit_reached = False
    for child in selected.iterdir():
        if counts["entries_seen"] >= MAX_RECEIPT_FOLDER_ENTRIES:
            entry_limit_reached = True
            break
        counts["entries_seen"] += 1
        try:
            if _is_link_or_junction(child):
                counts["links_or_junctions_skipped"] += 1
                add_detail(child, "link_or_junction_skipped")
                continue
            if child.is_dir():
                counts["other_entries_skipped"] += 1
                add_detail(child, "subfolder_skipped")
                continue
            if not child.is_file() or child.suffix.lower() != ".json":
                counts["other_entries_skipped"] += 1
                add_detail(child, "non_json_skipped")
                continue
            if counts["json_candidates"] >= MAX_RECEIPT_FOLDER_JSON_FILES:
                candidate_limit_reached = True
                add_detail(child, "candidate_limit_not_inspected")
                break
            counts["json_candidates"] += 1
            size = int(child.stat().st_size)
            if size > MAX_RECEIPT_BYTES:
                counts["oversized_receipts_skipped"] += 1
                add_detail(child, "oversized_skipped")
                continue
            if bytes_considered + size > MAX_RECEIPT_FOLDER_BYTES:
                byte_limit_reached = True
                add_detail(child, "byte_limit_not_inspected")
                break
            bytes_considered += size
            try:
                receipt = load_verification_receipt(child)
            except Exception:
                counts["invalid_or_tampered"] += 1
                add_detail(child, "invalid_or_tampered")
                continue
            integrity_state = receipt.get("integrity_state")
            if integrity_state not in INTEGRITY_LABELS:
                counts["invalid_or_tampered"] += 1
                add_detail(child, "invalid_or_tampered")
                continue
            counts["receipts_inspected"] += 1
            counts[integrity_state] += 1
            add_detail(child, integrity_state)
        except OSError:
            counts["invalid_or_tampered"] += 1
            add_detail(child, "read_error")
    report = {
        "schema_version": 1,
        "report_type": "vaultlink-receipt-folder-audit",
        "audited_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": "selected_folder_top_level_only",
        "limits": {
            "maximum_top_level_entries": MAX_RECEIPT_FOLDER_ENTRIES,
            "maximum_json_candidates": MAX_RECEIPT_FOLDER_JSON_FILES,
            "maximum_cumulative_receipt_bytes": MAX_RECEIPT_FOLDER_BYTES,
            "maximum_single_receipt_bytes": MAX_RECEIPT_BYTES,
        },
        "counts": counts,
        "bytes_considered": bytes_considered,
        "entry_limit_reached": entry_limit_reached,
        "candidate_limit_reached": candidate_limit_reached,
        "byte_limit_reached": byte_limit_reached,
        "privacy_note": "This aggregate report excludes the selected folder path, receipt filenames, receipt contents, hashes, signer data, public keys, and validation error text.",
        "limitations": [
            "Only top-level JSON files in the explicitly selected folder are considered.",
            "Invalid results may include malformed, unsupported, changed, or tampered receipts.",
            "An unsealed legacy receipt may have been edited.",
            "The audit does not rescan original downloads or prove that any file is safe.",
            "The audit runs locally and is not uploaded automatically.",
        ],
    }
    return report, local_details


def audit_receipt_folder(path):
    report, _local_details = _audit_receipt_folder_core(
        path,
        include_local_details=False,
    )
    return report


def audit_receipt_folder_with_local_details(path):
    return _audit_receipt_folder_core(path, include_local_details=True)


def receipt_folder_audit_summary(report):
    counts = report.get("counts") if isinstance(report.get("counts"), dict) else {}
    return "\n".join(
        [
            "VaultLink Receipt Folder Audit",
            f"Audited: {report.get('audited_at_utc', 'unknown')}",
            "Scope: selected folder top level only",
            f"JSON candidates: {counts.get('json_candidates', 0)}",
            f"Receipts inspected: {counts.get('receipts_inspected', 0)}",
            f"Valid local seals: {counts.get('valid_this_profile', 0)}",
            f"Valid external seals: {counts.get('valid_other_profile', 0)}",
            f"Unsealed legacy receipts: {counts.get('unsealed_legacy', 0)}",
            f"Invalid or tampered: {counts.get('invalid_or_tampered', 0)}",
            f"Links or junctions skipped: {counts.get('links_or_junctions_skipped', 0)}",
            f"Oversized receipts skipped: {counts.get('oversized_receipts_skipped', 0)}",
            f"Entry limit reached: {'YES' if report.get('entry_limit_reached') else 'NO'}",
            f"Candidate limit reached: {'YES' if report.get('candidate_limit_reached') else 'NO'}",
            f"Byte limit reached: {'YES' if report.get('byte_limit_reached') else 'NO'}",
            "",
            "No folder path, receipt filename, receipt content, hash, signer data, public key, or validation error text is included.",
            "This audit does not rescan original files or prove that they are safe.",
        ]
    )


def _file_identity(path):
    stat = Path(path).stat()
    return {
        "size": int(stat.st_size),
        "mtime_ns": int(stat.st_mtime_ns),
        "inode": int(getattr(stat, "st_ino", 0)),
    }


def validate_selected_file(path):
    selected = Path(path)
    if selected.is_symlink():
        raise ValueError("Linked files are not accepted. Choose the real downloaded file.")
    if not selected.is_file():
        raise ValueError("Choose one ordinary file.")
    identity = _file_identity(selected)
    if identity["size"] > MAX_FILE_BYTES:
        raise ValueError("That file is larger than the 8 GB verification limit.")
    return selected, identity


def compute_file_sha256(path):
    selected, before = validate_selected_file(path)
    digest = hashlib.sha256()
    read_bytes = 0
    with selected.open("rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            read_bytes += len(chunk)
            if read_bytes > MAX_FILE_BYTES:
                raise ValueError("The file grew beyond the 8 GB verification limit.")
            digest.update(chunk)
    after = _file_identity(selected)
    if before != after or read_bytes != before["size"]:
        raise ValueError("The file changed while it was being verified. Close its downloader and try again.")
    return {
        "sha256": digest.hexdigest(),
        "size_bytes": read_bytes,
        "size_band": size_band(read_bytes),
        "extension": selected.suffix.lower()[:24] or "[none]",
    }


def _looks_like_text(sample):
    if not sample or b"\x00" in sample:
        return False
    printable = sum(
        byte in {9, 10, 13} or 32 <= byte <= 126
        for byte in sample
    )
    return printable / len(sample) >= 0.90


def detect_file_header(path):
    selected, identity = validate_selected_file(path)
    with selected.open("rb") as handle:
        sample = handle.read(4096)
        if sample.startswith(b"MZ"):
            if len(sample) < 64:
                return {"detected_type": "dos_mz_or_invalid_pe", "pe_architecture": "unknown", "malformed_pe": True}
            pe_offset = struct.unpack("<I", sample[60:64])[0]
            if pe_offset > min(max(identity["size"] - 6, 0), 1024 * 1024):
                return {"detected_type": "dos_mz_or_invalid_pe", "pe_architecture": "unknown", "malformed_pe": True}
            handle.seek(pe_offset)
            pe_header = handle.read(6)
            if len(pe_header) != 6 or pe_header[:4] != b"PE\x00\x00":
                return {"detected_type": "dos_mz_or_invalid_pe", "pe_architecture": "unknown", "malformed_pe": True}
            machine = struct.unpack("<H", pe_header[4:6])[0]
            return {
                "detected_type": "windows_pe",
                "pe_architecture": PE_ARCHITECTURES.get(machine, f"unknown-0x{machine:04x}"),
                "malformed_pe": False,
            }
    if sample.startswith(WINDOWS_SHORTCUT_HEADER):
        detected_type = "windows_shortcut"
    elif zipfile.is_zipfile(selected):
        detected_type = "zip_archive"
    elif sample.startswith(b"%PDF-"):
        detected_type = "pdf"
    elif sample.startswith(b"\x89PNG\r\n\x1a\n"):
        detected_type = "png"
    elif sample.startswith(b"\xff\xd8\xff"):
        detected_type = "jpeg"
    elif sample.startswith((b"GIF87a", b"GIF89a")):
        detected_type = "gif"
    elif sample.startswith(b"7z\xbc\xaf'\x1c"):
        detected_type = "seven_zip"
    elif sample.startswith(b"Rar!\x1a\x07"):
        detected_type = "rar"
    elif sample.startswith(b"\x1f\x8b"):
        detected_type = "gzip"
    elif sample.startswith(b"\x7fELF"):
        detected_type = "elf"
    elif sample.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        detected_type = "ole_compound"
    elif _looks_like_text(sample):
        detected_type = "text"
    else:
        detected_type = "unknown"
    return {
        "detected_type": detected_type,
        "pe_architecture": "not_applicable",
        "malformed_pe": False,
    }


def extension_header_match(extension, detected_type):
    extension = str(extension or "").lower()
    expected = TYPE_EXTENSIONS.get(str(detected_type))
    if not expected or not extension:
        return "not_mapped"
    return "match" if extension in expected else "mismatch"


def inspect_zip_structure(path):
    selected, before = validate_selected_file(path)
    summary = {
        "reviewed": True,
        "entry_count": 0,
        "reviewed_entry_count": 0,
        "declared_size_band": "under 1 MB",
        "traversal_entry_count": 0,
        "link_entry_count": 0,
        "encrypted_entry_count": 0,
        "executable_entry_count": 0,
        "nested_archive_count": 0,
        "macro_entry_count": 0,
        "high_compression_entry_count": 0,
        "review_truncated": False,
        "warning_ids": [],
    }
    try:
        with zipfile.ZipFile(selected, "r") as archive:
            entries = archive.infolist()
            summary["entry_count"] = len(entries)
            reviewed = entries[:MAX_ARCHIVE_ENTRIES]
            summary["reviewed_entry_count"] = len(reviewed)
            summary["review_truncated"] = len(entries) > len(reviewed)
            total_declared = 0
            total_compressed = 0
            for info in reviewed:
                if info.is_dir():
                    continue
                total_declared += max(0, int(info.file_size))
                total_compressed += max(0, int(info.compress_size))
                normalized = str(info.filename).replace("\\", "/")
                parts = [part for part in normalized.split("/") if part not in {"", "."}]
                if (
                    normalized.startswith(("/", "\\"))
                    or re.match(r"(?i)^[a-z]:", normalized)
                    or ".." in parts
                ):
                    summary["traversal_entry_count"] += 1
                mode = (int(info.external_attr) >> 16) & 0xFFFF
                if mode and stat.S_ISLNK(mode):
                    summary["link_entry_count"] += 1
                if int(info.flag_bits) & 0x1:
                    summary["encrypted_entry_count"] += 1
                lowered = normalized.lower()
                suffix = Path(lowered).suffix
                if suffix in RISKY_EXTENSIONS:
                    summary["executable_entry_count"] += 1
                if suffix in NESTED_ARCHIVE_EXTENSIONS:
                    summary["nested_archive_count"] += 1
                if lowered.endswith("vbaproject.bin"):
                    summary["macro_entry_count"] += 1
                ratio = int(info.file_size) / max(1, int(info.compress_size))
                if int(info.file_size) >= HIGH_COMPRESSION_MIN_BYTES and ratio >= HIGH_COMPRESSION_RATIO:
                    summary["high_compression_entry_count"] += 1
            summary["declared_size_band"] = archive_size_band(total_declared)
            if total_declared > MAX_ARCHIVE_DECLARED_BYTES:
                summary["warning_ids"].append("archive_declared_size_over_50gb")
            if summary["review_truncated"]:
                summary["warning_ids"].append("archive_entry_review_truncated")
            warning_fields = (
                ("traversal_entry_count", "archive_traversal_paths"),
                ("link_entry_count", "archive_links"),
                ("encrypted_entry_count", "archive_encrypted_entries"),
                ("executable_entry_count", "archive_executable_entries"),
                ("nested_archive_count", "archive_nested_archives"),
                ("macro_entry_count", "archive_office_macros"),
                ("high_compression_entry_count", "archive_extreme_compression"),
            )
            for field, warning_id in warning_fields:
                if summary[field]:
                    summary["warning_ids"].append(warning_id)
            if total_compressed == 0 and total_declared > 0:
                summary["warning_ids"].append("archive_zero_compressed_size")
    except zipfile.BadZipFile as exc:
        raise ValueError("The file looked like ZIP data but its central directory was unreadable.") from exc
    if before != _file_identity(selected):
        raise ValueError("The file changed during its bounded ZIP structure review.")
    summary["warning_ids"] = sorted(set(summary["warning_ids"]))
    return summary


def inspect_file_structure(path):
    selected, before = validate_selected_file(path)
    header = detect_file_header(selected)
    extension = selected.suffix.lower()[:24] or "[none]"
    suffixes = [suffix.lower() for suffix in selected.suffixes]
    double_extension = (
        len(suffixes) >= 2
        and suffixes[-1] in RISKY_EXTENSIONS
        and any(suffix in DECOY_EXTENSIONS for suffix in suffixes[:-1])
    )
    match_state = extension_header_match(extension, header["detected_type"])
    warning_ids = []
    if extension in RISKY_EXTENSIONS:
        warning_ids.append("executable_or_script_extension")
    if double_extension:
        warning_ids.append("misleading_double_extension")
    if match_state == "mismatch":
        warning_ids.append("extension_header_mismatch")
    if header.get("malformed_pe"):
        warning_ids.append("malformed_pe_header")
    if header["detected_type"] == "windows_shortcut":
        warning_ids.append("windows_shortcut")
    if extension in {".docm", ".xlsm", ".pptm"}:
        warning_ids.append("macro_enabled_office_extension")
    archive = None
    if header["detected_type"] == "zip_archive":
        archive = inspect_zip_structure(selected)
        warning_ids.extend(archive["warning_ids"])
    if before != _file_identity(selected):
        raise ValueError("The file changed during its structure review.")
    return {
        "detected_type": header["detected_type"],
        "extension": extension,
        "extension_header_match": match_state,
        "pe_architecture": header["pe_architecture"],
        "double_extension": double_extension,
        "warning_ids": sorted(set(warning_ids)),
        "archive": archive,
    }


def _powershell_executable():
    if locker.POWERSHELL.is_file():
        return locker.POWERSHELL
    raise ValueError("Windows PowerShell was not found.")


def inspect_authenticode_signature(path):
    selected, before = validate_selected_file(path)
    escaped_path = str(selected).replace("'", "''")
    script = f"""
$path = '{escaped_path}'
$signature = Get-AuthenticodeSignature -LiteralPath $path
[pscustomobject]@{{
    Status = [string]$signature.Status
    StatusMessage = [string]$signature.StatusMessage
    Subject = if ($signature.SignerCertificate) {{ [string]$signature.SignerCertificate.Subject }} else {{ '' }}
    Issuer = if ($signature.SignerCertificate) {{ [string]$signature.SignerCertificate.Issuer }} else {{ '' }}
}} | ConvertTo-Json -Compress
"""
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    completed = subprocess.run(
        [
            str(_powershell_executable()),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded,
        ],
        cwd=str(selected.parent),
        capture_output=True,
        text=True,
        timeout=SIGNATURE_TIMEOUT_SECONDS,
        check=False,
        creationflags=flags,
    )
    if before != _file_identity(selected):
        raise ValueError("The file changed during its digital-signature check.")
    if completed.returncode != 0:
        raise ValueError("Windows could not inspect the file's digital signature.")
    line = next((item.strip() for item in completed.stdout.splitlines() if item.strip().startswith("{")), "")
    try:
        payload = json.loads(line)
    except Exception as exc:
        raise ValueError("Windows returned an unreadable digital-signature result.") from exc
    raw_status = str(payload.get("Status", "Unknown")).strip()[:80] or "Unknown"
    normalized = raw_status.lower()
    if normalized == "valid":
        state = "valid"
        label = "Valid Windows digital signature"
    elif normalized == "notsigned":
        state = "unsigned"
        label = "Not digitally signed"
    else:
        state = "attention"
        label = f"Not valid or unsupported: {raw_status}"
    return {
        "state": state,
        "status": raw_status,
        "label": label,
        "status_message": str(payload.get("StatusMessage", "")).strip()[:300],
        "signer_subject": str(payload.get("Subject", "")).strip()[:300],
        "signer_issuer": str(payload.get("Issuer", "")).strip()[:300],
    }


def verify_download(path, expected_sha256=""):
    expected = normalize_expected_sha256(expected_sha256)
    hash_result = compute_file_sha256(path)
    structure = inspect_file_structure(path)
    signature = inspect_authenticode_signature(path)
    if not expected:
        comparison = "not_provided"
    elif expected == hash_result["sha256"]:
        comparison = "match"
    else:
        comparison = "mismatch"
    return {
        **hash_result,
        "expected_sha256_provided": bool(expected),
        "hash_comparison": comparison,
        "structure": structure,
        "signature": signature,
        "verified_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def defender_executable():
    platform_root = (
        Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        / "Microsoft"
        / "Windows Defender"
        / "Platform"
    )
    candidates = []
    if platform_root.is_dir():
        candidates.extend(sorted(platform_root.glob("*/MpCmdRun.exe"), reverse=True))
    candidates.append(
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
        / "Windows Defender"
        / "MpCmdRun.exe"
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise ValueError("Microsoft Defender command-line scanner was not found.")


def scan_file_with_defender(path):
    selected, before = validate_selected_file(path)
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    completed = subprocess.run(
        [
            str(defender_executable()),
            "-Scan",
            "-ScanType",
            "3",
            "-File",
            str(selected),
            "-DisableRemediation",
        ],
        cwd=str(selected.parent),
        capture_output=True,
        text=True,
        timeout=DEFENDER_TIMEOUT_SECONDS,
        check=False,
        creationflags=flags,
    )
    if before != _file_identity(selected):
        raise ValueError("The file changed during its Defender scan.")
    combined = f"{completed.stdout}\n{completed.stderr}".strip()
    lowered = combined.lower()
    if completed.returncode == 0 and "no threats" in lowered:
        return {
            "state": "no_threats",
            "label": "Microsoft Defender reported no threats",
            "scan_mode": "custom file scan with remediation disabled",
        }
    if "threat" in lowered and "no threats" not in lowered:
        return {
            "state": "attention",
            "label": "Microsoft Defender reported a threat or required attention",
            "scan_mode": "custom file scan with remediation disabled",
        }
    return {
        "state": "inconclusive",
        "label": "Microsoft Defender did not return a clear result",
        "scan_mode": "custom file scan with remediation disabled",
    }


def build_privacy_safe_receipt(result, defender=None):
    result = dict(result or {})
    signature = dict(result.get("signature") or {})
    structure = dict(result.get("structure") or {})
    archive = structure.get("archive") if isinstance(structure.get("archive"), dict) else None
    defender = dict(defender or {})
    return {
        "schema_version": 1,
        "report_type": "vaultlink-download-verification",
        "created_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sha256": str(result.get("sha256", "")),
        "size_band": str(result.get("size_band", "unknown")),
        "extension": str(result.get("extension", "[none]"))[:24],
        "expected_sha256_provided": bool(result.get("expected_sha256_provided")),
        "hash_comparison": str(result.get("hash_comparison", "not_provided")),
        "signature_state": str(signature.get("state", "unknown")),
        "signature_status": str(signature.get("status", "Unknown"))[:80],
        "signer_subject": str(signature.get("signer_subject", ""))[:300],
        "structure": {
            "detected_type": str(structure.get("detected_type", "unknown"))[:80],
            "extension_header_match": str(structure.get("extension_header_match", "not_mapped"))[:40],
            "pe_architecture": str(structure.get("pe_architecture", "not_applicable"))[:40],
            "double_extension": bool(structure.get("double_extension")),
            "warning_ids": [
                str(value)[:80]
                for value in structure.get("warning_ids", [])
                if isinstance(value, str)
            ][:20],
            "archive": (
                {
                    key: archive.get(key)
                    for key in (
                        "entry_count",
                        "reviewed_entry_count",
                        "declared_size_band",
                        "traversal_entry_count",
                        "link_entry_count",
                        "encrypted_entry_count",
                        "executable_entry_count",
                        "nested_archive_count",
                        "macro_entry_count",
                        "high_compression_entry_count",
                        "review_truncated",
                        "warning_ids",
                    )
                }
                if archive is not None
                else None
            ),
        },
        "defender_state": str(defender.get("state", "not_run")),
        "defender_scan_mode": str(defender.get("scan_mode", "not run"))[:120],
        "privacy_note": "The receipt excludes the filename, path, Windows username, file contents, archive entry names, and Defender command output.",
        "limitations": [
            "A matching hash proves only that the bytes match the expected hash.",
            "A valid signature identifies a signer but does not guarantee the file is harmless.",
            "A Defender no-threat result is not proof that a file is safe.",
            "Header and ZIP structure checks are bounded warning signals, not malware detection.",
            "VaultLink does not upload the selected file or this receipt automatically.",
        ],
    }


def verification_summary(result, defender=None, comparison=None):
    receipt = build_privacy_safe_receipt(result, defender)
    hash_comparison = receipt["hash_comparison"].replace("_", " ").upper()
    signature = receipt["signature_state"].replace("_", " ").upper()
    defender_state = receipt["defender_state"].replace("_", " ").upper()
    structure = receipt["structure"]
    warning_count = len(structure["warning_ids"])
    lines = [
            "VaultLink Download Verification",
            f"Checked: {receipt['created_at_utc']}",
            f"File type: {receipt['extension']}",
            f"Size band: {receipt['size_band']}",
            f"SHA-256: {receipt['sha256']}",
            f"Expected hash: {hash_comparison}",
            f"Digital signature: {signature}",
            f"Detected type: {structure['detected_type']}",
            f"Extension/header: {structure['extension_header_match'].replace('_', ' ').upper()}",
            f"Structural warnings: {warning_count}",
            f"Microsoft Defender: {defender_state}",
            "",
            "A matching hash, valid signature, or no-threat scan does not guarantee a file is safe.",
            "The selected file was not uploaded by VaultLink.",
        ]
    if comparison:
        lines.extend(["", comparison_summary(comparison)])
    return "\n".join(lines)


class DownloadVerificationCenter(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VaultLink Download Verification Center")
        self.geometry("1120x960")
        self.minsize(1050, 950)
        self.configure(bg=locker.BG)
        self.selected_path = None
        self.result = None
        self.defender_result = None
        self.comparison_result = None
        self.inspection_result = None
        self.folder_audit_result = None
        self.folder_audit_local_details = []
        self.folder_review_window = None
        self.busy = False
        self.file_var = tk.StringVar(value="No file selected.")
        self.hash_var = tk.StringVar(value="Not calculated")
        self.compare_var = tk.StringVar(value="Expected hash not provided")
        self.signature_var = tk.StringVar(value="Not inspected")
        self.signer_var = tk.StringVar(value="No signer information")
        self.structure_var = tk.StringVar(value="Not inspected")
        self.warning_var = tk.StringVar(value="No structural review yet")
        self.archive_var = tk.StringVar(value="Not an inspected ZIP archive")
        self.defender_var = tk.StringVar(value="Not scanned")
        self.inspection_var = tk.StringVar(value="No receipt inspected")
        self.comparison_var = tk.StringVar(value="No prior receipt compared")
        self.folder_audit_var = tk.StringVar(value="No receipt folder audited")
        self.status_var = tk.StringVar(
            value="Choose one downloaded file, or inspect an existing VaultLink receipt."
        )
        self.expected_var = tk.StringVar(value="")
        self.progress = None
        self.verify_button = None
        self.defender_button = None
        self.copy_hash_button = None
        self.copy_summary_button = None
        self.export_button = None
        self.inspect_receipt_button = None
        self.copy_inspection_button = None
        self.compare_button = None
        self.export_comparison_button = None
        self.folder_audit_button = None
        self.export_folder_audit_button = None
        self.view_folder_review_button = None
        self.build_ui()

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=16)

        tk.Label(
            outer,
            text="Download Verification Center",
            bg=locker.BG,
            fg=locker.TEXT,
            font=("Segoe UI", 27, "bold"),
        ).pack(anchor="w")
        tk.Label(
            outer,
            text="Check the bytes, Windows signature, and Microsoft Defender result for one file you explicitly select.",
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 12))

        warning = tk.Frame(outer, bg="#2b2515")
        warning.pack(fill="x", pady=(0, 14))
        tk.Label(
            warning,
            text="LOCAL CHECKS ONLY | A matching hash, valid signature, or Defender no-threat result does not guarantee a file is safe.",
            bg="#2b2515",
            fg=locker.YELLOW,
            font=("Segoe UI", 9, "bold"),
            justify="left",
            wraplength=1040,
        ).pack(anchor="w", padx=14, pady=10)

        select_row = tk.Frame(outer, bg=locker.PANEL)
        select_row.pack(fill="x", pady=(0, 12))
        tk.Button(
            select_row,
            text="CHOOSE FILE",
            command=self.choose_file,
            bg=locker.WHITE,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=14, pady=14, ipadx=14, ipady=8)
        tk.Label(
            select_row,
            textvariable=self.file_var,
            bg=locker.PANEL,
            fg=locker.TEXT,
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(side="left", fill="x", expand=True, padx=(0, 14))

        expected = tk.Frame(outer, bg=locker.PANEL)
        expected.pack(fill="x", pady=(0, 12))
        tk.Label(
            expected,
            text="EXPECTED SHA-256, OPTIONAL",
            bg=locker.PANEL,
            fg=locker.MUTED,
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w", padx=14, pady=(12, 4))
        tk.Entry(
            expected,
            textvariable=self.expected_var,
            bg=locker.FIELD,
            fg=locker.TEXT,
            insertbackground=locker.TEXT,
            relief="flat",
            font=("Consolas", 10),
        ).pack(fill="x", padx=14, pady=(0, 12), ipady=7)

        actions = tk.Frame(outer, bg=locker.BG)
        actions.pack(fill="x", pady=(0, 12))
        self.verify_button = tk.Button(
            actions,
            text="VERIFY HASH + SIGNATURE",
            command=self.start_verification,
            bg=locker.GREEN,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            state="disabled",
        )
        self.verify_button.pack(side="left", ipadx=14, ipady=8)
        self.defender_button = tk.Button(
            actions,
            text="SCAN WITH DEFENDER",
            command=self.start_defender_scan,
            bg=locker.BLUE,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            state="disabled",
        )
        self.defender_button.pack(side="left", padx=(8, 0), ipadx=12, ipady=8)
        self.copy_hash_button = tk.Button(
            actions,
            text="COPY SHA-256",
            command=self.copy_hash,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            state="disabled",
        )
        self.copy_hash_button.pack(side="left", padx=(8, 0), ipadx=12, ipady=8)
        self.copy_summary_button = tk.Button(
            actions,
            text="COPY SAFE SUMMARY",
            command=self.copy_summary,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            state="disabled",
        )
        self.copy_summary_button.pack(side="left", padx=(8, 0), ipadx=12, ipady=8)
        self.export_button = tk.Button(
            actions,
            text="EXPORT SEALED RECEIPT",
            command=self.export_receipt,
            bg=locker.YELLOW,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            state="disabled",
        )
        self.export_button.pack(side="left", padx=(8, 0), ipadx=12, ipady=8)
        tk.Button(
            actions,
            text="WINDOWS SECURITY",
            command=self.open_windows_security,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right", ipadx=12, ipady=8)

        comparison_actions = tk.Frame(outer, bg=locker.BG)
        comparison_actions.pack(fill="x", pady=(0, 12))
        self.inspect_receipt_button = tk.Button(
            comparison_actions,
            text="INSPECT RECEIPT",
            command=self.inspect_receipt,
            bg=locker.GREEN,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        self.inspect_receipt_button.pack(side="left", ipadx=12, ipady=7)
        self.copy_inspection_button = tk.Button(
            comparison_actions,
            text="COPY RECEIPT CHECK",
            command=self.copy_receipt_inspection,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            state="disabled",
        )
        self.copy_inspection_button.pack(
            side="left",
            padx=(8, 0),
            ipadx=12,
            ipady=7,
        )
        self.compare_button = tk.Button(
            comparison_actions,
            text="COMPARE PRIOR RECEIPT",
            command=self.compare_prior_receipt,
            bg=locker.BLUE,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            state="disabled",
        )
        self.compare_button.pack(side="left", padx=(8, 0), ipadx=12, ipady=7)
        self.export_comparison_button = tk.Button(
            comparison_actions,
            text="EXPORT COMPARISON",
            command=self.export_comparison,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            state="disabled",
        )
        self.export_comparison_button.pack(side="left", padx=(8, 0), ipadx=12, ipady=7)

        folder_actions = tk.Frame(outer, bg=locker.BG)
        folder_actions.pack(fill="x", pady=(0, 12))
        self.folder_audit_button = tk.Button(
            folder_actions,
            text="AUDIT RECEIPT FOLDER",
            command=self.start_receipt_folder_audit,
            bg=locker.BLUE,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        self.folder_audit_button.pack(side="left", ipadx=12, ipady=7)
        self.export_folder_audit_button = tk.Button(
            folder_actions,
            text="EXPORT FOLDER AUDIT",
            command=self.export_receipt_folder_audit,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            state="disabled",
        )
        self.export_folder_audit_button.pack(
            side="left",
            padx=(8, 0),
            ipadx=12,
            ipady=7,
        )
        self.view_folder_review_button = tk.Button(
            folder_actions,
            text="VIEW LOCAL REVIEW",
            command=self.view_receipt_folder_review,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            state="disabled",
        )
        self.view_folder_review_button.pack(
            side="left",
            padx=(8, 0),
            ipadx=12,
            ipady=7,
        )
        tk.Label(
            folder_actions,
            textvariable=self.folder_audit_var,
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 8),
            anchor="w",
        ).pack(side="left", fill="x", expand=True, padx=(12, 0))

        results = tk.Frame(outer, bg=locker.PANEL)
        results.pack(fill="both", expand=True)
        tk.Label(
            results,
            text="VERIFICATION RESULTS",
            bg=locker.PANEL,
            fg=locker.TEXT,
            font=("Segoe UI", 17, "bold"),
        ).pack(anchor="w", padx=16, pady=(16, 8))
        for label, variable in (
            ("SHA-256", self.hash_var),
            ("EXPECTED HASH", self.compare_var),
            ("DIGITAL SIGNATURE", self.signature_var),
            ("SIGNER", self.signer_var),
            ("FILE STRUCTURE", self.structure_var),
            ("REVIEW SIGNALS", self.warning_var),
            ("ARCHIVE REVIEW", self.archive_var),
            ("MICROSOFT DEFENDER", self.defender_var),
            ("RECEIPT INSPECTION", self.inspection_var),
            ("RECEIPT COMPARISON", self.comparison_var),
        ):
            row = tk.Frame(results, bg=locker.PANEL)
            row.pack(fill="x", padx=16, pady=4)
            tk.Label(
                row,
                text=label,
                width=22,
                anchor="w",
                bg=locker.PANEL,
                fg=locker.MUTED,
                font=("Segoe UI", 8, "bold"),
            ).pack(side="left")
            tk.Label(
                row,
                textvariable=variable,
                anchor="w",
                justify="left",
                wraplength=760,
                bg=locker.PANEL,
                fg=locker.TEXT,
                font=("Segoe UI", 9),
            ).pack(side="left", fill="x", expand=True)

        self.progress = ttk.Progressbar(results, mode="indeterminate")
        self.progress.pack(fill="x", padx=16, pady=(16, 8))
        tk.Label(
            results,
            textvariable=self.status_var,
            bg=locker.PANEL,
            fg=locker.MUTED,
            font=("Segoe UI", 9),
            justify="left",
            wraplength=1020,
        ).pack(anchor="w", padx=16, pady=(0, 16))

    def choose_file(self):
        path_text = filedialog.askopenfilename(parent=self, title="Choose one downloaded file")
        if not path_text:
            return
        try:
            selected, identity = validate_selected_file(path_text)
            self.selected_path = selected
            self.result = None
            self.defender_result = None
            self.comparison_result = None
            self.file_var.set(f"{selected.name} | {locker.format_update_size(identity['size'])}")
            self.hash_var.set("Not calculated")
            self.compare_var.set("Expected hash not provided")
            self.signature_var.set("Not inspected")
            self.signer_var.set("No signer information")
            self.structure_var.set("Not inspected")
            self.warning_var.set("No structural review yet")
            self.archive_var.set("Not an inspected ZIP archive")
            self.defender_var.set("Not scanned")
            self.comparison_var.set("No prior receipt compared")
            self.verify_button.configure(state="normal")
            self.defender_button.configure(state="normal")
            self.copy_hash_button.configure(state="disabled")
            self.copy_summary_button.configure(state="disabled")
            self.export_button.configure(state="disabled")
            self.compare_button.configure(state="disabled")
            self.export_comparison_button.configure(state="disabled")
            self.status_var.set("File selected locally. Its path was not recorded or uploaded.")
            locker.log_event("download_verify_select", "local", "ok")
        except Exception as exc:
            locker.log_event("download_verify_select", "local", "failed")
            messagebox.showerror("Could not select file", str(exc), parent=self)

    def set_busy(self, busy, message):
        self.busy = bool(busy)
        if busy:
            self.progress.start(12)
            self.verify_button.configure(state="disabled")
            self.defender_button.configure(state="disabled")
            self.inspect_receipt_button.configure(state="disabled")
            self.folder_audit_button.configure(state="disabled")
        else:
            self.progress.stop()
            state = "normal" if self.selected_path else "disabled"
            self.verify_button.configure(state=state)
            self.defender_button.configure(state=state)
            self.inspect_receipt_button.configure(state="normal")
            self.folder_audit_button.configure(state="normal")
        self.status_var.set(message)

    def start_verification(self):
        if self.busy or not self.selected_path:
            return
        try:
            expected = normalize_expected_sha256(self.expected_var.get())
        except Exception as exc:
            messagebox.showerror("Expected hash is invalid", str(exc), parent=self)
            return
        selected = self.selected_path
        self.set_busy(True, "Calculating SHA-256, reviewing bounded file structure, and asking Windows to inspect the digital signature...")

        def worker():
            try:
                result = verify_download(selected, expected)
                self.after(0, lambda: self.finish_verification(result))
            except Exception as exc:
                self.after(
                    0,
                    lambda error=exc: self.finish_error(
                        "Verification failed",
                        error,
                        "download_verify_run",
                    ),
                )

        threading.Thread(target=worker, daemon=True).start()

    def finish_verification(self, result):
        self.result = result
        self.hash_var.set(result["sha256"])
        comparison = result["hash_comparison"]
        if comparison == "match":
            self.compare_var.set("MATCH - calculated SHA-256 equals the expected value")
        elif comparison == "mismatch":
            self.compare_var.set("MISMATCH - do not run the file until you verify the source")
        else:
            self.compare_var.set("Expected hash not provided")
        signature = result["signature"]
        self.signature_var.set(signature["label"])
        self.signer_var.set(signature["signer_subject"] or "No signer certificate reported")
        structure = result["structure"]
        warnings = structure["warning_ids"]
        detected = structure["detected_type"].replace("_", " ").upper()
        match_state = structure["extension_header_match"].replace("_", " ").upper()
        architecture = structure["pe_architecture"]
        architecture_text = "" if architecture == "not_applicable" else f" | {architecture}"
        self.structure_var.set(
            f"{detected}{architecture_text} | extension/header {match_state} | "
            f"{len(warnings)} fixed warning(s)"
        )
        labels = warning_labels(warnings)
        self.warning_var.set(" | ".join(labels) if labels else "No fixed structural warnings found")
        archive = structure.get("archive")
        if archive:
            self.archive_var.set(
                f"{archive['entry_count']} entries | {archive['reviewed_entry_count']} reviewed | "
                f"{len(archive['warning_ids'])} warning type(s) | declared {archive['declared_size_band']}"
            )
        else:
            self.archive_var.set("Not a ZIP-based format")
        self.copy_hash_button.configure(state="normal")
        self.copy_summary_button.configure(state="normal")
        self.export_button.configure(state="normal")
        self.compare_button.configure(state="normal")
        self.set_busy(False, "Verification finished locally. Review every result before deciding whether to use the file.")
        locker.log_event("download_verify_run", "local", "ok")

    def start_defender_scan(self):
        if self.busy or not self.selected_path:
            return
        selected = self.selected_path
        self.set_busy(True, "Running a Microsoft Defender custom file scan with remediation disabled...")

        def worker():
            try:
                result = scan_file_with_defender(selected)
                self.after(0, lambda: self.finish_defender_scan(result))
            except Exception as exc:
                self.after(
                    0,
                    lambda error=exc: self.finish_error(
                        "Defender scan failed",
                        error,
                        "download_verify_defender",
                    ),
                )

        threading.Thread(target=worker, daemon=True).start()

    def finish_defender_scan(self, result):
        self.defender_result = result
        self.defender_var.set(result["label"])
        if self.result:
            self.copy_summary_button.configure(state="normal")
            self.export_button.configure(state="normal")
        self.set_busy(False, "Defender scan finished. A no-threat result is not proof that a file is safe.")
        locker.log_event("download_verify_defender", "local", "ok")

    def finish_error(self, title, error, action):
        self.set_busy(False, str(error))
        locker.log_event(action, "local", "failed")
        messagebox.showerror(title, str(error), parent=self)

    def copy_hash(self):
        if not self.result:
            return
        self.clipboard_clear()
        self.clipboard_append(self.result["sha256"])
        self.update()
        self.status_var.set("Calculated SHA-256 copied.")
        locker.log_event("download_verify_copy_hash", "local", "ok")

    def copy_summary(self):
        if not self.result:
            return
        self.clipboard_clear()
        self.clipboard_append(
            verification_summary(self.result, self.defender_result, self.comparison_result)
        )
        self.update()
        self.status_var.set("Privacy-safe summary copied without the filename or path.")
        locker.log_event("download_verify_copy_summary", "local", "ok")

    def export_receipt(self):
        if not self.result:
            return
        path_text = filedialog.asksaveasfilename(
            parent=self,
            title="Export privacy-safe verification receipt",
            defaultextension=".json",
            initialfile="vaultlink-download-verification.json",
            filetypes=[("JSON file", "*.json")],
        )
        if not path_text:
            return
        try:
            receipt = seal_verification_receipt(
                build_privacy_safe_receipt(self.result, self.defender_result)
            )
            Path(path_text).write_text(json.dumps(receipt, indent=2), encoding="utf-8")
            self.status_var.set(
                "Locally sealed verification receipt exported. Its destination was not recorded."
            )
            locker.log_event("download_verify_export", "local", "ok")
        except Exception as exc:
            locker.log_event("download_verify_export", "local", "failed")
            messagebox.showerror("Could not export receipt", str(exc), parent=self)

    def inspect_receipt(self):
        if self.busy:
            return
        path_text = filedialog.askopenfilename(
            parent=self,
            title="Inspect a VaultLink verification receipt",
            filetypes=[("VaultLink JSON receipt", "*.json")],
        )
        if not path_text:
            return
        try:
            normalized = load_verification_receipt(path_text)
            self.inspection_result = build_receipt_inspection_report(normalized)
            integrity = INTEGRITY_LABELS[self.inspection_result["integrity_state"]]
            warning_count = len(
                self.inspection_result["structure"]["warning_ids"]
            )
            self.inspection_var.set(
                f"{integrity} | {warning_count} fixed structural warning(s)"
            )
            self.copy_inspection_button.configure(state="normal")
            self.status_var.set(
                "Receipt inspected locally. Unknown fields and its path were discarded."
            )
            locker.log_event("download_verify_inspect_receipt", "local", "ok")
        except Exception as exc:
            self.inspection_result = None
            self.inspection_var.set("Receipt inspection failed")
            self.copy_inspection_button.configure(state="disabled")
            locker.log_event("download_verify_inspect_receipt", "local", "failed")
            messagebox.showerror("Could not inspect receipt", str(exc), parent=self)

    def copy_receipt_inspection(self):
        if not self.inspection_result:
            return
        self.clipboard_clear()
        self.clipboard_append(receipt_inspection_summary(self.inspection_result))
        self.update()
        self.status_var.set(
            "Privacy-safe receipt inspection copied without its path or imported text."
        )
        locker.log_event("download_verify_copy_receipt_inspection", "local", "ok")

    def start_receipt_folder_audit(self):
        if self.busy:
            return
        path_text = filedialog.askdirectory(
            parent=self,
            title="Choose one folder containing VaultLink receipts",
        )
        if not path_text:
            return
        selected = Path(path_text)
        self.close_receipt_folder_review()
        self.folder_audit_result = None
        self.folder_audit_local_details = []
        self.export_folder_audit_button.configure(state="disabled")
        self.view_folder_review_button.configure(state="disabled")
        self.folder_audit_var.set("Receipt folder audit running")
        self.set_busy(
            True,
            "Auditing bounded top-level JSON receipts locally without opening subfolders...",
        )

        def worker():
            try:
                report, local_details = audit_receipt_folder_with_local_details(
                    selected
                )
                self.after(
                    0,
                    lambda: self.finish_receipt_folder_audit(
                        report,
                        local_details,
                    ),
                )
            except Exception as exc:
                self.after(
                    0,
                    lambda error=exc: self.finish_receipt_folder_audit_error(error),
                )

        threading.Thread(target=worker, daemon=True).start()

    def finish_receipt_folder_audit(self, report, local_details):
        self.folder_audit_result = report
        self.folder_audit_local_details = list(local_details)
        counts = report["counts"]
        self.folder_audit_var.set(
            f"{counts['receipts_inspected']} inspected | "
            f"{counts['valid_this_profile']} local | "
            f"{counts['valid_other_profile']} external | "
            f"{counts['unsealed_legacy']} legacy | "
            f"{counts['invalid_or_tampered']} invalid"
        )
        self.export_folder_audit_button.configure(state="normal")
        self.view_folder_review_button.configure(
            state="normal" if self.folder_audit_local_details else "disabled"
        )
        self.set_busy(
            False,
            "Receipt folder audit finished. The folder path and receipt names were not recorded.",
        )
        locker.log_event("download_verify_audit_receipt_folder", "local", "ok")

    def finish_receipt_folder_audit_error(self, error):
        self.folder_audit_result = None
        self.folder_audit_local_details = []
        self.folder_audit_var.set("Receipt folder audit failed")
        self.export_folder_audit_button.configure(state="disabled")
        self.view_folder_review_button.configure(state="disabled")
        self.finish_error(
            "Receipt folder audit failed",
            error,
            "download_verify_audit_receipt_folder",
        )

    def export_receipt_folder_audit(self):
        if not self.folder_audit_result:
            return
        path_text = filedialog.asksaveasfilename(
            parent=self,
            title="Export privacy-safe receipt folder audit",
            defaultextension=".json",
            initialfile="vaultlink-receipt-folder-audit.json",
            filetypes=[("JSON file", "*.json")],
        )
        if not path_text:
            return
        try:
            Path(path_text).write_text(
                json.dumps(self.folder_audit_result, indent=2),
                encoding="utf-8",
            )
            self.status_var.set(
                "Aggregate receipt folder audit exported. Its destination was not recorded."
            )
            locker.log_event(
                "download_verify_export_receipt_folder_audit",
                "local",
                "ok",
            )
        except Exception as exc:
            locker.log_event(
                "download_verify_export_receipt_folder_audit",
                "local",
                "failed",
            )
            messagebox.showerror(
                "Could not export receipt folder audit",
                str(exc),
                parent=self,
            )

    def view_receipt_folder_review(self):
        if not self.folder_audit_local_details:
            return
        if self.folder_review_window is not None:
            try:
                if self.folder_review_window.winfo_exists():
                    self.folder_review_window.deiconify()
                    self.folder_review_window.lift()
                    self.folder_review_window.focus_set()
                    return
            except tk.TclError:
                pass
            self.folder_review_window = None
        window = tk.Toplevel(self)
        self.folder_review_window = window
        window.title("VaultLink Local Receipt Review")
        window.geometry("1040x760")
        window.minsize(880, 650)
        window.configure(bg=locker.BG)
        window.transient(self)
        window.protocol(
            "WM_DELETE_WINDOW",
            lambda: self.close_receipt_folder_review(window),
        )
        window._vaultlink_search_after_id = None
        review_details = [
            dict(detail, review_id=index)
            for index, detail in enumerate(
                filter_receipt_folder_local_details(
                    self.folder_audit_local_details
                )
            )
        ]
        reviewed_ids = set()
        review_history = []

        tk.Label(
            window,
            text="Local Receipt Review",
            bg=locker.BG,
            fg=locker.TEXT,
            font=("Segoe UI", 22, "bold"),
        ).pack(anchor="w", padx=20, pady=(18, 2))
        tk.Label(
            window,
            text="Receipt names, searches, and review marks stay in this app's memory only and are never added to exports, audit logs, or API requests.",
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 9),
            wraplength=820,
            justify="left",
        ).pack(anchor="w", padx=20, pady=(0, 12))

        filter_labels = {
            "All results": "all",
            "Needs review": "needs_review",
            "Problems only": "problems",
            "Valid seals": "valid",
            "Legacy receipts": "legacy",
            "Skipped entries": "skipped",
            "Limit-stopped entries": "limits",
        }
        level_labels = {
            "All priorities": "all",
            "Action Required": "critical",
            "Review": "review",
            "Info": "info",
            "Valid": "good",
        }
        session_labels = {
            "All session states": "all",
            "Pending only": "pending",
            "Reviewed only": "reviewed",
        }
        sort_labels = {
            "Filename": "filename",
            "Priority then filename": "priority",
            "Result then filename": "result",
        }
        search_var = tk.StringVar()
        filter_var = tk.StringVar(value="All results")
        level_var = tk.StringVar(value="All priorities")
        sort_var = tk.StringVar(value="Filename")
        session_var = tk.StringVar(value="All session states")
        visible_count_var = tk.StringVar()
        session_progress_var = tk.StringVar()
        session_breakdown_var = tk.StringVar()
        review_percent_var = tk.DoubleVar(value=0.0)
        selection_position_var = tk.StringVar(value="No row selected")
        triage_title_var = tk.StringVar(value="NO RESULT SELECTED")
        triage_meaning_var = tk.StringVar(
            value="Select a row to see its fixed local meaning."
        )
        triage_action_var = tk.StringVar(
            value="Next safe step: no action selected."
        )
        review_action_var = tk.StringVar(value="MARK REVIEWED")
        copy_guidance_button = None

        controls = tk.Frame(window, bg=locker.PANEL)
        controls.pack(fill="x", padx=20, pady=(0, 12))
        tk.Label(
            controls,
            text="SEARCH RECEIPT FILENAMES",
            bg=locker.PANEL,
            fg=locker.MUTED,
            font=("Segoe UI", 8, "bold"),
        ).grid(row=0, column=0, sticky="w", padx=(12, 8), pady=(10, 3))
        tk.Label(
            controls,
            text="SHOW",
            bg=locker.PANEL,
            fg=locker.MUTED,
            font=("Segoe UI", 8, "bold"),
        ).grid(row=0, column=1, sticky="w", padx=8, pady=(10, 3))
        tk.Label(
            controls,
            text="PRIORITY",
            bg=locker.PANEL,
            fg=locker.MUTED,
            font=("Segoe UI", 8, "bold"),
        ).grid(row=0, column=2, sticky="w", padx=8, pady=(10, 3))
        tk.Label(
            controls,
            text="SORT",
            bg=locker.PANEL,
            fg=locker.MUTED,
            font=("Segoe UI", 8, "bold"),
        ).grid(row=0, column=3, sticky="w", padx=8, pady=(10, 3))
        search_entry = tk.Entry(
            controls,
            textvariable=search_var,
            bg=locker.FIELD,
            fg=locker.TEXT,
            insertbackground=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 10),
        )
        search_entry.grid(
            row=1,
            column=0,
            sticky="ew",
            padx=(12, 8),
            pady=(0, 12),
            ipady=6,
        )
        filter_box = ttk.Combobox(
            controls,
            textvariable=filter_var,
            values=tuple(filter_labels),
            state="readonly",
            width=22,
        )
        filter_box.grid(row=1, column=1, sticky="ew", padx=8, pady=(0, 12), ipady=4)
        level_box = ttk.Combobox(
            controls,
            textvariable=level_var,
            values=tuple(level_labels),
            state="readonly",
            width=18,
        )
        level_box.grid(row=1, column=2, sticky="ew", padx=8, pady=(0, 12), ipady=4)
        sort_box = ttk.Combobox(
            controls,
            textvariable=sort_var,
            values=tuple(sort_labels),
            state="readonly",
            width=20,
        )
        sort_box.grid(row=1, column=3, sticky="ew", padx=8, pady=(0, 12), ipady=4)
        tk.Label(
            controls,
            text="SESSION",
            bg=locker.PANEL,
            fg=locker.MUTED,
            font=("Segoe UI", 8, "bold"),
        ).grid(
            row=2,
            column=0,
            sticky="w",
            padx=12,
            pady=(0, 8),
        )
        session_box = ttk.Combobox(
            controls,
            textvariable=session_var,
            values=tuple(session_labels),
            state="readonly",
            width=22,
        )
        session_box.grid(
            row=2,
            column=1,
            sticky="w",
            padx=8,
            pady=(0, 10),
            ipady=4,
        )
        controls.columnconfigure(0, weight=1)

        table_frame = tk.Frame(window, bg=locker.PANEL)
        table_frame.pack(fill="both", expand=True, padx=20, pady=(0, 12))
        table = ttk.Treeview(
            table_frame,
            columns=("receipt", "priority", "result", "session"),
            show="headings",
            selectmode="browse",
        )
        table.heading("receipt", text="Receipt filename")
        table.heading("priority", text="Priority")
        table.heading("result", text="Local result")
        table.heading("session", text="Session")
        table.column("receipt", width=350, minwidth=220, anchor="w")
        table.column("priority", width=125, minwidth=105, anchor="w", stretch=False)
        table.column("result", width=330, minwidth=220, anchor="w")
        table.column("session", width=100, minwidth=90, anchor="w", stretch=False)
        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=table.yview,
        )
        table.configure(yscrollcommand=scrollbar.set)
        table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        table.tag_configure("critical", foreground=locker.RED)
        table.tag_configure("review", foreground=locker.YELLOW)
        table.tag_configure("info", foreground=locker.BLUE)
        table.tag_configure("good", foreground=locker.GREEN)
        table.tag_configure("reviewed", foreground=locker.MUTED)
        item_status = {}
        item_review_ids = {}

        def cancel_scheduled_search():
            after_id = getattr(window, "_vaultlink_search_after_id", None)
            if after_id is not None:
                try:
                    window.after_cancel(after_id)
                except tk.TclError:
                    pass
                window._vaultlink_search_after_id = None

        def clear_triage_panel():
            triage_title_var.set("NO RESULT SELECTED")
            triage_meaning_var.set("Select a row to see its fixed local meaning.")
            triage_action_var.set("Next safe step: no action selected.")
            review_action_var.set("MARK REVIEWED")
            selection_position_var.set("No row selected")
            if copy_guidance_button is not None:
                copy_guidance_button.configure(state="disabled")

        def refresh_review(_event=None, preferred_review_id=None):
            cancel_scheduled_search()
            if preferred_review_id is None:
                selected_items = table.selection()
                if selected_items:
                    preferred_review_id = item_review_ids.get(selected_items[0])
            rows = filter_receipt_folder_local_details(
                review_details,
                query=search_var.get(),
                category=filter_labels[filter_var.get()],
                level=level_labels[level_var.get()],
                sort_mode=sort_labels[sort_var.get()],
                reviewed_ids=reviewed_ids,
                session_state=session_labels[session_var.get()],
            )
            table.delete(*table.get_children())
            item_status.clear()
            item_review_ids.clear()
            for detail in rows:
                guidance = receipt_folder_review_triage(detail["status"])
                is_reviewed = bool(detail.get("reviewed"))
                item_id = table.insert(
                    "",
                    "end",
                    values=(
                        detail["name"],
                        guidance["level_label"],
                        FOLDER_REVIEW_STATUS_LABELS[detail["status"]],
                        "Reviewed" if is_reviewed else "Pending",
                    ),
                    tags=("reviewed" if is_reviewed else guidance["level"],),
                )
                item_status[item_id] = detail["status"]
                item_review_ids[item_id] = detail["review_id"]
            summary = receipt_folder_review_session_summary(
                review_details,
                reviewed_ids,
            )
            visible_pending = sum(not bool(row.get("reviewed")) for row in rows)
            visible_reviewed = len(rows) - visible_pending
            visible_count_var.set(
                f"{len(rows)} shown | {visible_pending} pending | "
                f"{visible_reviewed} reviewed"
            )
            review_percent = (
                100
                if summary["total_results"] == 0
                else round(100 * summary["reviewed"] / summary["total_results"])
            )
            review_percent_var.set(review_percent)
            session_progress_var.set(
                f"{summary['reviewed']} of {summary['total_results']} reviewed | "
                f"{summary['pending']} pending | {review_percent}% complete"
            )
            session_breakdown_var.set(
                "Pending by level: "
                f"{summary['action_required_pending']} Action Required | "
                f"{summary['review_pending']} Review | "
                f"{summary['info_pending']} Info | "
                f"{summary['valid_pending']} Valid"
            )
            clear_triage_panel()
            if preferred_review_id is not None:
                select_review_id(preferred_review_id)

        def show_selected_guidance(_event=None):
            selected_items = table.selection()
            if not selected_items:
                clear_triage_panel()
                return
            status = item_status.get(selected_items[0])
            if status not in FOLDER_REVIEW_TRIAGE:
                clear_triage_panel()
                return
            guidance = receipt_folder_review_triage(status)
            triage_title_var.set(
                f"{guidance['level_label']} | {FOLDER_REVIEW_STATUS_LABELS[status]}"
            )
            triage_meaning_var.set(guidance["meaning"])
            triage_action_var.set(f"Next safe step: {guidance['next_action']}")
            review_id = item_review_ids.get(selected_items[0])
            review_action_var.set(
                "MARK UNREVIEWED" if review_id in reviewed_ids else "MARK REVIEWED"
            )
            selection_position_var.set(
                f"Selected {table.index(selected_items[0]) + 1} of "
                f"{len(table.get_children())} shown"
            )
            if copy_guidance_button is not None:
                copy_guidance_button.configure(state="normal")

        def select_review_id(review_id):
            for item_id, item_review_id in item_review_ids.items():
                if item_review_id == review_id:
                    table.selection_set(item_id)
                    table.focus(item_id)
                    table.see(item_id)
                    show_selected_guidance()
                    return True
            return False

        def apply_review_mark_action(review_ids, reviewed):
            updated_reviewed_ids, changes = apply_receipt_folder_review_marks(
                reviewed_ids,
                review_ids,
                reviewed,
            )
            if not changes:
                return ()
            reviewed_ids.clear()
            reviewed_ids.update(updated_reviewed_ids)
            review_history.append(changes)
            del review_history[:-MAX_RECEIPT_REVIEW_HISTORY]
            return changes

        def toggle_selected_reviewed():
            selected_items = table.selection()
            if not selected_items:
                triage_title_var.set("NO RESULT SELECTED")
                triage_meaning_var.set(
                    "Select a row before changing its temporary review mark."
                )
                triage_action_var.set(
                    "Next safe step: select one visible receipt result."
                )
                return
            review_id = item_review_ids.get(selected_items[0])
            if review_id is None:
                clear_triage_panel()
                return
            apply_review_mark_action(
                (review_id,),
                review_id not in reviewed_ids,
            )
            refresh_review(preferred_review_id=review_id)

        def mark_shown_reviewed():
            visible_pending_ids = [
                item_review_ids[item_id]
                for item_id in table.get_children()
                if item_review_ids.get(item_id) not in reviewed_ids
            ]
            changes = apply_review_mark_action(visible_pending_ids, True)
            if not changes:
                triage_title_var.set("NO PENDING ITEMS SHOWN")
                triage_meaning_var.set(
                    "Every result in the current search and filter is already marked Reviewed."
                )
                triage_action_var.set(
                    "Next safe step: change the search or filters if you need to review another group."
                )
                return
            refresh_review(preferred_review_id=changes[0][0])

        def mark_shown_pending():
            visible_reviewed_ids = [
                item_review_ids[item_id]
                for item_id in table.get_children()
                if item_review_ids.get(item_id) in reviewed_ids
            ]
            changes = apply_review_mark_action(visible_reviewed_ids, False)
            if not changes:
                triage_title_var.set("NO REVIEWED ITEMS SHOWN")
                triage_meaning_var.set(
                    "Every result in the current search and filters is already Pending."
                )
                triage_action_var.set(
                    "Next safe step: change the session view or filters if you need to reopen another group."
                )
                return
            refresh_review(preferred_review_id=changes[0][0])

        def copy_selected_guidance():
            selected_items = table.selection()
            if not selected_items:
                triage_title_var.set("NO RESULT SELECTED")
                triage_meaning_var.set(
                    "Select one row before copying its fixed safe guidance."
                )
                triage_action_var.set(
                    "Next safe step: select a visible receipt result."
                )
                return
            status = item_status.get(selected_items[0])
            try:
                safe_text = receipt_folder_review_guidance_text(status)
                window.clipboard_clear()
                window.clipboard_append(safe_text)
                window.update_idletasks()
                triage_action_var.set(
                    "Fixed guidance copied without the receipt filename or path."
                )
                locker.log_event(
                    "download_verify_copy_review_guidance",
                    "local",
                    "ok",
                )
            except Exception:
                locker.log_event(
                    "download_verify_copy_review_guidance",
                    "local",
                    "failed",
                )
                messagebox.showerror(
                    "Copy failed",
                    "VaultLink could not copy the fixed guidance.",
                    parent=window,
                )

        def undo_last_review_mark():
            if not review_history:
                triage_title_var.set("NOTHING TO UNDO")
                triage_meaning_var.set(
                    "This review session has no earlier mark change to restore."
                )
                triage_action_var.set(
                    "Next safe step: select a row if you want to change its review mark."
                )
                return
            changes = review_history.pop()
            for review_id, was_reviewed in changes:
                if was_reviewed:
                    reviewed_ids.add(review_id)
                else:
                    reviewed_ids.discard(review_id)
            refresh_review(preferred_review_id=changes[0][0])

        def reset_review_marks():
            reviewed_ids.clear()
            review_history.clear()
            refresh_review()

        def next_review_item():
            review_items = [
                item_id
                for item_id in table.get_children()
                if item_status.get(item_id) in FOLDER_REVIEW_NEEDS_REVIEW_STATUSES
                and item_review_ids.get(item_id) not in reviewed_ids
            ]
            review_items.sort(
                key=lambda item_id: (
                    FOLDER_REVIEW_TRIAGE_PRIORITY[
                        FOLDER_REVIEW_TRIAGE[item_status[item_id]]["level"]
                    ],
                    table.index(item_id),
                )
            )
            if not review_items:
                triage_title_var.set("NO REVIEW ITEMS SHOWN")
                triage_meaning_var.set(
                    "The current search and filter contain no unreviewed Action Required or Review results."
                )
                triage_action_var.set(
                    "Next safe step: reset review marks or change the search and filter if you need another pass."
                )
                return
            selected_items = table.selection()
            if selected_items and selected_items[0] in review_items:
                selected_index = review_items.index(selected_items[0])
                target = review_items[(selected_index + 1) % len(review_items)]
            else:
                target = review_items[0]
            table.selection_set(target)
            table.focus(target)
            table.see(target)
            show_selected_guidance()

        def ordered_pending_items():
            pending_items = [
                item_id
                for item_id in table.get_children()
                if item_review_ids.get(item_id) not in reviewed_ids
            ]
            pending_items.sort(
                key=lambda item_id: (
                    FOLDER_REVIEW_TRIAGE_PRIORITY[
                        FOLDER_REVIEW_TRIAGE[item_status[item_id]]["level"]
                    ],
                    table.index(item_id),
                )
            )
            return pending_items

        def cycle_pending_item(step):
            pending_items = ordered_pending_items()
            if not pending_items:
                triage_title_var.set("NO PENDING ITEMS SHOWN")
                triage_meaning_var.set(
                    "Every result in the current search and filter is marked Reviewed."
                )
                triage_action_var.set(
                    "Next safe step: reset review marks or change the search and filter if you need another pass."
                )
                return
            selected_items = table.selection()
            if selected_items and selected_items[0] in pending_items:
                selected_index = pending_items.index(selected_items[0])
                target = pending_items[
                    (selected_index + step) % len(pending_items)
                ]
            else:
                target = pending_items[0 if step > 0 else -1]
            table.selection_set(target)
            table.focus(target)
            table.see(target)
            show_selected_guidance()

        def next_pending_item():
            cycle_pending_item(1)

        def previous_pending_item():
            cycle_pending_item(-1)

        def clear_filters():
            search_var.set("")
            filter_var.set("All results")
            level_var.set("All priorities")
            sort_var.set("Filename")
            session_var.set("All session states")
            refresh_review()

        def run_scheduled_search():
            window._vaultlink_search_after_id = None
            refresh_review()

        def schedule_search_refresh(_event=None):
            cancel_scheduled_search()
            window._vaultlink_search_after_id = window.after(
                RECEIPT_REVIEW_SEARCH_DEBOUNCE_MS,
                run_scheduled_search,
            )

        search_entry.bind("<KeyRelease>", schedule_search_refresh)
        filter_box.bind("<<ComboboxSelected>>", refresh_review)
        level_box.bind("<<ComboboxSelected>>", refresh_review)
        sort_box.bind("<<ComboboxSelected>>", refresh_review)
        session_box.bind("<<ComboboxSelected>>", refresh_review)
        table.bind("<<TreeviewSelect>>", show_selected_guidance)
        refresh_review()

        triage_panel = tk.Frame(window, bg=locker.PANEL)
        triage_panel.pack(fill="x", padx=20, pady=(0, 12))
        tk.Label(
            triage_panel,
            textvariable=triage_title_var,
            bg=locker.PANEL,
            fg=locker.TEXT,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", padx=12, pady=(10, 2))
        tk.Label(
            triage_panel,
            textvariable=triage_meaning_var,
            bg=locker.PANEL,
            fg=locker.MUTED,
            font=("Segoe UI", 9),
            wraplength=890,
            justify="left",
        ).pack(anchor="w", padx=12)
        tk.Label(
            triage_panel,
            textvariable=triage_action_var,
            bg=locker.PANEL,
            fg=locker.BLUE,
            font=("Segoe UI", 9, "bold"),
            wraplength=890,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(2, 10))
        tk.Label(
            triage_panel,
            textvariable=session_progress_var,
            bg=locker.PANEL,
            fg=locker.YELLOW,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", padx=12, pady=(0, 8))
        ttk.Progressbar(
            triage_panel,
            mode="determinate",
            maximum=100,
            variable=review_percent_var,
        ).pack(fill="x", padx=12, pady=(0, 8), ipady=2)
        tk.Label(
            triage_panel,
            textvariable=session_breakdown_var,
            bg=locker.PANEL,
            fg=locker.MUTED,
            font=("Segoe UI", 9),
            wraplength=950,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))
        tk.Label(
            triage_panel,
            textvariable=selection_position_var,
            bg=locker.PANEL,
            fg=locker.MUTED,
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=12, pady=(0, 8))
        review_controls = tk.Frame(triage_panel, bg=locker.PANEL)
        review_controls.pack(fill="x", padx=12, pady=(0, 10))
        tk.Button(
            review_controls,
            textvariable=review_action_var,
            command=toggle_selected_reviewed,
            bg=locker.BLUE,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", ipadx=10, ipady=5)
        tk.Button(
            review_controls,
            text="MARK SHOWN REVIEWED",
            command=mark_shown_reviewed,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", padx=(8, 0), ipadx=10, ipady=5)
        tk.Button(
            review_controls,
            text="MARK SHOWN PENDING",
            command=mark_shown_pending,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", padx=(8, 0), ipadx=10, ipady=5)
        tk.Button(
            review_controls,
            text="UNDO LAST CHANGE",
            command=undo_last_review_mark,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", padx=(8, 0), ipadx=10, ipady=5)
        copy_guidance_button = tk.Button(
            review_controls,
            text="COPY SAFE GUIDANCE",
            command=copy_selected_guidance,
            state="disabled",
            bg="#252936",
            fg=locker.TEXT,
            disabledforeground=locker.MUTED,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        )
        copy_guidance_button.pack(
            side="left",
            padx=(8, 0),
            ipadx=10,
            ipady=5,
        )
        tk.Button(
            review_controls,
            text="RESET REVIEW MARKS",
            command=reset_review_marks,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", padx=(8, 0), ipadx=10, ipady=5)

        actions = tk.Frame(window, bg=locker.BG)
        actions.pack(fill="x", padx=20, pady=(0, 18))
        tk.Button(
            actions,
            text="CLEAR LOCAL LIST",
            command=lambda: self.clear_receipt_folder_review(window),
            bg=locker.YELLOW,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", ipadx=12, ipady=7)
        tk.Button(
            actions,
            text="CLEAR FILTERS",
            command=clear_filters,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(10, 0), ipadx=12, ipady=7)
        tk.Button(
            actions,
            text="NEXT REVIEW ITEM",
            command=next_review_item,
            bg=locker.BLUE,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(10, 0), ipadx=12, ipady=7)
        tk.Button(
            actions,
            text="PREVIOUS PENDING",
            command=previous_pending_item,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(10, 0), ipadx=12, ipady=7)
        tk.Button(
            actions,
            text="NEXT PENDING ITEM",
            command=next_pending_item,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(10, 0), ipadx=12, ipady=7)
        tk.Label(
            actions,
            textvariable=visible_count_var,
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=14)
        tk.Button(
            actions,
            text="CLOSE",
            command=lambda: self.close_receipt_folder_review(window),
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right", ipadx=12, ipady=7)
        locker.log_event("download_verify_view_receipt_folder_review", "local", "ok")

    def close_receipt_folder_review(self, window=None):
        target = window or self.folder_review_window
        if target is not None:
            try:
                after_id = getattr(target, "_vaultlink_search_after_id", None)
                if after_id is not None:
                    target.after_cancel(after_id)
                    target._vaultlink_search_after_id = None
                if target.winfo_exists():
                    target.destroy()
            except tk.TclError:
                pass
        if target is self.folder_review_window:
            self.folder_review_window = None

    def clear_receipt_folder_review(self, window=None):
        self.folder_audit_local_details = []
        self.view_folder_review_button.configure(state="disabled")
        self.status_var.set(
            "Local receipt names cleared from memory. The aggregate audit remains available."
        )
        self.close_receipt_folder_review(window)
        locker.log_event("download_verify_clear_receipt_folder_review", "local", "ok")

    def compare_prior_receipt(self):
        if not self.result or self.busy:
            return
        path_text = filedialog.askopenfilename(
            parent=self,
            title="Choose a prior VaultLink verification receipt",
            filetypes=[("VaultLink JSON receipt", "*.json")],
        )
        if not path_text:
            return
        try:
            prior = load_verification_receipt(path_text)
            self.inspection_result = build_receipt_inspection_report(prior)
            self.inspection_var.set(
                f"{INTEGRITY_LABELS[self.inspection_result['integrity_state']]} | "
                f"{len(self.inspection_result['structure']['warning_ids'])} "
                "fixed structural warning(s)"
            )
            self.copy_inspection_button.configure(state="normal")
            self.comparison_result = compare_verification_receipt(
                self.result,
                self.defender_result,
                prior,
            )
            verdict = self.comparison_result["verdict"].replace("_", " ").upper()
            integrity = INTEGRITY_LABELS[
                self.comparison_result["prior_receipt_integrity"]
            ]
            self.comparison_var.set(
                f"{verdict} | {integrity} | "
                f"{self.comparison_result['change_count']} fixed field change(s)"
            )
            self.export_comparison_button.configure(state="normal")
            self.status_var.set("Prior receipt compared locally. Its path and unknown fields were discarded.")
            locker.log_event("download_verify_compare_receipt", "local", "ok")
        except Exception as exc:
            self.comparison_result = None
            self.comparison_var.set("Prior receipt comparison failed")
            self.export_comparison_button.configure(state="disabled")
            locker.log_event("download_verify_compare_receipt", "local", "failed")
            messagebox.showerror("Could not compare receipt", str(exc), parent=self)

    def export_comparison(self):
        if not self.comparison_result:
            return
        path_text = filedialog.asksaveasfilename(
            parent=self,
            title="Export privacy-safe receipt comparison",
            defaultextension=".json",
            initialfile="vaultlink-download-comparison.json",
            filetypes=[("JSON file", "*.json")],
        )
        if not path_text:
            return
        try:
            Path(path_text).write_text(
                json.dumps(self.comparison_result, indent=2),
                encoding="utf-8",
            )
            self.status_var.set("Comparison exported. Its destination was not recorded.")
            locker.log_event("download_verify_export_comparison", "local", "ok")
        except Exception as exc:
            locker.log_event("download_verify_export_comparison", "local", "failed")
            messagebox.showerror("Could not export comparison", str(exc), parent=self)

    def open_windows_security(self):
        try:
            if os.name != "nt" or not hasattr(os, "startfile"):
                raise OSError("Windows Security is available only on Windows.")
            os.startfile("windowsdefender:")
            self.status_var.set("Opened Windows Security. VaultLink does not control that window.")
        except Exception as exc:
            messagebox.showerror("Could not open Windows Security", str(exc), parent=self)


if __name__ == "__main__":
    DownloadVerificationCenter().mainloop()
