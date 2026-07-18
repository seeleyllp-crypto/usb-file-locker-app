from datetime import datetime, timezone
import base64
import hashlib
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

import usb_file_locker as locker


MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
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


def verification_summary(result, defender=None):
    receipt = build_privacy_safe_receipt(result, defender)
    comparison = receipt["hash_comparison"].replace("_", " ").upper()
    signature = receipt["signature_state"].replace("_", " ").upper()
    defender_state = receipt["defender_state"].replace("_", " ").upper()
    structure = receipt["structure"]
    warning_count = len(structure["warning_ids"])
    return "\n".join(
        [
            "VaultLink Download Verification",
            f"Checked: {receipt['created_at_utc']}",
            f"File type: {receipt['extension']}",
            f"Size band: {receipt['size_band']}",
            f"SHA-256: {receipt['sha256']}",
            f"Expected hash: {comparison}",
            f"Digital signature: {signature}",
            f"Detected type: {structure['detected_type']}",
            f"Extension/header: {structure['extension_header_match'].replace('_', ' ').upper()}",
            f"Structural warnings: {warning_count}",
            f"Microsoft Defender: {defender_state}",
            "",
            "A matching hash, valid signature, or no-threat scan does not guarantee a file is safe.",
            "The selected file was not uploaded by VaultLink.",
        ]
    )


class DownloadVerificationCenter(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VaultLink Download Verification Center")
        self.geometry("1120x790")
        self.minsize(900, 680)
        self.configure(bg=locker.BG)
        self.selected_path = None
        self.result = None
        self.defender_result = None
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
        self.status_var = tk.StringVar(value="Choose one downloaded file to begin.")
        self.expected_var = tk.StringVar(value="")
        self.progress = None
        self.verify_button = None
        self.defender_button = None
        self.copy_hash_button = None
        self.copy_summary_button = None
        self.export_button = None
        self.build_ui()

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=22)

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
            text="EXPORT RECEIPT",
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
        ):
            row = tk.Frame(results, bg=locker.PANEL)
            row.pack(fill="x", padx=16, pady=5)
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
            self.file_var.set(f"{selected.name} | {locker.format_update_size(identity['size'])}")
            self.hash_var.set("Not calculated")
            self.compare_var.set("Expected hash not provided")
            self.signature_var.set("Not inspected")
            self.signer_var.set("No signer information")
            self.structure_var.set("Not inspected")
            self.warning_var.set("No structural review yet")
            self.archive_var.set("Not an inspected ZIP archive")
            self.defender_var.set("Not scanned")
            self.verify_button.configure(state="normal")
            self.defender_button.configure(state="normal")
            self.copy_hash_button.configure(state="disabled")
            self.copy_summary_button.configure(state="disabled")
            self.export_button.configure(state="disabled")
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
        else:
            self.progress.stop()
            state = "normal" if self.selected_path else "disabled"
            self.verify_button.configure(state=state)
            self.defender_button.configure(state=state)
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
                self.after(0, lambda: self.finish_error("Verification failed", exc, "download_verify_run"))

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
                self.after(0, lambda: self.finish_error("Defender scan failed", exc, "download_verify_defender"))

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
        self.clipboard_append(verification_summary(self.result, self.defender_result))
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
            receipt = build_privacy_safe_receipt(self.result, self.defender_result)
            Path(path_text).write_text(json.dumps(receipt, indent=2), encoding="utf-8")
            self.status_var.set("Verification receipt exported. Its destination was not recorded.")
            locker.log_event("download_verify_export", "local", "ok")
        except Exception as exc:
            locker.log_event("download_verify_export", "local", "failed")
            messagebox.showerror("Could not export receipt", str(exc), parent=self)

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
