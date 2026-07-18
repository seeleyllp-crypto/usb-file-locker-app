from datetime import datetime, timezone
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import usb_file_locker as locker


MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
DEFENDER_TIMEOUT_SECONDS = 10 * 60
SIGNATURE_TIMEOUT_SECONDS = 30
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


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
        "defender_state": str(defender.get("state", "not_run")),
        "defender_scan_mode": str(defender.get("scan_mode", "not run"))[:120],
        "privacy_note": "The receipt excludes the filename, path, Windows username, file contents, and Defender command output.",
        "limitations": [
            "A matching hash proves only that the bytes match the expected hash.",
            "A valid signature identifies a signer but does not guarantee the file is harmless.",
            "A Defender no-threat result is not proof that a file is safe.",
            "VaultLink does not upload the selected file or this receipt automatically.",
        ],
    }


def verification_summary(result, defender=None):
    receipt = build_privacy_safe_receipt(result, defender)
    comparison = receipt["hash_comparison"].replace("_", " ").upper()
    signature = receipt["signature_state"].replace("_", " ").upper()
    defender_state = receipt["defender_state"].replace("_", " ").upper()
    return "\n".join(
        [
            "VaultLink Download Verification",
            f"Checked: {receipt['created_at_utc']}",
            f"File type: {receipt['extension']}",
            f"Size band: {receipt['size_band']}",
            f"SHA-256: {receipt['sha256']}",
            f"Expected hash: {comparison}",
            f"Digital signature: {signature}",
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
        self.set_busy(True, "Calculating SHA-256 and asking Windows to inspect the digital signature...")

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
