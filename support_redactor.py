from collections import Counter
from datetime import datetime
import ipaddress
from pathlib import Path
import re
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlsplit, urlunsplit

import usb_file_locker as locker


MAX_INPUT_BYTES = 5 * 1024 * 1024
SUPPORTED_SUFFIXES = {
    ".cfg",
    ".csv",
    ".ini",
    ".json",
    ".log",
    ".md",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
LABELED_SECRET_RE = re.compile(
    r"(?im)^(\s*(?:"
    r"password|passcode|passwd|pin|secret|"
    r"api[ _-]?key|access[ _-]?token|refresh[ _-]?token|auth(?:orization)?|"
    r"bearer|private[ _-]?key|master[ _-]?key|owner[ _-]?key|"
    r"license[ _-]?key|activation[ _-]?receipt|recovery[ _-]?code|"
    r"username|user[ _-]?name|account[ _-]?name|"
    r"machine[ _-]?(?:id|fingerprint)|device[ _-]?id|hardware[ _-]?id|"
    r"computer[ _-]?name|serial[ _-]?(?:number|id)"
    r")\s*[:=]\s*)(.+?)\s*$"
)
JSON_LABELED_SECRET_RE = re.compile(
    r"(?i)([\"'](?:"
    r"password|passcode|passwd|pin|secret|"
    r"api[ _-]?key|access[ _-]?token|refresh[ _-]?token|authorization|"
    r"private[ _-]?key|master[ _-]?key|owner[ _-]?key|"
    r"license[ _-]?key|activation[ _-]?receipt|recovery[ _-]?code|"
    r"username|user[ _-]?name|account[ _-]?name|"
    r"machine[ _-]?(?:id|fingerprint)|device[ _-]?id|hardware[ _-]?id|"
    r"computer[ _-]?name|serial[ _-]?(?:number|id)"
    r")[\"']\s*:\s*)"
    r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^,\r\n}\]]+)"
)
INLINE_SECRET_RE = re.compile(
    r"(?i)(\b(?:"
    r"password|passcode|passwd|pin|secret|"
    r"api[ _-]?key|access[ _-]?token|refresh[ _-]?token|authorization|"
    r"private[ _-]?key|master[ _-]?key|owner[ _-]?key|"
    r"license[ _-]?key|activation[ _-]?receipt|recovery[ _-]?code"
    r")\s*[:=]\s*)"
    r"(?!\[REDACTED\])"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^;\s,\]}]+)"
)
VAULTLINK_SECRET_RE = re.compile(
    r"(?i)\b(?:vlk1|vlr1|vla1|vlt1)\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]{6,})*\b"
)
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/\-=]{8,}")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
KNOWN_TOKEN_RE = re.compile(
    r"\b(?:"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"AKIA[A-Z0-9]{16}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}"
    r")\b"
)
KEY_FILE_RE = re.compile(
    r"(?i)(?<![\w.])(?:"
    r"(?:[A-Z]:\\|\\\\)[^\r\n\t\"<>|]*?\.key|"
    r"[A-Za-z0-9_. -]{1,120}\.key"
    r")\b"
)
EMAIL_RE = re.compile(r"(?i)(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])")
WINDOWS_USER_RE = re.compile(r"(?i)(?<![A-Za-z0-9_])([A-Z]:\\Users\\)([^\\/\r\n]+)")
UNC_USER_RE = re.compile(r"(?i)(?<!\\)\\\\([^\\\s]+)\\Users\\([^\\/\r\n]+)")
UNIX_USER_RE = re.compile(r"(?<![A-Za-z0-9_])(/(?:home|Users)/)([^/\s]+)")
UUID_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
)
MAC_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")
IPV4_CANDIDATE_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_CANDIDATE_RE = re.compile(
    r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])"
)
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}(?!\d)"
)
SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
PAYMENT_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def _replace_matches(text, pattern, replacement, category, counts):
    def replace(match):
        counts[category] += 1
        return replacement(match) if callable(replacement) else replacement

    return pattern.sub(replace, text)


def _redact_urls(text, counts):
    trailing_chars = ".,;!)]}"

    def replace(match):
        raw = match.group(0)
        core = raw.rstrip(trailing_chars)
        trailing = raw[len(core) :]
        try:
            parsed = urlsplit(core)
        except ValueError:
            return raw

        lowered_path = parsed.path.lower()
        if "/api/webhooks/" in lowered_path or "/bot" in lowered_path and "api" in lowered_path:
            counts["Secret URL"] += 1
            return "[SECRET_URL]" + trailing

        changed = False
        netloc = parsed.netloc
        if "@" in netloc:
            netloc = netloc.rsplit("@", 1)[1]
            changed = True
        if parsed.query or parsed.fragment:
            changed = True
        if not changed:
            return raw

        counts["URL credentials or query"] += 1
        clean = urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
        if parsed.query:
            clean += "?[QUERY_REMOVED]"
        if parsed.fragment:
            clean += "#[FRAGMENT_REMOVED]"
        return clean + trailing

    return URL_RE.sub(replace, text)


def _redact_ip_candidates(text, pattern, version, placeholder, category, counts):
    def replace(match):
        candidate = match.group(0)
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            return candidate
        if parsed.version != version:
            return candidate
        counts[category] += 1
        return placeholder

    return pattern.sub(replace, text)


def _passes_luhn(value):
    digits = [int(character) for character in value if character.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _redact_payment_cards(text, counts):
    def replace(match):
        candidate = match.group(0)
        if not _passes_luhn(candidate):
            return candidate
        counts["Payment card"] += 1
        return "[PAYMENT_CARD]"

    return PAYMENT_CARD_CANDIDATE_RE.sub(replace, text)


def redact_support_text(text):
    source = str(text or "")
    if len(source.encode("utf-8", errors="replace")) > MAX_INPUT_BYTES:
        raise ValueError("Support text is larger than the 5 MB safety limit.")

    counts = Counter()
    output = _redact_urls(source, counts)
    output = _replace_matches(
        output,
        JSON_LABELED_SECRET_RE,
        lambda match: match.group(1) + '"[REDACTED]"',
        "JSON secret or identity",
        counts,
    )
    output = _replace_matches(
        output,
        LABELED_SECRET_RE,
        lambda match: match.group(1) + "[REDACTED]",
        "Labeled secret or identity",
        counts,
    )
    output = _replace_matches(
        output,
        INLINE_SECRET_RE,
        lambda match: match.group(1) + "[REDACTED]",
        "Inline secret",
        counts,
    )
    output = _replace_matches(output, VAULTLINK_SECRET_RE, "[VAULTLINK_SECRET]", "VaultLink secret", counts)
    output = _replace_matches(output, BEARER_RE, "Bearer [TOKEN]", "Bearer token", counts)
    output = _replace_matches(output, JWT_RE, "[JWT]", "Authentication token", counts)
    output = _replace_matches(output, KNOWN_TOKEN_RE, "[API_TOKEN]", "API token", counts)
    output = _replace_matches(output, KEY_FILE_RE, "[KEY_FILE]", "Key filename or path", counts)
    output = _replace_matches(output, EMAIL_RE, "[EMAIL]", "Email address", counts)
    output = _replace_matches(
        output,
        UNC_USER_RE,
        r"\\[SERVER]\Users\[USER]",
        "Windows user path",
        counts,
    )
    output = _replace_matches(
        output,
        WINDOWS_USER_RE,
        lambda match: match.group(1) + "[USER]",
        "Windows user path",
        counts,
    )
    output = _replace_matches(
        output,
        UNIX_USER_RE,
        lambda match: match.group(1) + "[USER]",
        "User home path",
        counts,
    )
    output = _replace_matches(output, UUID_RE, "[UUID]", "Machine or event identifier", counts)
    output = _replace_matches(output, MAC_RE, "[MAC_ADDRESS]", "MAC address", counts)
    output = _redact_ip_candidates(
        output,
        IPV4_CANDIDATE_RE,
        4,
        "[IP_ADDRESS]",
        "IPv4 address",
        counts,
    )
    output = _redact_ip_candidates(
        output,
        IPV6_CANDIDATE_RE,
        6,
        "[IP_ADDRESS]",
        "IPv6 address",
        counts,
    )
    output = _replace_matches(output, EMAIL_RE, "[EMAIL]", "Email address", counts)
    output = _replace_matches(output, PHONE_RE, "[PHONE]", "Phone number", counts)
    output = _replace_matches(output, SSN_RE, "[SSN]", "US SSN", counts)
    output = _redact_payment_cards(output, counts)

    return {
        "text": output,
        "counts": dict(sorted(counts.items())),
        "total": sum(counts.values()),
        "changed": output != source,
    }


def redaction_summary(result):
    counts = result.get("counts") or {}
    total = int(result.get("total", 0))
    if not counts:
        return "No known sensitive patterns were found. Review the preview before sharing."
    details = " | ".join(f"{name}: {count}" for name, count in counts.items())
    return f"{total} item(s) redacted | {details}"


class SupportRedactor(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VaultLink Support Redactor")
        self.geometry("1320x860")
        self.minsize(1020, 700)
        self.configure(bg=locker.BG)
        self.status = tk.StringVar(value="Paste or open text, then click REDACT NOW.")
        self.summary = tk.StringVar(value="No redaction has been run.")
        self.result = None
        self.input_box = None
        self.preview_box = None
        self.copy_button = None
        self.save_button = None
        self.build_ui()

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=22)

        tk.Label(
            outer,
            text="Support Redactor",
            bg=locker.BG,
            fg=locker.TEXT,
            font=("Segoe UI", 28, "bold"),
        ).pack(anchor="w")
        tk.Label(
            outer,
            text="Remove common secrets and personal details from copied errors or logs before sharing them with support.",
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 12))

        warning = tk.Frame(outer, bg="#2b2515")
        warning.pack(fill="x", pady=(0, 14))
        tk.Label(
            warning,
            text="LOCAL ONLY | Nothing is uploaded. Redaction cannot guarantee every secret is found. Always review the preview before sharing.",
            bg="#2b2515",
            fg=locker.YELLOW,
            font=("Segoe UI", 9, "bold"),
            justify="left",
            wraplength=1220,
        ).pack(anchor="w", padx=14, pady=10)

        actions = tk.Frame(outer, bg=locker.BG)
        actions.pack(fill="x", pady=(0, 12))
        tk.Button(
            actions,
            text="OPEN TEXT FILE",
            command=self.open_text_file,
            bg=locker.WHITE,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", ipadx=12, ipady=8)
        tk.Button(
            actions,
            text="PASTE CLIPBOARD",
            command=self.paste_clipboard,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(
            actions,
            text="REDACT NOW",
            command=self.redact_now,
            bg=locker.GREEN,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(10, 0), ipadx=16, ipady=8)
        self.copy_button = tk.Button(
            actions,
            text="COPY REDACTED",
            command=self.copy_redacted,
            bg=locker.BLUE,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            state="disabled",
        )
        self.copy_button.pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        self.save_button = tk.Button(
            actions,
            text="SAVE REDACTED",
            command=self.save_redacted,
            bg=locker.YELLOW,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            state="disabled",
        )
        self.save_button.pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(
            actions,
            text="CLEAR",
            command=self.clear_all,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(
            actions,
            text="MAIN LOCKER",
            command=self.open_main_locker,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right", ipadx=12, ipady=8)

        summary_panel = tk.Frame(outer, bg=locker.PANEL)
        summary_panel.pack(fill="x", pady=(0, 14))
        tk.Label(
            summary_panel,
            text="REDACTION SUMMARY",
            bg=locker.PANEL,
            fg=locker.MUTED,
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w", padx=14, pady=(12, 4))
        tk.Label(
            summary_panel,
            textvariable=self.summary,
            bg=locker.PANEL,
            fg=locker.TEXT,
            font=("Segoe UI", 9),
            justify="left",
            wraplength=1220,
        ).pack(anchor="w", padx=14, pady=(0, 12))

        body = tk.PanedWindow(
            outer,
            orient="horizontal",
            sashwidth=8,
            bg=locker.BG,
            bd=0,
            relief="flat",
        )
        body.pack(fill="both", expand=True)
        input_panel = tk.Frame(body, bg=locker.PANEL)
        preview_panel = tk.Frame(body, bg=locker.PANEL)
        body.add(input_panel, minsize=430)
        body.add(preview_panel, minsize=430)
        self.input_box = self._text_panel(
            input_panel,
            "ORIGINAL TEXT",
            "Paste only the error or log text you intentionally want to review.",
            editable=True,
        )
        self.preview_box = self._text_panel(
            preview_panel,
            "REDACTED PREVIEW",
            "Copy and save stay disabled until redaction finishes.",
            editable=False,
        )

        tk.Label(
            outer,
            textvariable=self.status,
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(12, 0))

    def _text_panel(self, parent, title, detail, editable):
        tk.Label(
            parent,
            text=title,
            bg=locker.PANEL,
            fg=locker.TEXT,
            font=("Segoe UI", 15, "bold"),
        ).pack(anchor="w", padx=16, pady=(16, 4))
        tk.Label(
            parent,
            text=detail,
            bg=locker.PANEL,
            fg=locker.MUTED,
            font=("Segoe UI", 8),
            wraplength=550,
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 10))
        frame = tk.Frame(parent, bg=locker.PANEL)
        frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        text_box = tk.Text(
            frame,
            bg=locker.FIELD,
            fg=locker.TEXT,
            insertbackground=locker.TEXT,
            relief="flat",
            wrap="word",
            font=("Consolas", 10),
            undo=editable,
        )
        text_box.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text_box.yview)
        scroll.pack(side="right", fill="y")
        text_box.configure(yscrollcommand=scroll.set)
        if not editable:
            text_box.configure(state="disabled")
        return text_box

    def _set_input(self, text):
        self.input_box.delete("1.0", "end")
        self.input_box.insert("1.0", text)
        self._set_preview("")
        self.result = None
        self.copy_button.configure(state="disabled")
        self.save_button.configure(state="disabled")
        self.summary.set("No redaction has been run.")

    def _set_preview(self, text):
        self.preview_box.configure(state="normal")
        self.preview_box.delete("1.0", "end")
        if text:
            self.preview_box.insert("1.0", text)
        self.preview_box.configure(state="disabled")

    def open_text_file(self):
        path_text = filedialog.askopenfilename(
            parent=self,
            title="Choose a text-style support file",
            filetypes=[
                ("Text-style files", "*.txt *.log *.json *.csv *.md *.ini *.cfg *.xml *.yaml *.yml"),
                ("All files", "*.*"),
            ],
        )
        if not path_text:
            return
        try:
            path = Path(path_text)
            if path.suffix.lower() not in SUPPORTED_SUFFIXES:
                raise ValueError("Choose a text-style .txt, .log, .json, .csv, .md, .ini, .cfg, .xml, .yaml, or .yml file.")
            if path.stat().st_size > MAX_INPUT_BYTES:
                raise ValueError("That file is larger than the 5 MB safety limit.")
            text = path.read_text(encoding="utf-8", errors="replace")
            self._set_input(text)
            self.status.set(f"Loaded {len(text):,} character(s). The filename was not recorded.")
            locker.log_event("support_redactor_load", "local", "ok")
        except Exception as exc:
            self.status.set("Could not load that text file.")
            locker.log_event("support_redactor_load", "local", "failed")
            messagebox.showerror("Could not load text", str(exc), parent=self)

    def paste_clipboard(self):
        try:
            text = self.clipboard_get()
            if len(text.encode("utf-8", errors="replace")) > MAX_INPUT_BYTES:
                raise ValueError("Clipboard text is larger than the 5 MB safety limit.")
            self._set_input(text)
            self.status.set(f"Pasted {len(text):,} character(s). Clipboard contents were not recorded.")
            locker.log_event("support_redactor_paste", "local", "ok")
        except Exception as exc:
            self.status.set("Could not paste clipboard text.")
            locker.log_event("support_redactor_paste", "local", "failed")
            messagebox.showerror("Could not paste", str(exc), parent=self)

    def redact_now(self):
        source = self.input_box.get("1.0", "end-1c")
        if not source.strip():
            self.status.set("Paste or open some text first.")
            messagebox.showinfo("No text yet", "Paste or open some text first.", parent=self)
            return
        try:
            self.result = redact_support_text(source)
            self._set_preview(self.result["text"])
            self.summary.set(redaction_summary(self.result))
            self.copy_button.configure(state="normal")
            self.save_button.configure(state="normal")
            self.status.set("Redaction finished locally. Review the preview before sharing it.")
            locker.log_event("support_redactor_run", "local", "ok")
        except Exception as exc:
            self.result = None
            self.copy_button.configure(state="disabled")
            self.save_button.configure(state="disabled")
            self.status.set("Redaction could not finish.")
            locker.log_event("support_redactor_run", "local", "failed")
            messagebox.showerror("Redaction failed", str(exc), parent=self)

    def copy_redacted(self):
        if not self.result:
            return
        self.clipboard_clear()
        self.clipboard_append(self.result["text"])
        self.update()
        self.status.set("Redacted preview copied. Review it again before sending.")
        locker.log_event("support_redactor_copy", "local", "ok")

    def save_redacted(self):
        if not self.result:
            return
        default_name = datetime.now().strftime("vaultlink-support-redacted-%Y%m%d-%H%M%S.txt")
        path_text = filedialog.asksaveasfilename(
            parent=self,
            title="Save reviewed redacted support text",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("Text file", "*.txt")],
        )
        if not path_text:
            return
        try:
            Path(path_text).write_text(self.result["text"], encoding="utf-8")
            self.status.set("Redacted support copy saved. The output path was not recorded.")
            locker.log_event("support_redactor_save", "local", "ok")
        except Exception as exc:
            self.status.set("Could not save the redacted support copy.")
            locker.log_event("support_redactor_save", "local", "failed")
            messagebox.showerror("Could not save", str(exc), parent=self)

    def clear_all(self):
        self._set_input("")
        self.status.set("Cleared the original and preview from this window.")

    def open_main_locker(self):
        try:
            locker.launch_companion_script("usb_file_locker.py")
            self.status.set("Opened the main USB File Locker.")
        except Exception as exc:
            messagebox.showerror("Could not open main locker", str(exc), parent=self)


if __name__ == "__main__":
    SupportRedactor().mainloop()
