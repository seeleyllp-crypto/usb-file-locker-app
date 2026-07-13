import json
import os
import queue
import re
import threading
import tkinter as tk
from collections import Counter
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import usb_file_locker as locker


def inspect_locked_file(path, loaded_key_id=""):
    path = Path(path)
    row = {
        "path": str(path),
        "name": path.name,
        "folder": str(path.parent),
        "format": "Unreadable",
        "kind": "unknown",
        "health": "Issue",
        "key_match": "not checked",
        "key_id": "",
        "security_profile": "unknown",
        "issues": [],
    }
    try:
        info = locker.locked_file_info(path)
        header = info["header"]
        row["format"] = "Portable" if info["portable"] else "Legacy Windows-only"
        row["kind"] = str(info.get("kind", "file"))
        row["key_id"] = str(header.get("key_id", ""))
        row["security_profile"] = str(header.get("security_profile", "legacy" if not info["portable"] else "unknown"))
        if row["kind"] not in {"file", "folder", "vault_export"}:
            row["issues"].append("Unknown locked-item kind")
        if not str(header.get("original_name", "")).strip():
            row["issues"].append("Original name is missing")
        try:
            original_size = int(header.get("original_size", -1))
            if original_size < 0:
                raise ValueError
        except (TypeError, ValueError):
            row["issues"].append("Original size is invalid")
        if row["key_id"] and not re.fullmatch(r"[0-9a-fA-F]{16}", row["key_id"]):
            row["issues"].append("Key ID format is invalid")
        if info["portable"]:
            if int(header.get("format_version", 0)) != locker.PORTABLE_FORMAT_VERSION:
                row["issues"].append("Portable format version is unsupported")
            locker.portable_crypto_from_header(header)
        else:
            row["issues"].append("Legacy lock should be upgraded to portable format")
        if loaded_key_id:
            if row["key_id"]:
                row["key_match"] = "match" if row["key_id"] == loaded_key_id else "mismatch"
            else:
                row["key_match"] = "missing key ID"
        if not row["issues"]:
            row["health"] = "Healthy"
        elif not info["portable"] and len(row["issues"]) == 1:
            row["health"] = "Legacy"
        else:
            row["health"] = "Review"
    except Exception as exc:
        row["issues"] = [str(exc)]
        row["health"] = "Unreadable"
    return row


def build_privacy_safe_health_report(rows, scope="scan", loaded_key=False):
    rows = list(rows)
    health = Counter(str(row.get("health", "unknown")).lower() for row in rows)
    formats = Counter(str(row.get("format", "unknown")).lower() for row in rows)
    kinds = Counter(str(row.get("kind", "unknown")).lower() for row in rows)
    key_matches = Counter(str(row.get("key_match", "not checked")).lower() for row in rows)
    issue_counts = Counter()
    for row in rows:
        for issue in row.get("issues") or []:
            text = str(issue).lower()
            if "legacy" in text:
                issue_counts["legacy_format"] += 1
            elif "key id" in text:
                issue_counts["key_id_metadata"] += 1
            elif "original" in text:
                issue_counts["original_metadata"] += 1
            elif "cipher" in text or "scrypt" in text or "nonce" in text or "salt" in text:
                issue_counts["cryptographic_header"] += 1
            else:
                issue_counts["unreadable_or_other"] += 1
    recommendations = []
    if health.get("unreadable", 0):
        recommendations.append("Keep unreadable locked files unchanged and restore them from a known-good backup if available.")
    if health.get("legacy", 0) or formats.get("legacy windows-only", 0):
        recommendations.append("Upgrade legacy Windows-only locks from the main app while keeping the originals.")
    if key_matches.get("mismatch", 0):
        recommendations.append("Load the matching master USB key before attempting to unlock mismatched items.")
    if not rows:
        recommendations.append("No locked files were found in the selected scan scope.")
    if not recommendations:
        recommendations.append("No structural locked-file issues were found. Keep verified backups of every required USB key.")
    return {
        "schema_version": 1,
        "report_type": "vaultlink-vault-health",
        "created_at_utc": locker.utc_now_text(),
        "scope": str(scope)[:40],
        "loaded_key_compared": bool(loaded_key),
        "locked_file_count": len(rows),
        "health_counts": dict(sorted(health.items())),
        "format_counts": dict(sorted(formats.items())),
        "kind_counts": dict(sorted(kinds.items())),
        "key_match_counts": dict(sorted(key_matches.items())),
        "issue_category_counts": dict(sorted(issue_counts.items())),
        "recommendations": recommendations,
        "limitations": [
            "This is a read-only structural and metadata check.",
            "It does not decrypt files or prove the AES-GCM authentication tag without the exact key and optional PIN.",
        ],
        "privacy_note": (
            "This report excludes filenames, paths, original names, key IDs, USB secrets, PINs, passwords, "
            "license data, and file contents."
        ),
    }


class VaultHealthCenter(tk.Tk):
    def __init__(self):
        super().__init__()
        if not locker.ensure_license_feature("locked-file-browser", parent=self):
            self.after(0, self.destroy)
            return
        self.title("Vault Health Center")
        self.geometry("1180x780")
        self.minsize(1000, 680)
        self.configure(bg=locker.BG)
        self.rows = []
        self.filtered_rows = []
        self.loaded_key_id = ""
        self.scope = "quick-scan"
        self.results = queue.Queue()
        self.busy = False
        self.closing = False
        self.status_var = tk.StringVar(value="Ready for a read-only locked-file health scan.")
        self.key_var = tk.StringVar(value="KEY CHECK: NOT LOADED")
        self.summary_var = tk.StringVar(value="No scan has run yet.")
        self.search_var = tk.StringVar()
        self.scan_buttons = []
        self.build_ui()
        self.protocol("WM_DELETE_WINDOW", self.close_requested)

    def build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "VaultHealth.Treeview",
            background=locker.FIELD,
            fieldbackground=locker.FIELD,
            foreground=locker.TEXT,
            rowheight=28,
            borderwidth=0,
            font=("Segoe UI", 9),
        )
        style.configure(
            "VaultHealth.Treeview.Heading",
            background="#252936",
            foreground=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        style.map(
            "VaultHealth.Treeview",
            background=[("selected", locker.GREEN)],
            foreground=[("selected", locker.BLACK)],
        )
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=20)
        tk.Label(outer, text="Vault Health Center", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 25, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="READ-ONLY HEADER CHECK | KEY-ID COMPATIBILITY | PRIVACY-SAFE REPORTS",
            bg=locker.BG,
            fg=locker.GREEN,
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w", pady=(4, 14))

        toolbar = tk.Frame(outer, bg=locker.BG)
        toolbar.pack(fill="x", pady=(0, 12))
        actions = [
            ("QUICK SCAN", self.quick_scan, locker.GREEN, locker.BLACK),
            ("CHOOSE FOLDER", self.choose_folder_scan, locker.YELLOW, locker.BLACK),
            ("LOAD KEY FOR MATCH CHECK", self.load_key, "#252936", locker.TEXT),
            ("EXPORT SAFE REPORT", self.export_report, "#252936", locker.TEXT),
            ("OPEN MAIN LOCKER", self.open_main_locker, "#252936", locker.TEXT),
            ("OPEN LOCKED BROWSER", self.open_locked_browser, "#252936", locker.TEXT),
        ]
        for label, command, background, foreground in actions:
            button = tk.Button(toolbar, text=label, command=command, bg=background, fg=foreground, relief="flat", font=("Segoe UI", 8, "bold"))
            button.pack(side="left", padx=(0, 8), ipadx=9, ipady=7)
            if label in {"QUICK SCAN", "CHOOSE FOLDER"}:
                self.scan_buttons.append(button)

        summary = tk.Frame(outer, bg=locker.PANEL)
        summary.pack(fill="x", pady=(0, 12))
        tk.Label(summary, textvariable=self.key_var, bg=locker.PANEL, fg=locker.YELLOW, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=16, pady=(12, 2))
        tk.Label(summary, textvariable=self.summary_var, bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 10, "bold"), wraplength=1050, justify="left").pack(anchor="w", padx=16, pady=(2, 12))

        search_row = tk.Frame(outer, bg=locker.BG)
        search_row.pack(fill="x", pady=(0, 10))
        tk.Label(search_row, text="FILTER", bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        search = tk.Entry(search_row, textvariable=self.search_var, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 10))
        search.pack(side="left", fill="x", expand=True, padx=(10, 0), ipady=6)
        search.bind("<KeyRelease>", lambda _event: self.apply_filter())

        body = tk.PanedWindow(outer, sashwidth=6, bg=locker.BG, bd=0, relief="flat")
        body.pack(fill="both", expand=True)
        left = tk.Frame(body, bg=locker.BG)
        right = tk.Frame(body, bg=locker.BG)
        body.add(left, stretch="always")
        body.add(right, minsize=330)

        columns = ("name", "format", "kind", "health", "key", "folder")
        self.tree = ttk.Treeview(left, columns=columns, show="headings", height=20, style="VaultHealth.Treeview")
        for column, title, width in (
            ("name", "Locked Item", 230),
            ("format", "Format", 135),
            ("kind", "Kind", 90),
            ("health", "Health", 90),
            ("key", "Key Check", 110),
            ("folder", "Folder", 330),
        ):
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda _event: self.update_details())
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        scroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scroll.set)

        tk.Label(right, text="Selected Health", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 17, "bold")).pack(anchor="w")
        self.details = tk.Text(right, bg=locker.FIELD, fg=locker.TEXT, relief="flat", wrap="word", font=("Consolas", 9), state="disabled")
        self.details.pack(fill="both", expand=True, pady=(10, 8))
        tk.Button(right, text="OPEN SELECTED FOLDER", command=self.open_selected_folder, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold")).pack(anchor="w", ipadx=10, ipady=7)

        tk.Label(outer, textvariable=self.status_var, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9), wraplength=1100, justify="left").pack(anchor="w", pady=(10, 0))

    def set_busy(self, enabled):
        self.busy = bool(enabled)
        for button in self.scan_buttons:
            button.configure(state="disabled" if enabled else "normal")

    def quick_scan(self):
        self.start_scan(locker.common_user_dirs(), "quick-scan", 1200)

    def choose_folder_scan(self):
        folder = filedialog.askdirectory(title="Choose folder for read-only vault health scan", parent=self)
        if folder:
            self.start_scan([Path(folder)], "selected-folder", 2500)

    def start_scan(self, roots, scope, max_results):
        if self.busy:
            return
        self.scope = scope
        self.set_busy(True)
        self.status_var.set("Scanning locked-file headers without decrypting file contents...")
        key_id = self.loaded_key_id

        def worker():
            try:
                paths = locker.find_locked_files_in_roots(roots, max_results=max_results)
                rows = [inspect_locked_file(path, key_id) for path in paths]
                error = ""
            except Exception as exc:
                rows = []
                error = str(exc)
            self.results.put((rows, error))

        threading.Thread(target=worker, name="VaultHealthScan", daemon=True).start()
        self.after(75, self.poll_results)

    def poll_results(self):
        try:
            rows, error = self.results.get_nowait()
        except queue.Empty:
            if self.busy and not self.closing:
                self.after(75, self.poll_results)
            return
        self.set_busy(False)
        if error:
            self.status_var.set(f"Vault health scan failed: {error}")
            locker.log_event("vault_health_scan", "scan", "failed")
            return
        self.rows = sorted(rows, key=lambda row: row["path"].lower())
        self.apply_filter()
        report = build_privacy_safe_health_report(self.rows, self.scope, bool(self.loaded_key_id))
        counts = report["health_counts"]
        self.summary_var.set(
            f"Locked items: {len(self.rows)} | Healthy: {counts.get('healthy', 0)} | "
            f"Legacy: {counts.get('legacy', 0)} | Review: {counts.get('review', 0)} | "
            f"Unreadable: {counts.get('unreadable', 0)}"
        )
        self.status_var.set("Read-only vault health scan complete. No locked file was modified or decrypted.")
        locker.log_event("vault_health_scan", "scan", "ok")

    def load_key(self):
        path = filedialog.askopenfilename(title="Choose master USB key for ID matching", filetypes=[("USB locker key", "*.key"), ("All files", "*.*")], parent=self)
        if not path:
            return
        try:
            key = locker.load_key_file(path)
            self.loaded_key_id = key["key_id"]
            self.key_var.set(f"KEY CHECK: LOADED ID {self.loaded_key_id}")
            self.status_var.set("Loaded the key ID for compatibility checks. File contents remain encrypted.")
            if self.rows:
                self.rows = [inspect_locked_file(row["path"], self.loaded_key_id) for row in self.rows]
                self.apply_filter()
            locker.log_event("vault_health_key_check", "key", "ok")
        except Exception as exc:
            self.status_var.set("Could not load the selected key for compatibility checking.")
            locker.log_event("vault_health_key_check", "key", "failed")
            messagebox.showerror("Key check failed", str(exc), parent=self)

    def apply_filter(self):
        needle = self.search_var.get().strip().lower()
        if needle:
            self.filtered_rows = [
                row for row in self.rows
                if needle in row["name"].lower()
                or needle in row["folder"].lower()
                or needle in row["format"].lower()
                or needle in row["health"].lower()
                or needle in row["key_match"].lower()
            ]
        else:
            self.filtered_rows = list(self.rows)
        self.tree.delete(*self.tree.get_children())
        for index, row in enumerate(self.filtered_rows):
            self.tree.insert("", "end", iid=str(index), values=(row["name"], row["format"], row["kind"], row["health"], row["key_match"], row["folder"]))
        if self.filtered_rows:
            self.tree.selection_set("0")
        self.update_details()

    def selected_row(self):
        selection = self.tree.selection()
        if not selection:
            return None
        try:
            return self.filtered_rows[int(selection[0])]
        except Exception:
            return None

    def update_details(self):
        row = self.selected_row()
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        if row is None:
            self.details.insert("1.0", "Select a locked item to view its read-only health result.")
        else:
            lines = [
                f"Name: {row['name']}",
                f"Folder: {row['folder']}",
                f"Format: {row['format']}",
                f"Kind: {row['kind']}",
                f"Health: {row['health']}",
                f"Key check: {row['key_match']}",
                f"Security profile: {row['security_profile']}",
                "",
                "Issues:",
                *([f"- {issue}" for issue in row["issues"]] or ["- None found in the structural header check."]),
                "",
                "The encrypted contents and AES-GCM tag were not decrypted or exposed.",
            ]
            self.details.insert("1.0", "\n".join(lines))
        self.details.configure(state="disabled")

    def export_report(self):
        report = build_privacy_safe_health_report(self.rows, self.scope, bool(self.loaded_key_id))
        target = filedialog.asksaveasfilename(
            title="Export privacy-safe vault health report",
            defaultextension=".json",
            initialfile="VaultLink-Vault-Health-Report.json",
            filetypes=[("JSON report", "*.json")],
            parent=self,
        )
        if not target:
            return
        try:
            locker.write_text_atomic(Path(target), json.dumps(report, indent=2))
            self.status_var.set("Exported the privacy-safe vault health report.")
            locker.log_event("vault_health_report_export", "report", "ok")
        except Exception as exc:
            locker.log_event("vault_health_report_export", "report", "failed")
            messagebox.showerror("Report export failed", str(exc), parent=self)

    def open_selected_folder(self):
        row = self.selected_row()
        if row is None:
            messagebox.showinfo("Nothing selected", "Choose a locked item first.", parent=self)
            return
        try:
            os.startfile(Path(row["folder"]))
        except Exception as exc:
            messagebox.showerror("Could not open folder", str(exc), parent=self)

    def open_main_locker(self):
        try:
            locker.launch_main_app_process()
        except Exception as exc:
            messagebox.showerror("Could not open main locker", str(exc), parent=self)

    def open_locked_browser(self):
        try:
            locker.launch_companion_script("locked_file_browser.py")
        except Exception as exc:
            messagebox.showerror("Could not open Locked File Browser", str(exc), parent=self)

    def close_requested(self):
        self.closing = True
        self.destroy()


if __name__ == "__main__":
    VaultHealthCenter().mainloop()
