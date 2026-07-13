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


def normalize_key_ids(loaded_key_ids):
    if not loaded_key_ids:
        return set()
    if isinstance(loaded_key_ids, str):
        loaded_key_ids = [loaded_key_ids]
    return {str(key_id).strip().lower() for key_id in loaded_key_ids if str(key_id).strip()}


def recovery_status(row, key_check_enabled=False):
    health = str(row.get("health", "")).lower()
    if health == "unreadable":
        return "Unreadable"
    if health == "review":
        return "Review"
    if health == "legacy":
        return "Upgrade first"
    if not key_check_enabled:
        return "Key not checked"
    if row.get("key_match") == "match":
        return "Key ID covered"
    return "Matching key needed"


def inspect_locked_file(path, loaded_key_ids=None):
    path = Path(path)
    loaded_key_ids = normalize_key_ids(loaded_key_ids)
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
        "recovery": "Unknown",
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
        if loaded_key_ids:
            if row["key_id"]:
                row["key_match"] = "match" if row["key_id"].lower() in loaded_key_ids else "mismatch"
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
    row["recovery"] = recovery_status(row, bool(loaded_key_ids))
    return row


def build_privacy_safe_health_report(rows, scope="scan", loaded_key=False):
    rows = list(rows)
    try:
        loaded_key_count = max(0, int(loaded_key))
    except (TypeError, ValueError):
        loaded_key_count = 1 if loaded_key else 0
    health = Counter(str(row.get("health", "unknown")).lower() for row in rows)
    formats = Counter(str(row.get("format", "unknown")).lower() for row in rows)
    kinds = Counter(str(row.get("kind", "unknown")).lower() for row in rows)
    key_matches = Counter(str(row.get("key_match", "not checked")).lower() for row in rows)
    recovery = Counter(str(row.get("recovery", "unknown")).lower() for row in rows)
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
        "loaded_key_compared": loaded_key_count > 0,
        "loaded_key_count": loaded_key_count,
        "locked_file_count": len(rows),
        "health_counts": dict(sorted(health.items())),
        "format_counts": dict(sorted(formats.items())),
        "kind_counts": dict(sorted(kinds.items())),
        "key_match_counts": dict(sorted(key_matches.items())),
        "recovery_counts": dict(sorted(recovery.items())),
        "key_coverage_percent": (
            round(100 * key_matches.get("match", 0) / len(rows), 1)
            if rows and loaded_key_count > 0
            else None
        ),
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


def compare_health_reports(previous, current):
    for label, report in (("Previous", previous), ("Current", current)):
        if not isinstance(report, dict) or report.get("report_type") != "vaultlink-vault-health":
            raise ValueError(f"{label} file is not a VaultLink privacy-safe health report.")

    def count(report, group, name):
        try:
            return int((report.get(group) or {}).get(name, 0))
        except (TypeError, ValueError):
            return 0

    previous_concerns = sum(count(previous, "health_counts", name) for name in ("legacy", "review", "unreadable"))
    current_concerns = sum(count(current, "health_counts", name) for name in ("legacy", "review", "unreadable"))
    if current_concerns < previous_concerns:
        trend = "improved"
    elif current_concerns > previous_concerns:
        trend = "needs attention"
    else:
        trend = "unchanged"
    return {
        "schema_version": 1,
        "comparison_type": "vaultlink-vault-health-aggregate",
        "created_at_utc": locker.utc_now_text(),
        "trend": trend,
        "locked_file_count_delta": int(current.get("locked_file_count", 0)) - int(previous.get("locked_file_count", 0)),
        "healthy_delta": count(current, "health_counts", "healthy") - count(previous, "health_counts", "healthy"),
        "legacy_delta": count(current, "health_counts", "legacy") - count(previous, "health_counts", "legacy"),
        "review_delta": count(current, "health_counts", "review") - count(previous, "health_counts", "review"),
        "unreadable_delta": count(current, "health_counts", "unreadable") - count(previous, "health_counts", "unreadable"),
        "key_covered_delta": count(current, "key_match_counts", "match") - count(previous, "key_match_counts", "match"),
        "privacy_note": "The comparison uses aggregate counters only and contains no filenames, paths, key IDs, secrets, or contents.",
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
        self.loaded_key_ids = set()
        self.scope = "quick-scan"
        self.results = queue.Queue()
        self.busy = False
        self.closing = False
        self.cancel_event = None
        self.status_var = tk.StringVar(value="Ready for a read-only locked-file health scan.")
        self.key_var = tk.StringVar(value="KEY COVERAGE: NO KEYS LOADED")
        self.summary_var = tk.StringVar(value="No scan has run yet.")
        self.comparison_var = tk.StringVar(value="SAFE SNAPSHOT: Run a scan, export it, then compare a later scan.")
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

        primary_toolbar = tk.Frame(outer, bg=locker.BG)
        primary_toolbar.pack(fill="x", pady=(0, 7))
        primary_actions = [
            ("QUICK SCAN", self.quick_scan, locker.GREEN, locker.BLACK),
            ("CHOOSE FOLDER", self.choose_folder_scan, locker.YELLOW, locker.BLACK),
        ]
        for label, command, background, foreground in primary_actions:
            button = tk.Button(primary_toolbar, text=label, command=command, bg=background, fg=foreground, relief="flat", font=("Segoe UI", 8, "bold"))
            button.pack(side="left", padx=(0, 8), ipadx=9, ipady=7)
            self.scan_buttons.append(button)
        self.stop_button = tk.Button(primary_toolbar, text="STOP SCAN", command=self.cancel_scan, state="disabled", bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold"))
        self.stop_button.pack(side="left", padx=(0, 8), ipadx=9, ipady=7)

        secondary_toolbar = tk.Frame(outer, bg=locker.BG)
        secondary_toolbar.pack(fill="x", pady=(0, 12))
        secondary_actions = [
            ("ADD KEY FOR COVERAGE", self.load_key, "#252936", locker.TEXT),
            ("CLEAR KEY IDS", self.clear_keys, "#252936", locker.TEXT),
            ("COMPARE SAFE SNAPSHOT", self.compare_snapshot, "#252936", locker.TEXT),
            ("EXPORT SAFE REPORT", self.export_report, "#252936", locker.TEXT),
            ("OPEN MAIN LOCKER", self.open_main_locker, "#252936", locker.TEXT),
            ("OPEN LOCKED BROWSER", self.open_locked_browser, "#252936", locker.TEXT),
        ]
        for label, command, background, foreground in secondary_actions:
            button = tk.Button(secondary_toolbar, text=label, command=command, bg=background, fg=foreground, relief="flat", font=("Segoe UI", 8, "bold"))
            button.pack(side="left", padx=(0, 8), ipadx=9, ipady=7)

        summary = tk.Frame(outer, bg=locker.PANEL)
        summary.pack(fill="x", pady=(0, 12))
        tk.Label(summary, textvariable=self.key_var, bg=locker.PANEL, fg=locker.YELLOW, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=16, pady=(12, 2))
        tk.Label(summary, textvariable=self.summary_var, bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 10, "bold"), wraplength=1050, justify="left").pack(anchor="w", padx=16, pady=2)
        tk.Label(summary, textvariable=self.comparison_var, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8), wraplength=1050, justify="left").pack(anchor="w", padx=16, pady=(2, 12))

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

        columns = ("name", "format", "health", "key", "recovery")
        self.tree = ttk.Treeview(left, columns=columns, show="headings", height=20, style="VaultHealth.Treeview")
        for column, title, width in (
            ("name", "Locked Item", 180),
            ("format", "Format", 110),
            ("health", "Health", 70),
            ("key", "Key Check", 90),
            ("recovery", "Recovery", 150),
        ):
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, anchor="w", stretch=False)
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
        self.stop_button.configure(state="normal" if enabled else "disabled")

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
        self.cancel_event = threading.Event()
        self.set_busy(True)
        self.status_var.set("Scanning locked-file headers without decrypting file contents...")
        key_ids = set(self.loaded_key_ids)
        cancel_event = self.cancel_event

        def worker():
            try:
                paths = locker.find_locked_files_in_roots(roots, max_results=max_results, stop_event=cancel_event)
                rows = []
                for path in paths:
                    if cancel_event.is_set():
                        break
                    rows.append(inspect_locked_file(path, key_ids))
                error = ""
            except Exception as exc:
                rows = []
                error = str(exc)
            self.results.put((rows, error, cancel_event.is_set()))

        threading.Thread(target=worker, name="VaultHealthScan", daemon=True).start()
        self.after(75, self.poll_results)

    def cancel_scan(self):
        if self.busy and self.cancel_event is not None:
            self.cancel_event.set()
            self.stop_button.configure(state="disabled")
            self.status_var.set("Stopping the read-only scan safely...")

    def poll_results(self):
        try:
            rows, error, cancelled = self.results.get_nowait()
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
        self.update_summary()
        if cancelled:
            self.status_var.set(f"Scan stopped safely after checking {len(self.rows)} locked item(s). No file was modified.")
            locker.log_event("vault_health_scan", "scan", "cancelled")
        else:
            self.status_var.set("Read-only vault health scan complete. No locked file was modified or decrypted.")
            locker.log_event("vault_health_scan", "scan", "ok")

    def update_summary(self):
        report = build_privacy_safe_health_report(self.rows, self.scope, len(self.loaded_key_ids))
        counts = report["health_counts"]
        recovery = report["recovery_counts"]
        coverage = report["key_coverage_percent"]
        coverage_text = "not checked" if coverage is None else f"{coverage:.1f}%"
        self.summary_var.set(
            f"Locked: {len(self.rows)} | Healthy: {counts.get('healthy', 0)} | "
            f"Legacy: {counts.get('legacy', 0)} | Review: {counts.get('review', 0)} | "
            f"Unreadable: {counts.get('unreadable', 0)} | Key coverage: {coverage_text} | "
            f"Key needed: {recovery.get('matching key needed', 0)}"
        )

    def load_key(self):
        path = filedialog.askopenfilename(title="Choose master USB key for ID matching", filetypes=[("USB locker key", "*.key"), ("All files", "*.*")], parent=self)
        if not path:
            return
        try:
            key = locker.load_key_file(path)
            self.loaded_key_ids.add(key["key_id"].lower())
            key_count = len(self.loaded_key_ids)
            self.key_var.set(f"KEY COVERAGE: {key_count} KEY ID{'S' if key_count != 1 else ''} LOADED")
            self.status_var.set("Added a key ID for aggregate coverage checks. The USB secret is not retained by this window.")
            if self.rows:
                self.rows = [inspect_locked_file(row["path"], self.loaded_key_ids) for row in self.rows]
                self.apply_filter()
                self.update_summary()
            locker.log_event("vault_health_key_check", "key", "ok")
        except Exception as exc:
            self.status_var.set("Could not load the selected key for compatibility checking.")
            locker.log_event("vault_health_key_check", "key", "failed")
            messagebox.showerror("Key check failed", str(exc), parent=self)

    def clear_keys(self):
        self.loaded_key_ids.clear()
        self.key_var.set("KEY COVERAGE: NO KEYS LOADED")
        if self.rows:
            self.rows = [inspect_locked_file(row["path"]) for row in self.rows]
            self.apply_filter()
            self.update_summary()
        self.status_var.set("Cleared all loaded key IDs from this window. Locked files were not changed.")
        locker.log_event("vault_health_key_check", "clear", "ok")

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
                or needle in row["recovery"].lower()
            ]
        else:
            self.filtered_rows = list(self.rows)
        self.tree.delete(*self.tree.get_children())
        for index, row in enumerate(self.filtered_rows):
            self.tree.insert("", "end", iid=str(index), values=(row["name"], row["format"], row["health"], row["key_match"], row["recovery"]))
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
                f"Recovery: {row['recovery']}",
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
        report = build_privacy_safe_health_report(self.rows, self.scope, len(self.loaded_key_ids))
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

    def compare_snapshot(self):
        if not self.rows:
            messagebox.showinfo("Run a scan first", "Run a vault health scan before comparing a previous safe snapshot.", parent=self)
            return
        path = filedialog.askopenfilename(
            title="Choose previous privacy-safe vault health report",
            filetypes=[("Vault health report", "*.json")],
            parent=self,
        )
        if not path:
            return
        try:
            previous = json.loads(Path(path).read_text(encoding="utf-8"))
            current = build_privacy_safe_health_report(self.rows, self.scope, len(self.loaded_key_ids))
            comparison = compare_health_reports(previous, current)
            self.comparison_var.set(
                f"SAFE SNAPSHOT: {comparison['trend'].upper()} | Files {comparison['locked_file_count_delta']:+d} | "
                f"Healthy {comparison['healthy_delta']:+d} | Legacy {comparison['legacy_delta']:+d} | "
                f"Review {comparison['review_delta']:+d} | Unreadable {comparison['unreadable_delta']:+d} | "
                f"Key covered {comparison['key_covered_delta']:+d}"
            )
            self.status_var.set("Compared aggregate privacy-safe counters. No filenames, paths, or key IDs were imported.")
            locker.log_event("vault_health_snapshot_compare", "report", "ok")
        except Exception as exc:
            locker.log_event("vault_health_snapshot_compare", "report", "failed")
            messagebox.showerror("Snapshot comparison failed", str(exc), parent=self)

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
        if self.cancel_event is not None:
            self.cancel_event.set()
        self.destroy()


if __name__ == "__main__":
    VaultHealthCenter().mainloop()
