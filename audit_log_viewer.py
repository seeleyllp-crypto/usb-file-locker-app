import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

import usb_file_locker as locker


class AuditLogViewer(tk.Tk):
    def __init__(self):
        super().__init__()
        if not locker.ensure_license_feature("audit-log-viewer", parent=self):
            self.after(0, self.destroy)
            return
        self.title("Audit Log Viewer")
        self.geometry("1260x860")
        self.minsize(1080, 760)
        self.configure(bg=locker.BG)
        settings = locker.load_settings()
        self.owner_policy = locker.load_owner_policy(settings)
        key_path = settings.get("last_key_path", "")
        if not key_path:
            for candidate in locker.bundled_key_candidates():
                key_path = str(candidate)
                break
        self.key_path = tk.StringVar(value=key_path)
        self.pin_var = tk.StringVar(value="")
        self.search_var = tk.StringVar(value="")
        self.result_filter = tk.StringVar(value="all")
        self.status = tk.StringVar(value="Refresh to load the audit chain.")
        self.verify_text = tk.StringVar(value="")
        self.breach_text = tk.StringVar(value="")
        self.defender_text = tk.StringVar(value="")
        self.count_text = tk.StringVar(value="")
        self.records = []
        self.filtered_records = []
        self.latest_verification = (True, 0, "No audit events have been recorded yet.")
        self.api_export_busy = False
        self.api_export_results = queue.Queue()
        self.api_export_button = None
        self.tree = None
        self.details = None
        self.build_ui()
        locker.log_event("audit_viewer_open", locker.LOG_FILE, "ok")
        self.refresh_data()

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=22)

        tk.Label(outer, text="Audit Log Viewer", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 28, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="Privacy-safe activity history with hash-chain verification, Defender summary, and easy export tools.",
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 14))

        top = tk.Frame(outer, bg=locker.PANEL)
        top.pack(fill="x")

        tk.Label(top, text="USB KEY FOR LOCKED EXPORT", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).grid(row=0, column=0, sticky="w", padx=18, pady=(18, 4))
        tk.Entry(top, textvariable=self.key_path, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 10)).grid(row=1, column=0, sticky="ew", padx=18, ipady=7)
        tk.Button(top, text="BROWSE", command=self.pick_key, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).grid(row=1, column=1, padx=(0, 18), ipadx=10, ipady=6)

        tk.Label(top, text="OPTIONAL PIN FOR LOCKED EXPORT", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).grid(row=0, column=2, sticky="w", padx=(0, 18), pady=(18, 4))
        tk.Entry(top, textvariable=self.pin_var, show="*", bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 10), width=24).grid(row=1, column=2, sticky="ew", padx=(0, 18), ipady=7)

        action_row = tk.Frame(top, bg=locker.PANEL)
        action_row.grid(row=2, column=0, columnspan=3, sticky="ew", padx=18, pady=(12, 10))
        tk.Button(action_row, text="REFRESH", command=self.refresh_data, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=14, ipady=8)
        tk.Button(action_row, text="BREACH CHECK", command=self.open_breach_check, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(action_row, text="EXPORT RAW", command=self.export_raw, bg=locker.WHITE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(action_row, text="EXPORT LOCKED REPORT", command=self.export_locked_report, bg=locker.YELLOW, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(action_row, text="OPEN AUDIT FOLDER", command=self.open_audit_folder, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(action_row, text="OPEN MAIN LOCKER", command=self.open_main_locker, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=12, ipady=8)

        api_row = tk.Frame(top, bg=locker.PANEL)
        api_row.grid(row=3, column=0, columnspan=3, sticky="ew", padx=18, pady=(0, 18))
        self.api_export_button = tk.Button(
            api_row,
            text="UPLOAD + DOWNLOAD API COPY",
            command=self.upload_download_api_copy,
            bg="#4d8cff",
            fg=locker.WHITE,
            activebackground="#6ba0ff",
            activeforeground=locker.WHITE,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        self.api_export_button.pack(side="left", ipadx=14, ipady=8)
        tk.Label(
            api_row,
            text="PRIVACY-SAFE FIELDS ONLY | SIGNED DOWNLOAD | SHORT-LIVED SERVER COPY",
            bg=locker.PANEL,
            fg=locker.MUTED,
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", padx=(12, 0))

        top.columnconfigure(0, weight=1)
        top.columnconfigure(2, weight=1)

        summary = tk.Frame(outer, bg=locker.PANEL)
        summary.pack(fill="x", pady=(14, 14))
        tk.Label(summary, text="Current Status", bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=18, pady=(16, 6))
        tk.Label(summary, textvariable=self.verify_text, bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 10, "bold"), justify="left", wraplength=1160).pack(anchor="w", padx=18)
        tk.Label(summary, textvariable=self.breach_text, bg=locker.PANEL, fg=locker.YELLOW, font=("Segoe UI", 9, "bold"), justify="left", wraplength=1160).pack(anchor="w", padx=18, pady=(8, 0))
        tk.Label(summary, textvariable=self.defender_text, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 9), justify="left", wraplength=1160).pack(anchor="w", padx=18, pady=(8, 0))
        tk.Label(summary, textvariable=self.count_text, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 9), justify="left", wraplength=1160).pack(anchor="w", padx=18, pady=(8, 16))

        filters = tk.Frame(outer, bg=locker.BG)
        filters.pack(fill="x", pady=(0, 12))
        tk.Label(filters, text="SEARCH", bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        search_entry = tk.Entry(filters, textvariable=self.search_var, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 10), width=36)
        search_entry.pack(side="left", padx=(10, 18), ipady=7)
        tk.Label(filters, text="SHOW", bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        tk.Radiobutton(filters, text="ALL", value="all", variable=self.result_filter, command=self.apply_filter, bg=locker.BG, fg=locker.TEXT, selectcolor=locker.FIELD, activebackground=locker.BG, activeforeground=locker.TEXT, font=("Segoe UI", 8, "bold")).pack(side="left", padx=(10, 0))
        tk.Radiobutton(filters, text="SUCCESS", value="success", variable=self.result_filter, command=self.apply_filter, bg=locker.BG, fg=locker.TEXT, selectcolor=locker.FIELD, activebackground=locker.BG, activeforeground=locker.TEXT, font=("Segoe UI", 8, "bold")).pack(side="left", padx=(10, 0))
        tk.Radiobutton(filters, text="FAILURE", value="failure", variable=self.result_filter, command=self.apply_filter, bg=locker.BG, fg=locker.TEXT, selectcolor=locker.FIELD, activebackground=locker.BG, activeforeground=locker.TEXT, font=("Segoe UI", 8, "bold")).pack(side="left", padx=(10, 0))
        search_entry.bind("<KeyRelease>", lambda _event: self.apply_filter())

        body = tk.Frame(outer, bg=locker.BG)
        body.pack(fill="both", expand=True)

        left = tk.Frame(body, bg=locker.PANEL)
        left.pack(side="left", fill="both", expand=True)

        columns = ("sequence", "time", "event_id", "action", "result")
        self.tree = ttk.Treeview(left, columns=columns, show="headings", height=18)
        self.tree.heading("sequence", text="Seq")
        self.tree.heading("time", text="UTC Time")
        self.tree.heading("event_id", text="Event ID")
        self.tree.heading("action", text="Action")
        self.tree.heading("result", text="Result")
        self.tree.column("sequence", width=80, anchor="e")
        self.tree.column("time", width=180, anchor="w")
        self.tree.column("event_id", width=160, anchor="w")
        self.tree.column("action", width=280, anchor="w")
        self.tree.column("result", width=110, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True, padx=(18, 0), pady=18)
        self.tree.bind("<<TreeviewSelect>>", lambda _event: self.update_details())
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        scroll.pack(side="left", fill="y", padx=(0, 18), pady=18)
        self.tree.configure(yscrollcommand=scroll.set)

        right = tk.Frame(body, bg=locker.PANEL, width=360)
        right.pack(side="left", fill="y", padx=(14, 0))
        right.pack_propagate(False)

        tk.Label(right, text="Selected Event", bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=18, pady=(18, 10))
        self.details = tk.Text(right, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", bd=0, wrap="word", font=("Consolas", 10), height=20)
        self.details.pack(fill="both", expand=True, padx=18)

        side_buttons = tk.Frame(right, bg=locker.PANEL)
        side_buttons.pack(fill="x", padx=18, pady=18)
        tk.Button(side_buttons, text="COPY EVENT ID", command=self.copy_event_id, bg=locker.WHITE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(fill="x", pady=(0, 8), ipady=8)
        tk.Button(side_buttons, text="COPY ACTION", command=self.copy_action, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(fill="x", pady=(0, 8), ipady=8)
        tk.Button(side_buttons, text="VERIFY AGAIN", command=self.refresh_data, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(fill="x", pady=(0, 8), ipady=8)
        tk.Button(side_buttons, text="CLOSE", command=self.destroy, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(fill="x", ipady=8)

        tk.Label(outer, textvariable=self.status, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(12, 0))

    def pick_key(self):
        path = filedialog.askopenfilename(title="Load master USB key", filetypes=[("USB locker key", "*.key"), ("All files", "*.*")])
        if path:
            self.key_path.set(path)

    def open_main_locker(self):
        try:
            locker.launch_main_app_process()
            self.status.set("Opened Main Locker.")
        except Exception as exc:
            self.status.set("Could not open Main Locker.")
            messagebox.showerror("Could not open Main Locker", str(exc))

    def load_records(self):
        records = []
        for path in locker.audit_log_paths(locker.APP_DIR):
            if path.exists():
                records.extend(locker.load_audit_records(path))
        return records

    def refresh_data(self):
        try:
            self.records = self.load_records()
            valid, count, message = locker.verify_audit_logs()
            self.latest_verification = (valid, count, message)
            prefix = "Audit chain OK" if valid else "Audit chain needs attention"
            self.verify_text.set(f"{prefix}: {count} event(s). {message}")
            breach = locker.breach_detection_summary(records=self.records, verification=self.latest_verification)
            self.breach_text.set(f"Breach check: {breach['level'].upper()} - {breach['headline']}")
            defender = locker.get_defender_status_report()
            if defender.get("available"):
                rt = "on" if defender.get("RealTimeProtectionEnabled") else "off"
                behavior = "on" if defender.get("BehaviorMonitorEnabled") else "off"
                ioav = "on" if defender.get("IoavProtectionEnabled") else "off"
                protected = "protected now" if defender.get("ProtectedNow") else "not fully protected"
                self.defender_text.set(
                    "Defender: "
                    f"{protected}. Real-time {rt}, behavior monitor {behavior}, downloads/web {ioav}. "
                    f"Quick scan age: {defender.get('QuickScanAge', 'unknown')}. "
                    f"Full scan age: {defender.get('FullScanAge', 'unknown')}."
                )
            else:
                self.defender_text.set(f"Defender status was not available: {defender.get('error', 'unknown error')}")
            latest = self.records[-1] if self.records else None
            if latest:
                self.count_text.set(
                    f"Latest event: seq {latest.get('sequence')} | {latest.get('action')} | {latest.get('result')} | {latest.get('time_utc')}"
                )
            else:
                self.count_text.set("No audit events recorded yet.")
            self.apply_filter()
            self.status.set("Audit data refreshed.")
        except Exception as exc:
            self.records = []
            self.filtered_records = []
            self.tree.delete(*self.tree.get_children())
            self.verify_text.set(f"Audit log could not be read: {exc}")
            self.breach_text.set("")
            self.defender_text.set("")
            self.count_text.set("")
            self.update_details()
            self.status.set("Refresh failed.")

    def open_breach_check(self):
        try:
            locker.open_breach_detection_window(self, records=self.records, verification=self.latest_verification)
            self.status.set("Opened Breach Detection.")
        except Exception as exc:
            self.status.set("Could not open Breach Detection.")
            messagebox.showerror("Could not open Breach Detection", str(exc))

    def apply_filter(self):
        query = self.search_var.get().strip().lower()
        desired = self.result_filter.get()
        filtered = []
        for record in self.records:
            result = str(record.get("result", "")).lower()
            if desired != "all" and result != desired:
                continue
            haystack = " ".join(
                str(record.get(field, ""))
                for field in ("sequence", "time_utc", "event_id", "action", "result", "hash", "previous_hash")
            ).lower()
            if query and query not in haystack:
                continue
            filtered.append(record)
        self.filtered_records = filtered
        self.tree.delete(*self.tree.get_children())
        for index, record in enumerate(filtered):
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    record.get("sequence", ""),
                    record.get("time_utc", ""),
                    record.get("event_id", ""),
                    record.get("action", ""),
                    record.get("result", ""),
                ),
            )
        if filtered:
            self.tree.selection_set("0")
            self.tree.see("0")
        self.update_details()
        self.status.set(f"Showing {len(filtered)} of {len(self.records)} audit event(s).")

    def selected_record(self):
        selection = self.tree.selection()
        if not selection:
            return None
        try:
            return self.filtered_records[int(selection[0])]
        except Exception:
            return None

    def update_details(self):
        record = self.selected_record()
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        if record is None:
            self.details.insert("1.0", "Select an audit event to inspect it here.")
        else:
            lines = [
                f"Sequence: {record.get('sequence', '')}",
                f"Time UTC: {record.get('time_utc', '')}",
                f"Event ID: {record.get('event_id', '')}",
                f"Action: {record.get('action', '')}",
                f"Result: {record.get('result', '')}",
                "",
                f"Hash: {record.get('hash', '')}",
                f"Previous hash: {record.get('previous_hash', '')}",
                "",
                "This audit record is privacy-safe.",
                "It does not include keystrokes, passwords, PINs, file contents, or full paths.",
            ]
            self.details.insert("1.0", "\n".join(lines))
        self.details.configure(state="disabled")

    def copy_selected_field(self, field_name, label):
        record = self.selected_record()
        if record is None:
            messagebox.showinfo("Nothing selected", "Pick an audit event first.")
            return
        value = str(record.get(field_name, "")).strip()
        if not value:
            self.status.set(f"No {label.lower()} to copy.")
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.update()
        self.status.set(f"Copied {label.lower()} to the clipboard.")

    def copy_event_id(self):
        self.copy_selected_field("event_id", "Event ID")

    def copy_action(self):
        self.copy_selected_field("action", "Action")

    def load_key(self):
        key_path = self.key_path.get().strip()
        if not key_path:
            raise ValueError("Choose a USB key first.")
        key = locker.load_key_file(key_path)
        allowed, message = locker.owner_key_allowed(key, self.owner_policy)
        if not allowed:
            raise ValueError(message)
        settings = locker.load_settings()
        settings["last_key_path"] = key_path
        locker.save_settings(settings)
        return key

    def confirmed_pin_if_needed(self):
        pin = self.pin_var.get()
        if not pin:
            return ""
        confirmation = simpledialog.askstring(
            "Confirm optional PIN",
            "Re-enter the exact PIN for this locked audit export.\n\nIf you forget it, the exported report cannot be opened.",
            show="*",
            parent=self,
        )
        if confirmation is None:
            self.status.set("Locked export canceled before PIN confirmation.")
            return None
        if confirmation != pin:
            messagebox.showerror("PINs do not match", "The two PIN entries were different. Nothing was exported.")
            self.status.set("PIN confirmation failed. Nothing was exported.")
            return None
        return pin

    def export_raw(self):
        destination = filedialog.askdirectory(title="Export Audit Log")
        if not destination:
            return
        try:
            copied, summary = locker.export_audit_logs(destination)
            extra = ""
            if summary.get("already_present"):
                extra = f"\nSkipped {summary['already_present']} file(s) already in that folder."
            locker.log_event("audit_viewer_export_raw", destination, "ok", f"files={copied}")
            messagebox.showinfo(
                "Audit Log Exported",
                f"Exported {copied} audit log file(s).{extra}\n\nVerification: {summary['verification']}",
            )
            self.refresh_data()
        except Exception as exc:
            locker.log_event("audit_viewer_export_raw", destination, "failed", str(exc))
            messagebox.showerror("Export failed", str(exc))

    def upload_download_api_copy(self):
        if self.api_export_busy:
            return
        state = locker.load_license_state(locker.load_settings())
        if not locker.license_is_active(state):
            messagebox.showwarning(
                "Active license required",
                "Open License Center in the main locker and activate this PC first.",
                parent=self,
            )
            return
        timestamp = locker.utc_now_text().replace("-", "").replace(":", "").replace("T", "-").replace("Z", "")
        destination = filedialog.asksaveasfilename(
            title="Download API Audit Copy",
            initialdir=str(Path.home() / "Downloads"),
            initialfile=f"vaultlink-audit-{timestamp}.json",
            defaultextension=".json",
            filetypes=[("JSON audit report", "*.json")],
            parent=self,
        )
        if not destination:
            return
        self.api_export_busy = True
        self.api_export_button.configure(state="disabled", text="UPLOADING...")
        self.status.set("Creating a privacy-safe report and sending it to the API...")
        worker = threading.Thread(
            target=self._run_api_export,
            args=(state, destination),
            name="AuditApiExport",
            daemon=True,
        )
        worker.start()
        self.after(50, self._poll_api_export)

    def _run_api_export(self, state, destination):
        try:
            upload = locker.upload_audit_report_online(state)
            out_path = locker.download_audit_export_online(state, upload, destination)
            self.api_export_results.put((True, str(out_path), upload))
        except Exception as exc:
            self.api_export_results.put((False, destination, {"message": str(exc)}))

    def _poll_api_export(self):
        try:
            success, destination, response = self.api_export_results.get_nowait()
        except queue.Empty:
            if self.api_export_busy and self.winfo_exists():
                self.after(50, self._poll_api_export)
            return
        self._finish_api_export(success, destination, response)

    def _finish_api_export(self, success, destination, response):
        self.api_export_busy = False
        if self.api_export_button is not None and self.api_export_button.winfo_exists():
            self.api_export_button.configure(state="normal", text="UPLOAD + DOWNLOAD API COPY")
        if not success:
            error = str(response.get("message") or "The API export failed.")
            locker.log_event("audit_api_export", destination, "failed", error)
            self.status.set("API audit export failed.")
            messagebox.showerror("API export failed", error, parent=self)
            return
        event_count = int(response.get("event_count", 0) or 0)
        expires_at = str(response.get("expires_at_utc", "") or "unknown")
        export_id = str(response.get("export_id", "") or "")
        locker.log_event("audit_api_export", destination, "ok", f"events={event_count}")
        self.status.set(f"API copy downloaded: {export_id}")
        try:
            os.startfile(Path(destination).parent)
        except OSError:
            pass
        messagebox.showinfo(
            "API Audit Copy Downloaded",
            f"Saved {event_count} privacy-safe event(s).\n\n"
            f"File: {destination}\n"
            f"Export ID: {export_id}\n"
            f"Server copy expires: {expires_at}",
            parent=self,
        )
        self.refresh_data()

    def open_audit_folder(self):
        try:
            os.startfile(locker.APP_DIR)
            self.status.set("Opened audit folder.")
        except Exception as exc:
            self.status.set("Could not open the audit folder.")
            messagebox.showerror("Could not open audit folder", str(exc))

    def export_locked_report(self):
        destination = filedialog.askdirectory(title="Save Locked Audit Report")
        if not destination:
            return
        try:
            key = self.load_key()
            pin = self.confirmed_pin_if_needed()
            if pin is None:
                return
            out_path, report = locker.export_locked_audit_report(destination, key, pin)
            protection = "USB key only" if not pin else "USB key and PIN"
            locker.log_event("audit_viewer_export_locked", out_path, "ok", protection)
            messagebox.showinfo(
                "Locked Audit Report Exported",
                "Created locked audit report:\n"
                f"{out_path}\n\n"
                f"Protection: {protection}\n"
                f"USB File Locker events: {report['usb_file_locker_audit']['event_count']}\n"
                f"PC Safety Check events: {report['pc_safety_check_audit']['event_count']}",
            )
            self.refresh_data()
        except Exception as exc:
            locker.log_event("audit_viewer_export_locked", destination, "failed", str(exc))
            messagebox.showerror("Locked export failed", str(exc))


if __name__ == "__main__":
    app = AuditLogViewer()
    app.mainloop()
