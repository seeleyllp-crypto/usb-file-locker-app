import json
import os
import queue
import threading
import tkinter as tk
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import usb_file_locker as locker


RANKS = [
    {
        "label": "$5 Starter",
        "id": "starter",
        "best_for": "One Windows PC and basic locking instructions",
        "highlight": "Locking, quick notes, Defender package scan, PIN, recovery, and audit basics",
    },
    {
        "label": "$10-$25 Home",
        "id": "home",
        "best_for": "A home that needs clearer setup and recovery guidance",
        "highlight": "Starter plus home safety, USB-key custody, recovery, and setup guides",
    },
    {
        "label": "$50 Personal Plus",
        "id": "personal-plus",
        "best_for": "Personal records and anonymous Windows safety reporting",
        "highlight": "Personal Vault, file browser, audit viewer, PERM UNLOCK, and personal report",
    },
    {
        "label": "$100 Family Safety",
        "id": "family-safety",
        "best_for": "Families managing anonymous safety records across devices",
        "highlight": "Family reports, Safety Hub, Breach Guard, log processor, and Owner USB mode",
    },
    {
        "label": "$200 Small Office",
        "id": "small-office",
        "best_for": "Small offices needing readiness and evidence workflows",
        "highlight": "Office readiness report, SHA-256 manifest, policies, onboarding, and incident docs",
    },
    {
        "label": "$500-$3,000 Family Office",
        "id": "family-office",
        "best_for": "Multi-PC family offices needing guided setup and records",
        "highlight": "Multi-PC index, evidence bundle, policy pack, records, and adult-led setup",
    },
    {
        "label": "$20,000+ Pro Baseline",
        "id": "pro-baseline",
        "best_for": "A professionally reviewed security baseline",
        "highlight": "Signed release evidence, USB-bound option, review pack, and HIPAA-readiness workspace",
    },
]
PLAN_CHOICES = {item["label"]: item["id"] for item in RANKS}
RANK_BY_LABEL = {item["label"]: item for item in RANKS}

EXPIRY_CHOICES = {
    "Never expires": 0,
    "30 days": 30,
    "90 days": 90,
    "1 year": 365,
}


class ApiAuditLogsWindow(tk.Toplevel):
    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.title("VaultLink API Audit Logs")
        self.geometry("1120x720")
        self.minsize(940, 620)
        self.configure(bg=locker.BG)
        self.records = []
        self.results = queue.Queue()
        self.busy = False
        self.status_var = tk.StringVar(value="Enter the admin token in the issuer, then refresh API logs.")
        self.storage_var = tk.StringVar(value="Storage status has not been checked yet.")
        self.detail_var = tk.StringVar(value="Select a stored report to review its breach summary.")
        self.refresh_button = None
        self.download_button = None
        self.tree = None
        self.build_ui()
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        if owner.admin_token_var.get().strip():
            self.after(100, self.refresh_logs)

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=22)

        tk.Label(
            outer,
            text="API Audit Logs",
            bg=locker.BG,
            fg=locker.TEXT,
            font=("Segoe UI", 25, "bold"),
        ).pack(anchor="w")
        tk.Label(
            outer,
            text="OWNER-ONLY BREACH REVIEW | PRIVACY-SAFE FIELDS | ADMIN TOKEN REQUIRED",
            bg=locker.BG,
            fg=locker.YELLOW,
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w", pady=(4, 14))

        toolbar = tk.Frame(outer, bg=locker.PANEL)
        toolbar.pack(fill="x")
        self.refresh_button = tk.Button(
            toolbar,
            text="REFRESH LOGS",
            command=self.refresh_logs,
            bg=locker.GREEN,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        self.refresh_button.pack(side="left", padx=(16, 0), pady=14, ipadx=14, ipady=8)
        self.download_button = tk.Button(
            toolbar,
            text="DOWNLOAD SELECTED",
            command=self.download_selected,
            state="disabled",
            bg="#58b7e8",
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        self.download_button.pack(side="left", padx=(10, 0), pady=14, ipadx=14, ipady=8)
        tk.Button(
            toolbar,
            text="OPEN DOWNLOADS",
            command=self.open_downloads,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(10, 0), pady=14, ipadx=12, ipady=8)
        tk.Button(
            toolbar,
            text="CLOSE",
            command=self.destroy,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right", padx=(0, 16), pady=14, ipadx=14, ipady=8)

        tk.Label(
            outer,
            textvariable=self.storage_var,
            bg=locker.BG,
            fg=locker.MUTED,
            justify="left",
            wraplength=1050,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", pady=(12, 8))

        columns = ("uploaded", "level", "events", "machine", "plan", "export_id")
        tree_frame = tk.Frame(outer, bg=locker.BG)
        tree_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=14)
        headings = {
            "uploaded": "UPLOADED UTC",
            "level": "BREACH LEVEL",
            "events": "EVENTS",
            "machine": "MACHINE HASH",
            "plan": "RANK ID",
            "export_id": "EXPORT ID",
        }
        widths = {
            "uploaded": 170,
            "level": 110,
            "events": 70,
            "machine": 130,
            "plan": 120,
            "export_id": 245,
        }
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], minwidth=60, anchor="w")
        self.tree.tag_configure("clear", foreground="#74e27f")
        self.tree.tag_configure("warning", foreground="#ffd166")
        self.tree.tag_configure("high", foreground="#ff7b72")
        self.tree.tag_configure("critical", foreground="#ff5c5c")
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _event: self.update_details())

        detail = tk.Label(
            outer,
            textvariable=self.detail_var,
            bg=locker.PANEL,
            fg=locker.TEXT,
            justify="left",
            anchor="w",
            wraplength=1030,
            font=("Segoe UI", 9),
        )
        detail.pack(fill="x", pady=(12, 0), padx=0, ipady=12)
        tk.Label(
            outer,
            textvariable=self.status_var,
            bg=locker.BG,
            fg=locker.MUTED,
            justify="left",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(10, 0))

    def set_busy(self, busy, status):
        self.busy = busy
        if self.refresh_button is not None:
            self.refresh_button.configure(state="disabled" if busy else "normal")
        if self.download_button is not None:
            selected = bool(self.tree.selection()) if self.tree is not None else False
            self.download_button.configure(state="normal" if selected and not busy else "disabled")
        self.status_var.set(status)

    def api_credentials(self):
        server = locker.validated_license_server_url(self.owner.server_var.get())
        token = locker.validated_admin_api_token(self.owner.admin_token_var.get())
        return server, token

    def refresh_logs(self):
        if self.busy:
            return
        try:
            server, token = self.api_credentials()
        except Exception as exc:
            self.status_var.set(str(exc))
            return
        self.set_busy(True, "Loading stored privacy-safe reports from the API...")

        def worker():
            try:
                response = locker.list_admin_audit_exports_online(server, token)
                self.results.put(("list", response, ""))
            except Exception as exc:
                self.results.put(("error", None, str(exc)))

        threading.Thread(target=worker, name="ApiAuditLogList", daemon=True).start()
        self.after(50, self.poll_results)

    def poll_results(self):
        try:
            kind, payload, error = self.results.get_nowait()
        except queue.Empty:
            if self.busy and self.winfo_exists():
                self.after(50, self.poll_results)
            return
        if kind == "error":
            self.set_busy(False, "API log request failed.")
            messagebox.showerror("API logs failed", error, parent=self)
            return
        if kind == "list":
            self.show_listing(payload)
            return
        if kind == "download":
            self.set_busy(False, f"Downloaded API audit report: {payload}")
            locker.log_event("api_audit_download", "api", "ok")
            try:
                os.startfile(Path(payload).parent)
            except OSError:
                pass
            messagebox.showinfo("Audit report downloaded", f"Saved privacy-safe report:\n\n{payload}", parent=self)

    def show_listing(self, response):
        items = response.get("items") or []
        self.records = [item for item in items if isinstance(item, dict)]
        self.tree.delete(*self.tree.get_children())
        for index, item in enumerate(self.records):
            source = item.get("source") or {}
            summary = item.get("breach_summary") or {}
            level = str(summary.get("level", "unknown") or "unknown").lower()
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    item.get("uploaded_at_utc", ""),
                    level.upper(),
                    item.get("event_count", 0),
                    source.get("machine_hash", ""),
                    source.get("plan_id", ""),
                    item.get("export_id", ""),
                ),
                tags=(level,),
            )
        storage = str(response.get("storage", "unknown"))
        retention = int(response.get("retention_hours", 0) or 0)
        if storage == "persistent_configured":
            storage_text = f"Persistent API storage configured | Retention: {retention} hour(s)"
        else:
            storage_text = (
                f"TEMPORARY RAILWAY STORAGE | Retention target: {retention} hour(s) | "
                "Reports can disappear when the service restarts until a Railway Volume is mounted."
            )
        self.storage_var.set(storage_text)
        if self.records:
            self.tree.selection_set("0")
            self.tree.see("0")
        self.update_details()
        self.set_busy(False, f"Loaded {len(self.records)} stored API audit report(s).")
        locker.log_event("api_audit_list", "api", "ok", f"count={len(self.records)}")

    def selected_record(self):
        selection = self.tree.selection()
        if not selection:
            return None
        try:
            return self.records[int(selection[0])]
        except (IndexError, TypeError, ValueError):
            return None

    def update_details(self):
        item = self.selected_record()
        if item is None:
            self.detail_var.set("Select a stored report to review its breach summary.")
            if self.download_button is not None:
                self.download_button.configure(state="disabled")
            return
        summary = item.get("breach_summary") or {}
        signals = summary.get("signals") or []
        signal_text = "; ".join(
            f"{signal.get('level', '').upper()}: {signal.get('title', '')} ({signal.get('count', 0)})"
            for signal in signals
            if isinstance(signal, dict)
        ) or "No suspicious signal was reported in this snapshot."
        self.detail_var.set(
            f"{summary.get('headline', 'No breach summary available.')}  "
            f"Expires: {item.get('expires_at_utc', 'unknown')}  |  {signal_text}"
        )
        if self.download_button is not None and not self.busy:
            self.download_button.configure(state="normal")

    def download_selected(self):
        if self.busy:
            return
        item = self.selected_record()
        if item is None:
            messagebox.showinfo("Nothing selected", "Select an API audit report first.", parent=self)
            return
        try:
            server, token = self.api_credentials()
        except Exception as exc:
            messagebox.showerror("Cannot download", str(exc), parent=self)
            return
        export_id = str(item.get("export_id", "")).strip()
        destination = filedialog.asksaveasfilename(
            title="Download API Audit Report",
            initialdir=str(Path.home() / "Downloads"),
            initialfile=f"vaultlink-audit-{export_id}.json",
            defaultextension=".json",
            filetypes=[("JSON audit report", "*.json")],
            parent=self,
        )
        if not destination:
            return
        self.set_busy(True, f"Downloading {export_id}...")

        def worker():
            try:
                path = locker.download_admin_audit_export_online(
                    server,
                    token,
                    export_id,
                    destination,
                )
                self.results.put(("download", str(path), ""))
            except Exception as exc:
                self.results.put(("error", None, str(exc)))

        threading.Thread(target=worker, name="ApiAuditLogDownload", daemon=True).start()
        self.after(50, self.poll_results)

    def open_downloads(self):
        try:
            os.startfile(Path.home() / "Downloads")
        except OSError as exc:
            messagebox.showerror("Could not open Downloads", str(exc), parent=self)


class LicenseIssuer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VaultLink License Issuer")
        self.geometry("1040x940")
        self.minsize(900, 840)
        self.configure(bg=locker.BG)
        self.server_var = tk.StringVar(value=locker.DEFAULT_LICENSE_SERVER)
        self.admin_token_var = tk.StringVar(value="")
        self.show_token_var = tk.BooleanVar(value=False)
        self.plan_var = tk.StringVar(value="$20,000+ Pro Baseline")
        self.rank_detail_var = tk.StringVar(value="")
        self.customer_var = tk.StringVar(value="")
        self.email_var = tk.StringVar(value="")
        self.note_var = tk.StringVar(value="")
        self.max_devices_var = tk.StringVar(value="1")
        self.expiry_var = tk.StringVar(value="Never expires")
        self.status_var = tk.StringVar(value="Ready to issue a license.")
        self.issue_results = queue.Queue()
        self.issue_busy = False
        self.latest_response = None
        self.issue_button = None
        self.copy_button = None
        self.handoff_button = None
        self.save_button = None
        self.revoke_button = None
        self.result_text = None
        self.token_entry = None
        self.rank_buttons = {}
        self.api_logs_window = None
        self.management_results = queue.Queue()
        self.management_busy = False
        self.build_ui()
        self.protocol("WM_DELETE_WINDOW", self.close_window)

    def build_ui(self):
        page_host = tk.Frame(self, bg=locker.BG)
        page_host.pack(fill="both", expand=True)
        page_canvas = tk.Canvas(page_host, bg=locker.BG, highlightthickness=0, borderwidth=0)
        page_scrollbar = ttk.Scrollbar(page_host, orient="vertical", command=page_canvas.yview)
        page_canvas.configure(yscrollcommand=page_scrollbar.set)
        page_scrollbar.pack(side="right", fill="y")
        page_canvas.pack(side="left", fill="both", expand=True)
        outer = tk.Frame(page_canvas, bg=locker.BG)
        page_window = page_canvas.create_window((0, 0), window=outer, anchor="nw")
        outer.configure(padx=26, pady=22)

        def resize_page(_event=None):
            page_canvas.configure(scrollregion=page_canvas.bbox("all"))

        def fit_page(event):
            page_canvas.itemconfigure(page_window, width=event.width)

        outer.bind("<Configure>", resize_page)
        page_canvas.bind("<Configure>", fit_page)
        self.bind(
            "<MouseWheel>",
            lambda event: page_canvas.yview_scroll(-1 if event.delta > 0 else 1, "units"),
        )

        tk.Label(
            outer,
            text="VaultLink License Issuer",
            bg=locker.BG,
            fg=locker.TEXT,
            font=("Segoe UI", 26, "bold"),
        ).pack(anchor="w")
        tk.Label(
            outer,
            text="OWNER TOOL | ADMIN TOKEN IS MASKED AND NEVER SAVED",
            bg=locker.BG,
            fg=locker.YELLOW,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", pady=(4, 2))
        tk.Label(
            outer,
            text="MANUAL ISSUANCE | THIS APP DOES NOT VERIFY CUSTOMER PAYMENT",
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w", pady=(0, 14))

        form = tk.Frame(outer, bg=locker.PANEL)
        form.pack(fill="x")
        form.columnconfigure(0, weight=1)
        form.columnconfigure(1, weight=1)

        self.add_label(form, "LICENSE API URL", 0, 0, columnspan=2)
        api_row = tk.Frame(form, bg=locker.PANEL)
        api_row.grid(row=1, column=0, columnspan=2, sticky="ew", padx=18)
        api_row.columnconfigure(0, weight=1)
        tk.Entry(
            api_row,
            textvariable=self.server_var,
            bg=locker.FIELD,
            fg=locker.TEXT,
            insertbackground=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 10),
        ).grid(row=0, column=0, sticky="ew", ipady=7)
        tk.Button(
            api_row,
            text="DEFAULT",
            command=lambda: self.server_var.set(locker.DEFAULT_LICENSE_SERVER),
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).grid(row=0, column=1, padx=(10, 0), ipadx=10, ipady=7)

        self.add_label(form, "RAILWAY LICENSE_ADMIN_TOKEN", 2, 0, columnspan=2)
        token_row = tk.Frame(form, bg=locker.PANEL)
        token_row.grid(row=3, column=0, columnspan=2, sticky="ew", padx=18)
        token_row.columnconfigure(0, weight=1)
        self.token_entry = tk.Entry(
            token_row,
            textvariable=self.admin_token_var,
            show="*",
            bg=locker.FIELD,
            fg=locker.TEXT,
            insertbackground=locker.TEXT,
            relief="flat",
            font=("Consolas", 10),
        )
        self.token_entry.grid(row=0, column=0, sticky="ew", ipady=7)
        tk.Checkbutton(
            token_row,
            text="SHOW",
            variable=self.show_token_var,
            command=self.toggle_token,
            bg=locker.PANEL,
            fg=locker.TEXT,
            selectcolor=locker.FIELD,
            activebackground=locker.PANEL,
            activeforeground=locker.TEXT,
            font=("Segoe UI", 8, "bold"),
        ).grid(row=0, column=1, padx=(10, 0))

        self.add_label(form, "ALL 7 LICENSE RANKS", 4, 0, columnspan=2)
        rank_frame = tk.Frame(form, bg=locker.PANEL)
        rank_frame.grid(row=5, column=0, columnspan=2, sticky="ew", padx=18)
        for column in range(4):
            rank_frame.columnconfigure(column, weight=1, uniform="rank")
        for index, rank in enumerate(RANKS):
            label = rank["label"]
            button = tk.Button(
                rank_frame,
                text=f"RANK {index + 1}\n{label}",
                command=lambda selected=label: self.select_rank(selected),
                bg="#252936",
                fg=locker.TEXT,
                activebackground=locker.GREEN,
                activeforeground=locker.BLACK,
                relief="flat",
                borderwidth=0,
                height=2,
                wraplength=210,
                font=("Segoe UI", 9, "bold"),
            )
            button.grid(
                row=index // 4,
                column=index % 4,
                sticky="nsew",
                padx=(0 if index % 4 == 0 else 5, 0),
                pady=(0 if index < 4 else 6, 0),
                ipady=4,
            )
            self.rank_buttons[label] = button
        self.select_rank(self.plan_var.get())
        tk.Label(
            form,
            textvariable=self.rank_detail_var,
            bg=locker.PANEL,
            fg=locker.MUTED,
            justify="left",
            wraplength=960,
            font=("Segoe UI", 9),
        ).grid(row=6, column=0, columnspan=2, sticky="w", padx=18, pady=(8, 0))

        self.add_label(form, "MAX DEVICES", 7, 0)
        self.add_label(form, "EXPIRATION", 7, 1)
        tk.Spinbox(
            form,
            from_=1,
            to=1000,
            textvariable=self.max_devices_var,
            bg=locker.FIELD,
            fg=locker.TEXT,
            buttonbackground="#252936",
            insertbackground=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 10),
        ).grid(row=8, column=0, sticky="ew", padx=(18, 8), ipady=5)
        ttk.Combobox(
            form,
            textvariable=self.expiry_var,
            values=list(EXPIRY_CHOICES),
            state="readonly",
            font=("Segoe UI", 10),
        ).grid(row=8, column=1, sticky="ew", padx=(8, 18), ipady=5)

        self.add_label(form, "CUSTOMER LABEL, OPTIONAL", 9, 0)
        self.add_label(form, "CUSTOMER EMAIL, OPTIONAL", 9, 1)
        tk.Entry(
            form,
            textvariable=self.customer_var,
            bg=locker.FIELD,
            fg=locker.TEXT,
            insertbackground=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 10),
        ).grid(row=10, column=0, sticky="ew", padx=(18, 8), ipady=7)
        tk.Entry(
            form,
            textvariable=self.email_var,
            bg=locker.FIELD,
            fg=locker.TEXT,
            insertbackground=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 10),
        ).grid(row=10, column=1, sticky="ew", padx=(8, 18), ipady=7)

        self.add_label(form, "PRIVATE OWNER NOTE, OPTIONAL", 11, 0, columnspan=2)
        tk.Entry(
            form,
            textvariable=self.note_var,
            bg=locker.FIELD,
            fg=locker.TEXT,
            insertbackground=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 10),
        ).grid(row=12, column=0, columnspan=2, sticky="ew", padx=18, ipady=7)

        action_row = tk.Frame(form, bg=locker.PANEL)
        action_row.grid(row=13, column=0, columnspan=2, sticky="e", padx=18, pady=(14, 18))
        self.issue_button = tk.Button(
            action_row,
            text="ISSUE LICENSE",
            command=self.issue_license,
            bg=locker.GREEN,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 10, "bold"),
        )
        self.issue_button.pack(side="left", ipadx=18, ipady=9)
        tk.Button(
            action_row,
            text="API LOGS",
            command=self.open_api_logs,
            bg="#58b7e8",
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(10, 0), ipadx=12, ipady=9)
        tk.Button(
            action_row,
            text="KEYS + NOTES WEBSITE",
            command=self.open_owner_portal,
            bg=locker.YELLOW,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(10, 0), ipadx=12, ipady=9)
        tk.Button(
            action_row,
            text="API DOCS",
            command=self.open_docs,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(10, 0), ipadx=10, ipady=9)

        result_panel = tk.Frame(outer, bg=locker.PANEL)
        result_panel.pack(fill="both", expand=True, pady=(14, 0))
        tk.Label(
            result_panel,
            text="ISSUED LICENSE",
            bg=locker.PANEL,
            fg=locker.MUTED,
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w", padx=18, pady=(16, 6))
        self.result_text = tk.Text(
            result_panel,
            height=6,
            bg=locker.FIELD,
            fg=locker.TEXT,
            insertbackground=locker.TEXT,
            relief="flat",
            wrap="word",
            font=("Consolas", 10),
            state="disabled",
        )
        self.result_text.pack(fill="both", expand=True, padx=18)

        result_actions = tk.Frame(result_panel, bg=locker.PANEL)
        result_actions.pack(fill="x", padx=18, pady=14)
        self.copy_button = tk.Button(
            result_actions,
            text="COPY LICENSE KEY",
            command=self.copy_license_key,
            state="disabled",
            bg=locker.WHITE,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        self.copy_button.pack(side="left", ipadx=14, ipady=8)
        self.handoff_button = tk.Button(
            result_actions,
            text="COPY CUSTOMER SETUP",
            command=self.copy_customer_handoff,
            state="disabled",
            bg="#58b7e8",
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        self.handoff_button.pack(side="left", padx=(10, 0), ipadx=14, ipady=8)
        self.save_button = tk.Button(
            result_actions,
            text="SAVE RECEIPT JSON",
            command=self.save_receipt,
            state="disabled",
            bg=locker.YELLOW,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        self.save_button.pack(side="left", padx=(10, 0), ipadx=14, ipady=8)
        self.revoke_button = tk.Button(
            result_actions,
            text="REVOKE LATEST",
            command=self.revoke_latest_license,
            state="disabled",
            bg=locker.RED,
            fg=locker.WHITE,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        self.revoke_button.pack(side="left", padx=(10, 0), ipadx=14, ipady=8)
        tk.Button(
            result_actions,
            text="CLEAR TOKEN",
            command=self.clear_token,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right", ipadx=12, ipady=8)

        tk.Label(
            outer,
            textvariable=self.status_var,
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 9),
            wraplength=840,
            justify="left",
        ).pack(anchor="w", pady=(10, 0))

    def add_label(self, parent, text, row, column, columnspan=1):
        tk.Label(
            parent,
            text=text,
            bg=locker.PANEL,
            fg=locker.MUTED,
            font=("Segoe UI", 8, "bold"),
        ).grid(
            row=row,
            column=column,
            columnspan=columnspan,
            sticky="w",
            padx=18,
            pady=(14, 4),
        )

    def toggle_token(self):
        self.token_entry.configure(show="" if self.show_token_var.get() else "*")

    def select_rank(self, label):
        if label not in RANK_BY_LABEL:
            return
        self.plan_var.set(label)
        rank = RANK_BY_LABEL[label]
        rank_number = RANKS.index(rank) + 1
        self.rank_detail_var.set(
            f"Rank {rank_number} | Best for: {rank['best_for']} | Includes: {rank['highlight']}"
        )
        for button_label, button in self.rank_buttons.items():
            selected = button_label == label
            button.configure(
                bg=locker.GREEN if selected else "#252936",
                fg=locker.BLACK if selected else locker.TEXT,
            )

    def clear_token(self):
        self.admin_token_var.set("")
        self.show_token_var.set(False)
        self.toggle_token()
        self.status_var.set("Admin token cleared from memory.")

    def expiry_text(self):
        days = EXPIRY_CHOICES.get(self.expiry_var.get(), 0)
        if not days:
            return ""
        expires = datetime.now(timezone.utc) + timedelta(days=days)
        return expires.strftime("%Y-%m-%dT%H:%M:%SZ")

    def issue_license(self):
        if self.issue_busy:
            return
        try:
            server = locker.validated_license_server_url(self.server_var.get())
            plan_id = PLAN_CHOICES[self.plan_var.get()]
            max_devices = int(self.max_devices_var.get())
            token = self.admin_token_var.get()
            if not token.strip():
                raise ValueError("Enter the Railway LICENSE_ADMIN_TOKEN.")
        except Exception as exc:
            messagebox.showerror("Check issuer fields", str(exc), parent=self)
            return

        self.issue_busy = True
        self.issue_button.configure(state="disabled", text="ISSUING...")
        self.status_var.set("Issuing a signed license through the API...")
        request_data = {
            "server_url": server,
            "admin_token": token,
            "plan_id": plan_id,
            "customer_label": self.customer_var.get(),
            "customer_email": self.email_var.get(),
            "license_note": self.note_var.get(),
            "max_devices": max_devices,
            "expires_at_utc": self.expiry_text(),
        }

        def worker():
            try:
                response = locker.issue_license_online(**request_data)
                error = None
            except Exception as exc:
                response = None
                error = str(exc)
            request_data["admin_token"] = ""
            self.issue_results.put((response, error))

        threading.Thread(target=worker, name="LicenseIssuerRequest", daemon=True).start()
        self.after(50, self.poll_issue_result)

    def poll_issue_result(self):
        try:
            response, error = self.issue_results.get_nowait()
        except queue.Empty:
            if self.issue_busy and self.winfo_exists():
                self.after(50, self.poll_issue_result)
            return
        self.issue_busy = False
        self.issue_button.configure(state="normal", text="ISSUE LICENSE")
        if error:
            locker.log_event("license_issue", "api", "failed")
            self.status_var.set("License issue failed.")
            messagebox.showerror("License issue failed", error, parent=self)
            return
        self.latest_response = response
        self.show_response(response)
        self.copy_button.configure(state="normal")
        self.handoff_button.configure(state="normal")
        self.save_button.configure(state="normal")
        self.revoke_button.configure(state="normal", text="REVOKE LATEST")
        locker.log_event("license_issue", "api", "ok")
        self.status_var.set("License issued. Send only the license key to the customer.")

    def show_response(self, response):
        license_info = response.get("license") or {}
        plan = response.get("plan") or {}
        entitlements = plan.get("entitlements") or license_info.get("entitlements") or []
        entitlement_names = [locker.feature_title(item) for item in entitlements]
        lines = [
            f"License ID: {license_info.get('license_id', '')}",
            f"Rank: {plan.get('rank_label', '')} | {plan.get('name', license_info.get('plan_name', ''))}",
            f"Expires: {license_info.get('expires_at_utc') or 'Never'}",
            f"Max devices claim: {license_info.get('max_devices', '')}",
            f"Private owner note: {self.note_var.get().strip() or 'None'}",
            f"Entitlements ({len(entitlement_names)}): {', '.join(entitlement_names)}",
            "",
            "LICENSE KEY",
            str(response.get("license_key", "")),
            "",
            "Treat this key like a password. The admin token is not included.",
        ]
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", "\n".join(lines))
        self.result_text.configure(state="disabled")

    def copy_license_key(self):
        key = str((self.latest_response or {}).get("license_key", "")).strip()
        if not key:
            return
        self.clipboard_clear()
        self.clipboard_append(key)
        self.update()
        self.status_var.set("License key copied to the clipboard.")

    def copy_customer_handoff(self):
        response = self.latest_response or {}
        key = str(response.get("license_key", "")).strip()
        if not key:
            return
        license_info = response.get("license") or {}
        plan = response.get("plan") or {}
        setup = "\n".join(
            [
                "VaultLink USB File Locker customer setup",
                f"Rank: {plan.get('name', license_info.get('plan_name', ''))}",
                f"License ID: {license_info.get('license_id', '')}",
                f"API: {self.server_var.get().strip()}",
                "",
                "1. Open USB File Locker.",
                "2. Open License and API settings.",
                "3. Paste the license key and choose Activate.",
                "4. Keep the USB master key and recovery copy in separate safe places.",
                "",
                "LICENSE KEY",
                key,
                "",
                "Treat the license key like a password. This note never includes the admin token.",
            ]
        )
        self.clipboard_clear()
        self.clipboard_append(setup)
        self.update()
        self.status_var.set("Customer setup instructions copied without the admin token.")

    def save_receipt(self):
        if not self.latest_response:
            return
        license_info = self.latest_response.get("license") or {}
        license_id = locker.safe_filename_piece(license_info.get("license_id"), "vaultlink-license")
        destination = filedialog.asksaveasfilename(
            title="Save License Receipt",
            initialdir=str(Path.home() / "Downloads"),
            initialfile=f"{license_id}.json",
            defaultextension=".json",
            filetypes=[("JSON license receipt", "*.json")],
            parent=self,
        )
        if not destination:
            return
        try:
            locker.write_text_atomic(destination, json.dumps(self.latest_response, indent=2))
            self.status_var.set(f"Saved license receipt: {destination}")
            try:
                os.startfile(Path(destination).parent)
            except OSError:
                pass
        except Exception as exc:
            messagebox.showerror("Could not save receipt", str(exc), parent=self)

    def open_docs(self):
        try:
            server = locker.validated_license_server_url(self.server_var.get())
            webbrowser.open(server + "/docs")
            self.status_var.set("Opened API documentation.")
        except Exception as exc:
            messagebox.showerror("Could not open API docs", str(exc), parent=self)

    def open_owner_portal(self):
        try:
            server = locker.validated_license_server_url(self.server_var.get())
            webbrowser.open(server + "/owner")
            self.status_var.set("Opened the owner keys and notes website. Enter the admin token there to connect.")
        except Exception as exc:
            messagebox.showerror("Could not open owner website", str(exc), parent=self)

    def revoke_latest_license(self):
        if self.management_busy:
            return
        response = self.latest_response or {}
        license_key = str(response.get("license_key", "")).strip()
        license_info = response.get("license") or {}
        license_id = str(license_info.get("license_id", "")).strip() or "the latest license"
        try:
            server = locker.validated_license_server_url(self.server_var.get())
            token = locker.validated_admin_api_token(self.admin_token_var.get())
            license_key = locker.require_valid_api_license_key(license_key)
        except Exception as exc:
            messagebox.showerror("Cannot revoke license", str(exc), parent=self)
            return
        if not messagebox.askyesno(
            "Revoke license",
            f"Revoke {license_id}?\n\nExisting receipts will stop verifying. You can restore it later from the owner website.",
            parent=self,
        ):
            return
        self.management_busy = True
        self.revoke_button.configure(state="disabled", text="REVOKING...")
        self.status_var.set(f"Revoking {license_id} through the API...")

        def worker():
            try:
                result = locker.revoke_license_online(server, token, license_key)
                error = ""
            except Exception as exc:
                result = None
                error = str(exc)
            self.management_results.put((license_id, result, error))

        threading.Thread(target=worker, name="LicenseRevokeRequest", daemon=True).start()
        self.after(50, self.poll_management_result)

    def poll_management_result(self):
        try:
            license_id, result, error = self.management_results.get_nowait()
        except queue.Empty:
            if self.management_busy and self.winfo_exists():
                self.after(50, self.poll_management_result)
            return
        self.management_busy = False
        if error:
            self.revoke_button.configure(state="normal", text="REVOKE LATEST")
            locker.log_event("license_revoke", "api", "failed")
            self.status_var.set(f"Could not revoke {license_id}.")
            messagebox.showerror("License revoke failed", error, parent=self)
            return
        self.revoke_button.configure(state="disabled", text="REVOKED")
        locker.log_event("license_revoke", "api", "ok")
        self.status_var.set(f"{license_id} is revoked. Restore it from the owner website if needed.")
        messagebox.showinfo(
            "License revoked",
            str((result or {}).get("message") or f"{license_id} was revoked."),
            parent=self,
        )

    def open_api_logs(self):
        if self.api_logs_window is not None:
            try:
                if self.api_logs_window.winfo_exists():
                    self.api_logs_window.lift()
                    self.api_logs_window.focus_force()
                    return
            except tk.TclError:
                pass
        self.api_logs_window = ApiAuditLogsWindow(self)

    def close_window(self):
        self.admin_token_var.set("")
        self.latest_response = None
        self.destroy()


if __name__ == "__main__":
    app = LicenseIssuer()
    app.mainloop()
