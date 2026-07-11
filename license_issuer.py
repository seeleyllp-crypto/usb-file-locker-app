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


PLAN_CHOICES = {
    "$5 Starter": "starter",
    "$50 Plus": "plus",
    "$100 Pro": "pro",
    "$200 Signature": "signature",
}

EXPIRY_CHOICES = {
    "Never expires": 0,
    "30 days": 30,
    "90 days": 90,
    "1 year": 365,
}


class LicenseIssuer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VaultLink License Issuer")
        self.geometry("900x850")
        self.minsize(820, 800)
        self.configure(bg=locker.BG)
        self.server_var = tk.StringVar(value=locker.DEFAULT_LICENSE_SERVER)
        self.admin_token_var = tk.StringVar(value="")
        self.show_token_var = tk.BooleanVar(value=False)
        self.plan_var = tk.StringVar(value="$100 Pro")
        self.customer_var = tk.StringVar(value="")
        self.email_var = tk.StringVar(value="")
        self.max_devices_var = tk.StringVar(value="1")
        self.expiry_var = tk.StringVar(value="Never expires")
        self.status_var = tk.StringVar(value="Ready to issue a license.")
        self.issue_results = queue.Queue()
        self.issue_busy = False
        self.latest_response = None
        self.issue_button = None
        self.copy_button = None
        self.save_button = None
        self.result_text = None
        self.token_entry = None
        self.build_ui()
        self.protocol("WM_DELETE_WINDOW", self.close_window)

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=26, pady=22)

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

        self.add_label(form, "PLAN", 4, 0)
        self.add_label(form, "MAX DEVICES", 4, 1)
        ttk.Combobox(
            form,
            textvariable=self.plan_var,
            values=list(PLAN_CHOICES),
            state="readonly",
            font=("Segoe UI", 10),
        ).grid(row=5, column=0, sticky="ew", padx=(18, 8), ipady=5)
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
        ).grid(row=5, column=1, sticky="ew", padx=(8, 18), ipady=5)

        self.add_label(form, "CUSTOMER LABEL, OPTIONAL", 6, 0)
        self.add_label(form, "CUSTOMER EMAIL, OPTIONAL", 6, 1)
        tk.Entry(
            form,
            textvariable=self.customer_var,
            bg=locker.FIELD,
            fg=locker.TEXT,
            insertbackground=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 10),
        ).grid(row=7, column=0, sticky="ew", padx=(18, 8), ipady=7)
        tk.Entry(
            form,
            textvariable=self.email_var,
            bg=locker.FIELD,
            fg=locker.TEXT,
            insertbackground=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 10),
        ).grid(row=7, column=1, sticky="ew", padx=(8, 18), ipady=7)

        self.add_label(form, "EXPIRATION", 8, 0)
        ttk.Combobox(
            form,
            textvariable=self.expiry_var,
            values=list(EXPIRY_CHOICES),
            state="readonly",
            font=("Segoe UI", 10),
        ).grid(row=9, column=0, sticky="ew", padx=(18, 8), pady=(0, 18), ipady=5)

        action_row = tk.Frame(form, bg=locker.PANEL)
        action_row.grid(row=9, column=1, sticky="e", padx=(8, 18), pady=(0, 18))
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
            height=8,
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
        self.save_button.configure(state="normal")
        locker.log_event("license_issue", "api", "ok")
        self.status_var.set("License issued. Send only the license key to the customer.")

    def show_response(self, response):
        license_info = response.get("license") or {}
        plan = response.get("plan") or {}
        lines = [
            f"License ID: {license_info.get('license_id', '')}",
            f"Plan: {plan.get('name', license_info.get('plan_name', ''))}",
            f"Expires: {license_info.get('expires_at_utc') or 'Never'}",
            f"Max devices claim: {license_info.get('max_devices', '')}",
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

    def close_window(self):
        self.admin_token_var.set("")
        self.latest_response = None
        self.destroy()


if __name__ == "__main__":
    app = LicenseIssuer()
    app.mainloop()
