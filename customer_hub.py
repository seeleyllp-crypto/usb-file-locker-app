import os
import queue
import threading
import tkinter as tk
from tkinter import messagebox

import usb_file_locker as locker


class CustomerHub(tk.Tk):
    DETAIL_FIELDS = (
        ("LICENSE", "license_status"),
        ("PLAN", "plan"),
        ("DEVICE SEATS", "device_seats"),
        ("DESKTOP", "desktop"),
        ("API", "api"),
        ("SERVICE", "service"),
        ("LAST SYNC", "last_sync"),
        ("OWNER MESSAGES", "owner_messages"),
        ("VERIFIED AUTO-UPDATES", "automatic_updates"),
    )

    def __init__(self):
        super().__init__()
        self.title("VaultLink Customer Hub")
        self.geometry("820x760")
        self.minsize(720, 660)
        self.configure(bg=locker.BG)
        self.settings = locker.load_settings()
        self.state = locker.load_license_state(self.settings)
        self.results = queue.Queue()
        self.busy = False
        self.status_var = tk.StringVar(value="Loading public rank and signed-release information...")
        self.value_vars = {key: tk.StringVar(value="-") for _label, key in self.DETAIL_FIELDS}
        self.verify_button = None
        self.refresh_button = None
        self.rank_box = None
        self.build_ui()
        self.render_details()
        self.after(150, self.refresh_public_info)

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=20)
        tk.Label(outer, text="VaultLink Customer Hub", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 24, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="AVAILABLE TO EVERY RANK | LICENSE PROOF, MACHINE ID, FILES, PATHS, PINS, AND USB SECRETS STAY HIDDEN",
            bg=locker.BG,
            fg=locker.GREEN,
            font=("Segoe UI", 8, "bold"),
            wraplength=760,
            justify="left",
        ).pack(anchor="w", pady=(4, 14))

        details = tk.Frame(outer, bg=locker.PANEL)
        details.pack(fill="x")
        for index, (label, key) in enumerate(self.DETAIL_FIELDS):
            row = tk.Frame(details, bg=locker.PANEL)
            row.pack(fill="x", padx=16, pady=(10 if index == 0 else 4, 0))
            tk.Label(row, text=label, width=22, anchor="w", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
            tk.Label(
                row,
                textvariable=self.value_vars[key],
                anchor="w",
                justify="left",
                bg=locker.PANEL,
                fg=locker.TEXT,
                font=("Segoe UI", 9, "bold"),
                wraplength=520,
            ).pack(side="left", fill="x", expand=True)
        tk.Frame(details, height=10, bg=locker.PANEL).pack(fill="x")

        controls = tk.Frame(outer, bg=locker.BG)
        controls.pack(fill="x", pady=(12, 0))
        self.verify_button = tk.Button(controls, text="VERIFY LICENSE NOW", command=self.verify_now, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold"))
        self.verify_button.pack(side="left", ipadx=10, ipady=7)
        self.refresh_button = tk.Button(controls, text="REFRESH PUBLIC INFO", command=self.refresh_public_info, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.refresh_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=7)
        tk.Button(controls, text="MAIN LOCKER", command=self.open_main_locker, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=10, ipady=7)

        links = tk.Frame(outer, bg=locker.BG)
        links.pack(fill="x", pady=(8, 0))
        for label, path in (
            ("STATUS", "/status"),
            ("DRAFT TERMS", "/terms"),
            ("PRIVACY", "/privacy"),
            ("SHOP", "/shop"),
        ):
            tk.Button(
                links,
                text=label,
                command=lambda value=path: self.open_customer_page(value),
                bg="#252936",
                fg=locker.TEXT,
                relief="flat",
                font=("Segoe UI", 8, "bold"),
            ).pack(side="left", padx=(0 if path == "/status" else 8, 0), ipadx=10, ipady=6)

        tk.Label(outer, text="ALL SEVEN RANKS", bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(14, 6))
        self.rank_box = tk.Text(outer, height=10, bg=locker.FIELD, fg=locker.TEXT, relief="flat", wrap="word", font=("Segoe UI", 9), padx=12, pady=10, state="disabled")
        self.rank_box.pack(fill="both", expand=True)
        tk.Label(outer, textvariable=self.status_var, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9), wraplength=760, justify="left").pack(anchor="w", pady=(10, 0))

    def server_url(self):
        return locker.validated_license_server_url(self.state.get("server_url") or locker.DEFAULT_LICENSE_SERVER)

    def render_details(self):
        details = locker.customer_center_details(self.state, self.settings)
        for key, variable in self.value_vars.items():
            variable.set(details.get(key, "-"))
        has_proof = bool(self.state.get("license_key") and self.state.get("receipt"))
        if self.verify_button is not None:
            self.verify_button.configure(state="normal" if has_proof and not self.busy else "disabled")

    def render_ranks(self, items):
        lines = []
        for item in items:
            lines.append(
                f"RANK {item.get('rank', '?')} | {item.get('name', 'Unknown')} | {item.get('price_label', '')}\n"
                f"{item.get('best_for', '')}"
            )
        text = "\n\n".join(lines) if lines else "Rank information is unavailable."
        self.rank_box.configure(state="normal")
        self.rank_box.delete("1.0", "end")
        self.rank_box.insert("1.0", text)
        self.rank_box.configure(state="disabled")

    def set_busy(self, value):
        self.busy = bool(value)
        self.refresh_button.configure(state="disabled" if value else "normal")
        self.render_details()

    def refresh_public_info(self):
        if self.busy:
            return
        self.set_busy(True)
        self.status_var.set("Checking public ranks and the signed desktop release...")
        server = self.server_url()

        def worker():
            try:
                ranks = locker.license_api_get_json(server, "/api/v1/ranks")
                manifest = locker.check_windows_update_online(server)
                error = ""
            except Exception as exc:
                ranks = None
                manifest = None
                error = str(exc)
            self.results.put(("public", ranks, manifest, error))

        threading.Thread(target=worker, name="CustomerHubPublic", daemon=True).start()
        self.after(75, self.poll_results)

    def verify_now(self):
        if self.busy:
            return
        self.settings = locker.load_settings()
        self.state = locker.load_license_state(self.settings)
        if not self.state.get("license_key") or not self.state.get("receipt"):
            self.status_var.set("Activate a license in the main locker's License Center first.")
            self.render_details()
            return
        self.set_busy(True)
        self.status_var.set("Verifying the saved license with the configured VaultLink API...")
        state = locker.normalize_license_state(self.state)

        def worker():
            try:
                updated = locker.verify_license_online(state)
                error = ""
            except Exception as exc:
                updated = None
                error = str(exc)
            self.results.put(("verify", updated, None, error))

        threading.Thread(target=worker, name="CustomerHubVerify", daemon=True).start()
        self.after(75, self.poll_results)

    def poll_results(self):
        try:
            mode, first, second, error = self.results.get_nowait()
        except queue.Empty:
            if self.busy and self.winfo_exists():
                self.after(75, self.poll_results)
            return
        self.set_busy(False)
        if error:
            self.status_var.set(error)
            locker.log_event("customer_hub_refresh", "api", "failed")
            return
        if mode == "verify":
            self.state = locker.save_license_state(self.settings, first)
            self.render_details()
            self.status_var.set("License and customer status refreshed.")
            locker.log_event("customer_hub_verify", "api", "ok")
            return
        manifest = second or {}
        self.state["api_version"] = manifest.get("api_version", self.state.get("api_version", ""))
        self.state["latest_desktop_version"] = manifest.get("version", "")
        self.state["update_available"] = bool(manifest.get("update_available"))
        self.render_details()
        self.render_ranks((first or {}).get("items") or [])
        self.status_var.set("Public rank and signed-release information refreshed.")
        locker.log_event("customer_hub_refresh", "api", "ok")

    def open_customer_page(self, path):
        try:
            os.startfile(self.server_url() + path)
            self.status_var.set(f"Opened {path} in the browser.")
        except Exception as exc:
            messagebox.showerror("Could not open page", str(exc), parent=self)

    def open_main_locker(self):
        try:
            locker.launch_companion_script("usb_file_locker.py")
            self.status_var.set("Opened the main USB File Locker.")
        except Exception as exc:
            messagebox.showerror("Could not open main locker", str(exc), parent=self)


if __name__ == "__main__":
    CustomerHub().mainloop()
