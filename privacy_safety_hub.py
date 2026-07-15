import os
import tkinter as tk
from pathlib import Path
from tkinter import messagebox

import usb_file_locker as locker


class PrivacySafetyHub(tk.Tk):
    def __init__(self):
        super().__init__()
        if not locker.ensure_license_feature("privacy-safety-hub", parent=self):
            self.after(0, self.destroy)
            return
        self.title("Privacy Safety Hub")
        self.geometry("1180x900")
        self.minsize(1040, 780)
        self.configure(bg=locker.BG)
        self.status = tk.StringVar(value="Loading...")
        self.summary = tk.StringVar(value="")
        self.stats = tk.StringVar(value="")
        self.audit_text = tk.StringVar(value="")
        self.build_ui()
        self.refresh_status()

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=22)

        tk.Label(outer, text="Privacy Safety Hub", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 27, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="Open the locker toolkit, check USB status, and jump into the smaller helper apps.",
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 16))

        top = tk.Frame(outer, bg=locker.BG)
        top.pack(fill="x", pady=(0, 14))
        tk.Button(top, text="REFRESH", command=self.refresh_status, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=14, ipady=8)
        tk.Button(top, text="OPEN APP FOLDER", command=self.open_app_folder, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(top, text="OPEN DATA FOLDER", command=self.open_data_folder, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(top, text="BACK UP DATA", command=self.backup_data, bg=locker.YELLOW, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(top, text="RESTORE DATA", command=self.restore_data, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(top, text="BREACH CHECK", command=self.open_breach_check, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(top, text="OPEN PERM UNLOCK", command=self.open_perm_unlock_folder, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(top, text="CLOSE", command=self.destroy, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=14, ipady=8)

        status_panel = tk.Frame(outer, bg=locker.PANEL)
        status_panel.pack(fill="x", pady=(0, 16))
        tk.Label(status_panel, text="Current Status", bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=18, pady=(16, 6))
        tk.Label(status_panel, textvariable=self.summary, bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 10), justify="left", wraplength=900).pack(anchor="w", padx=18)
        tk.Label(status_panel, textvariable=self.stats, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 9), justify="left", wraplength=900).pack(anchor="w", padx=18, pady=(8, 16))
        tk.Label(status_panel, textvariable=self.audit_text, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 9, "bold"), justify="left", wraplength=900).pack(anchor="w", padx=18, pady=(0, 16))

        apps = tk.Frame(outer, bg=locker.BG)
        apps.pack(fill="both", expand=True)

        self.app_card(apps, "Main Locker", "Full lock, unlock, vault, audit log, and owner USB controls.", self.open_main, 0, 0, locker.WHITE, locker.BLACK)
        self.app_card(apps, "Locked File Browser", "Find .locked files fast, inspect them, and jump into unlock mode.", self.open_browser, 0, 1, "#252936", locker.TEXT)
        self.app_card(apps, "Quick Lock Note", "Type or paste text and turn it into a locked note quickly.", self.open_quick_note, 0, 2, locker.YELLOW, locker.BLACK)
        self.app_card(apps, "Key Inspector", "Check a master USB key, see drive info, and verify owner-key matching.", self.open_key_inspector, 1, 0, "#252936", locker.TEXT)
        self.app_card(apps, "PERM UNLOCK Workbench", "See what is in the PERM UNLOCK folder and relock edited items safely.", self.open_perm_unlock_workbench, 1, 1, locker.YELLOW, locker.BLACK)
        self.app_card(apps, "Personal Vault Pad", "Open the vault in a simpler note-style window with quick local tools.", self.open_personal_vault_pad, 1, 2, "#252936", locker.TEXT)
        self.app_card(apps, "Audit Log Viewer", "Read, verify, and export the privacy-safe activity chain.", self.open_audit_log_viewer, 2, 0, locker.WHITE, locker.BLACK)
        self.app_card(apps, "Text Log Processor", "Parse pasted audit-style text into a cleaner local summary.", self.open_text_log_processor, 2, 1, locker.YELLOW, locker.BLACK)
        self.app_card(apps, "Global Breach Guard", "Watch the signed local audit trail and show high-risk alerts.", self.open_global_breach_guard, 2, 2, locker.WHITE, locker.BLACK)
        self.app_card(apps, "Vault Health Center", "Check locked-file structure, compatibility, legacy formats, and safe health totals.", self.open_vault_health_center, 3, 0, "#252936", locker.TEXT)
        self.app_card(apps, "Trust & Recovery Center", "Combine Defender, audit, USB, license, signed-update, and public trust posture.", self.open_trust_recovery_center, 3, 1, locker.BLUE, locker.BLACK)
        self.app_card(apps, "Customer Workspace", "Review account health, actions, rank tools, releases, and safe exports.", self.open_customer_workspace, 3, 2, "#252936", locker.TEXT)
        self.app_card(apps, "Diagnostics Center", "Run 18 read-only checks and export a privacy-safe troubleshooting report.", self.open_diagnostics_center, 4, 0, locker.GREEN, locker.BLACK)
        self.app_card(apps, "Local Control Center", "Launch approved VaultLink apps from a USB and PIN protected same-PC website.", self.open_local_control_center, 4, 1, locker.BLUE, locker.BLACK)
        self.app_card(apps, "Recovery Readiness", "Open the public fixed-field recovery planner without uploading files or secrets.", self.open_recovery_readiness, 4, 2, locker.YELLOW, locker.BLACK)

        for col in range(3):
            apps.grid_columnconfigure(col, weight=1)
        for row in range(5):
            apps.grid_rowconfigure(row, weight=1)

        tk.Label(outer, textvariable=self.status, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(14, 0))

    def app_card(self, parent, title, body, command, row, column, bg, fg):
        card = tk.Frame(parent, bg=locker.PANEL)
        card.grid(row=row, column=column, sticky="nsew", padx=(0 if column == 0 else 10, 10 if column == 0 else 0), pady=(0 if row == 0 else 10, 10 if row == 0 else 0))
        tk.Label(card, text=title, bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=14, pady=(12, 5))
        tk.Label(card, text=body, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 9), justify="left", wraplength=340).pack(anchor="w", padx=14)
        tk.Button(card, text=f"OPEN {title.upper()}", command=command, bg=bg, fg=fg, relief="flat", font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=14, pady=(10, 12), ipadx=12, ipady=6)

    def refresh_status(self):
        settings = locker.load_settings()
        owner_policy = locker.load_owner_policy(settings)
        lines = []
        stats = []
        last_key = settings.get("last_key_path")
        key = None
        if last_key and Path(last_key).exists():
            try:
                key = locker.load_key_file(last_key)
            except Exception as exc:
                lines.append(f"Saved key path exists but could not be read: {exc}")
        if key:
            lines.append(f"Last key: {key['key_id']} from {locker.key_location_summary(key)}")
        else:
            lines.append("Last key: not currently readable from saved settings.")
        if owner_policy:
            lines.append(f"Owner USB mode: ON - {locker.owner_policy_description(owner_policy)}")
            if key:
                allowed, message = locker.owner_key_allowed(key, owner_policy)
                lines.append("Owner match: yes" if allowed else f"Owner match: no - {message}")
        else:
            lines.append("Owner USB mode: OFF")
        try:
            locked_count = len(locker.find_locked_files())
        except Exception:
            locked_count = "unknown"
        try:
            perm_folder = locker.ensure_perm_unlock_folder()
            perm_unlock_items = len(list(perm_folder.iterdir()))
            perm_folder_text = str(perm_folder)
        except Exception as exc:
            perm_unlock_items = "unknown"
            perm_folder_text = f"Unavailable: {exc}"
        try:
            audit_valid, audit_count, audit_message = locker.verify_audit_logs()
            audit_summary = f"Audit log: {'OK' if audit_valid else 'CHECK'} - {audit_count} events - {audit_message}"
        except Exception as exc:
            audit_summary = f"Audit log: could not verify - {exc}"
        try:
            breach = locker.breach_detection_summary(verification=(audit_valid, audit_count, audit_message))
            audit_summary += f"\nBreach check: {breach['level'].upper()} - {breach['headline']}"
        except Exception:
            pass
        recent_keys = locker.recent_key_paths_from_settings(settings)
        stats.append(f"Fast-scan locked file count: {locked_count}")
        stats.append(f"PERM UNLOCK item count: {perm_unlock_items}")
        stats.append(f"PERM UNLOCK folder: {perm_folder_text}")
        stats.append(f"App folder: {locker.SOURCE_DIR}")
        stats.append(f"Data folder: {locker.APP_DIR}")
        stats.append(f"Saved recent key paths: {len(recent_keys)}")
        self.summary.set("\n".join(lines))
        self.stats.set("\n".join(stats))
        self.audit_text.set(audit_summary)
        self.status.set("Status refreshed.")

    def open_main(self):
        try:
            locker.launch_main_app_process()
            self.status.set("Opened Main Locker.")
        except Exception as exc:
            self.status.set("Could not open Main Locker.")
            messagebox.showerror("Could not open Main Locker", str(exc))

    def open_browser(self):
        try:
            locker.launch_companion_script("locked_file_browser.py")
            self.status.set("Opened Locked File Browser.")
        except Exception as exc:
            self.status.set("Could not open Locked File Browser.")
            messagebox.showerror("Could not open browser", str(exc))

    def open_app_folder(self):
        try:
            os.startfile(locker.SOURCE_DIR)
            self.status.set("Opened app folder.")
        except Exception as exc:
            self.status.set("Could not open the app folder.")
            messagebox.showerror("Could not open app folder", str(exc))

    def open_data_folder(self):
        try:
            os.startfile(locker.APP_DIR)
            self.status.set("Opened data folder.")
        except Exception as exc:
            self.status.set("Could not open the data folder.")
            messagebox.showerror("Could not open data folder", str(exc))

    def backup_data(self):
        destination = locker.filedialog.askdirectory(title="Choose folder for app data backup")
        if not destination:
            self.status.set("App data backup canceled.")
            return
        try:
            backup_dir, copied, _summary = locker.export_app_data_backup(destination)
            self.status.set(f"Backed up app data to {backup_dir}.")
            messagebox.showinfo("App data backed up", f"Saved backup folder:\n{backup_dir}\n\nCopied {len(copied)} file(s).")
        except Exception as exc:
            self.status.set("Could not back up app data.")
            messagebox.showerror("Backup failed", str(exc))

    def restore_data(self):
        source = locker.filedialog.askdirectory(title="Choose app data backup folder to restore")
        if not source:
            self.status.set("App data restore canceled.")
            return
        if not messagebox.askyesno(
            "Restore app data",
            "This will replace matching app-data files in your USB File Locker data folder.\n\n"
            "A safety snapshot of the current app data will be made first.\n\nContinue?",
        ):
            self.status.set("App data restore canceled.")
            return
        try:
            snapshot_dir, restored_files, _summary = locker.restore_app_data_backup(source)
            self.status.set(f"Restored app data from {source}.")
            self.refresh_status()
            messagebox.showinfo(
                "App data restored",
                f"Restored {len(restored_files)} file(s) from:\n{source}\n\n"
                f"Safety snapshot saved in:\n{snapshot_dir}",
            )
        except Exception as exc:
            self.status.set("Could not restore app data.")
            messagebox.showerror("Restore failed", str(exc))

    def open_breach_check(self):
        try:
            locker.open_breach_detection_window(self)
            self.status.set("Opened Breach Detection.")
        except Exception as exc:
            self.status.set("Could not open Breach Detection.")
            messagebox.showerror("Could not open Breach Detection", str(exc))

    def open_perm_unlock_folder(self):
        try:
            os.startfile(locker.ensure_perm_unlock_folder())
            self.status.set("Opened PERM UNLOCK folder.")
        except Exception as exc:
            self.status.set("Could not open the PERM UNLOCK folder.")
            messagebox.showerror("Could not open PERM UNLOCK", str(exc))

    def open_quick_note(self):
        try:
            locker.launch_companion_script("quick_lock_note.py")
            self.status.set("Opened Quick Lock Note.")
        except Exception as exc:
            self.status.set("Could not open Quick Lock Note.")
            messagebox.showerror("Could not open quick note", str(exc))

    def open_key_inspector(self):
        try:
            locker.launch_companion_script("key_inspector.py")
            self.status.set("Opened Key Inspector.")
        except Exception as exc:
            self.status.set("Could not open Key Inspector.")
            messagebox.showerror("Could not open key inspector", str(exc))

    def open_perm_unlock_workbench(self):
        try:
            locker.launch_companion_script("perm_unlock_workbench.py")
            self.status.set("Opened PERM UNLOCK Workbench.")
        except Exception as exc:
            self.status.set("Could not open PERM UNLOCK Workbench.")
            messagebox.showerror("Could not open PERM UNLOCK Workbench", str(exc))

    def open_personal_vault_pad(self):
        try:
            locker.launch_companion_script("personal_vault_pad.py")
            self.status.set("Opened Personal Vault Pad.")
        except Exception as exc:
            self.status.set("Could not open Personal Vault Pad.")
            messagebox.showerror("Could not open Personal Vault Pad", str(exc))

    def open_audit_log_viewer(self):
        try:
            locker.launch_companion_script("audit_log_viewer.py")
            self.status.set("Opened Audit Log Viewer.")
        except Exception as exc:
            self.status.set("Could not open Audit Log Viewer.")
            messagebox.showerror("Could not open Audit Log Viewer", str(exc))

    def open_text_log_processor(self):
        try:
            locker.launch_companion_script("text_log_processor.py")
            self.status.set("Opened Text Log Processor.")
        except Exception as exc:
            self.status.set("Could not open Text Log Processor.")
            messagebox.showerror("Could not open Text Log Processor", str(exc))

    def open_global_breach_guard(self):
        try:
            locker.launch_companion_script("global_breach_guard.py")
            self.status.set("Opened Global Breach Guard.")
        except Exception as exc:
            self.status.set("Could not open Global Breach Guard.")
            messagebox.showerror("Could not open Global Breach Guard", str(exc))

    def open_vault_health_center(self):
        try:
            locker.launch_companion_script("vault_health_center.py")
            self.status.set("Opened Vault Health Center.")
        except Exception as exc:
            self.status.set("Could not open Vault Health Center.")
            messagebox.showerror("Could not open Vault Health Center", str(exc))

    def open_trust_recovery_center(self):
        try:
            locker.launch_companion_script("trust_recovery_center.py")
            self.status.set("Opened Trust & Recovery Center.")
        except Exception as exc:
            self.status.set("Could not open Trust & Recovery Center.")
            messagebox.showerror("Could not open Trust & Recovery Center", str(exc))

    def open_customer_workspace(self):
        try:
            locker.launch_companion_script("customer_hub.py")
            self.status.set("Opened Customer Workspace.")
        except Exception as exc:
            self.status.set("Could not open Customer Workspace.")
            messagebox.showerror("Could not open Customer Workspace", str(exc))

    def open_diagnostics_center(self):
        try:
            locker.launch_companion_script("diagnostics_center.py")
            self.status.set("Opened Diagnostics Center.")
        except Exception as exc:
            self.status.set("Could not open Diagnostics Center.")
            messagebox.showerror("Could not open Diagnostics Center", str(exc))

    def open_local_control_center(self):
        try:
            locker.launch_companion_script("local_control_center.py")
            self.status.set("Opened Local Control Center.")
        except Exception as exc:
            self.status.set("Could not open Local Control Center.")
            messagebox.showerror("Could not open Local Control Center", str(exc))

    def open_recovery_readiness(self):
        try:
            import webbrowser

            settings = locker.load_settings()
            state = locker.load_license_state(settings)
            server = locker.validated_license_server_url(state.get("server_url"))
            webbrowser.open(server + "/readiness", new=2)
            self.status.set("Opened Recovery Readiness.")
        except Exception as exc:
            self.status.set("Could not open Recovery Readiness.")
            messagebox.showerror("Could not open Recovery Readiness", str(exc))


if __name__ == "__main__":
    app = PrivacySafetyHub()
    app.mainloop()
