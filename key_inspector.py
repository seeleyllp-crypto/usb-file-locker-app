import os
import os
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

import usb_file_locker as locker


class KeyInspectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Key Inspector")
        self.geometry("860x620")
        self.minsize(780, 560)
        self.configure(bg=locker.BG)
        settings = locker.load_settings()
        key_path = settings.get("last_key_path", "")
        if not key_path:
            for candidate in locker.bundled_key_candidates():
                key_path = str(candidate)
                break
        self.key_path = tk.StringVar(value=key_path)
        self.status = tk.StringVar(value="Choose a master USB key and inspect it.")
        self.owner_policy = locker.load_owner_policy(settings)
        self.build_ui()
        self.inspect_now()

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=22)

        tk.Label(outer, text="Key Inspector", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 25, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="Read a master USB key, see where it lives, and check whether it matches this PC's owner USB rule.",
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 14))

        panel = tk.Frame(outer, bg=locker.PANEL)
        panel.pack(fill="both", expand=True)

        tk.Label(panel, text="MASTER USB KEY", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=18, pady=(18, 4))
        row = tk.Frame(panel, bg=locker.PANEL)
        row.pack(fill="x", padx=18)
        tk.Entry(row, textvariable=self.key_path, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 10)).pack(side="left", fill="x", expand=True, ipady=7)
        tk.Button(row, text="BROWSE", command=self.pick_key, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=10, ipady=6)

        actions = tk.Frame(panel, bg=locker.PANEL)
        actions.pack(fill="x", padx=18, pady=(12, 12))
        tk.Button(actions, text="INSPECT", command=self.inspect_now, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=14, ipady=8)
        tk.Button(actions, text="COPY SUMMARY", command=self.copy_summary, bg=locker.WHITE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(actions, text="OPEN KEY FOLDER", command=self.open_key_folder, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(actions, text="OPEN MAIN LOCKER", command=self.open_main_locker, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)

        self.details = tk.Text(panel, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", bd=0, wrap="word", font=("Consolas", 10))
        self.details.pack(fill="both", expand=True, padx=18, pady=(0, 18))

        tk.Label(outer, textvariable=self.status, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(10, 0))

    def pick_key(self):
        path = filedialog.askopenfilename(title="Load master USB key", filetypes=[("USB locker key", "*.key"), ("All files", "*.*")])
        if path:
            self.key_path.set(path)
            self.inspect_now()

    def current_summary(self):
        return self.details.get("1.0", "end").strip()

    def open_main_locker(self):
        try:
            locker.launch_main_app_process()
            self.status.set("Opened Main Locker.")
        except Exception as exc:
            self.status.set("Could not open Main Locker.")
            messagebox.showerror("Could not open Main Locker", str(exc))

    def inspect_now(self):
        path = self.key_path.get().strip()
        self.details.delete("1.0", "end")
        if not path:
            self.details.insert("1.0", "Choose a key file first.")
            self.status.set("No key chosen.")
            return
        try:
            key = locker.load_key_file(path)
            settings = locker.load_settings()
            settings["last_key_path"] = path
            locker.save_settings(settings)
            lines = [
                f"Key file: {path}",
                f"Key ID: {key['key_id']}",
                f"Location: {locker.key_location_summary(key)}",
            ]
            origin = key.get("origin")
            if origin:
                lines.extend(
                    [
                        f"Drive root: {origin.get('root', '?')}",
                        f"Drive label: {origin.get('label', '(no label)')}",
                        f"Drive serial: {origin.get('serial', '?')}",
                        f"Drive type: {origin.get('drive_type_name', 'unknown')}",
                        f"Filesystem: {origin.get('filesystem', '') or '(unknown)'}",
                    ]
                )
            if self.owner_policy:
                allowed, message = locker.owner_key_allowed(key, self.owner_policy)
                lines.append("")
                lines.append(f"Owner USB mode: {locker.owner_policy_description(self.owner_policy)}")
                lines.append("Owner match: yes" if allowed else f"Owner match: no - {message}")
            else:
                lines.append("")
                lines.append("Owner USB mode: off on this PC.")
            self.details.insert("1.0", "\n".join(lines))
            self.status.set("Key inspection complete.")
        except Exception as exc:
            self.details.insert("1.0", f"Could not inspect key.\n\n{exc}")
            self.status.set("Key inspection failed.")

    def copy_summary(self):
        text = self.current_summary()
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status.set("Copied key summary.")

    def open_key_folder(self):
        path = self.key_path.get().strip()
        if not path:
            self.status.set("No key file chosen.")
            return
        target = Path(path)
        if not target.exists():
            self.status.set("Key file is missing.")
            messagebox.showerror("Missing key file", "That key file does not exist.")
            return
        if not target.is_file():
            self.status.set("Choose a key file, not a folder.")
            messagebox.showerror("Bad key path", "Choose a master USB key file, not a folder.")
            return
        try:
            os.startfile(target.parent)
            self.status.set("Opened key folder.")
        except Exception as exc:
            self.status.set("Could not open the key folder.")
            messagebox.showerror("Could not open key folder", str(exc))


if __name__ == "__main__":
    app = KeyInspectorApp()
    app.mainloop()
