import os
import os
import shutil
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

import usb_file_locker as locker


class PermUnlockWorkbench(tk.Tk):
    def __init__(self):
        super().__init__()
        if not locker.ensure_license_feature("perm-unlock", parent=self):
            self.after(0, self.destroy)
            return
        self.title("PERM UNLOCK Workbench")
        self.geometry("1120x760")
        self.minsize(980, 680)
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
        self.status = tk.StringVar(value="Refresh the PERM UNLOCK folder, then relock what you are done editing.")
        self.folder_text = tk.StringVar(value=str(locker.preferred_desktop_dir() / "PERM UNLOCK"))
        self.mode_var = tk.StringVar(value="show_all")
        self.items = []
        self.filtered_items = []
        self.build_ui()
        self.refresh_items()

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=22)

        tk.Label(outer, text="PERM UNLOCK Workbench", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 25, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="Use this after editing unlocked files. Keep a readable copy if you want, or relock and remove it after verification.",
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 14))

        top = tk.Frame(outer, bg=locker.PANEL)
        top.pack(fill="x")

        tk.Label(top, text="USB KEY", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).grid(row=0, column=0, sticky="w", padx=18, pady=(18, 4))
        tk.Entry(top, textvariable=self.key_path, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 10)).grid(row=1, column=0, sticky="ew", padx=18, ipady=7)
        tk.Button(top, text="BROWSE", command=self.pick_key, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).grid(row=1, column=1, padx=(0, 18), ipadx=10, ipady=6)

        tk.Label(top, text="OPTIONAL PIN", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).grid(row=0, column=2, sticky="w", padx=(0, 18), pady=(18, 4))
        tk.Entry(top, textvariable=self.pin_var, show="*", bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 10), width=22).grid(row=1, column=2, sticky="ew", padx=(0, 18), ipady=7)

        tk.Label(top, text="PERM UNLOCK FOLDER", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).grid(row=2, column=0, sticky="w", padx=18, pady=(12, 4))
        tk.Entry(top, textvariable=self.folder_text, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 10)).grid(row=3, column=0, columnspan=2, sticky="ew", padx=18, ipady=7)
        tk.Button(top, text="OPEN FOLDER", command=self.open_folder, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).grid(row=3, column=2, sticky="ew", padx=(0, 18), ipadx=10, ipady=6)

        filters = tk.Frame(top, bg=locker.PANEL)
        filters.grid(row=4, column=0, columnspan=3, sticky="w", padx=18, pady=(12, 12))
        tk.Label(filters, text="SHOW", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        tk.Radiobutton(filters, text="ALL", value="show_all", variable=self.mode_var, command=self.apply_filter, bg=locker.PANEL, fg=locker.TEXT, selectcolor=locker.FIELD, activebackground=locker.PANEL, activeforeground=locker.TEXT, font=("Segoe UI", 8, "bold")).pack(side="left", padx=(10, 0))
        tk.Radiobutton(filters, text="UNLOCKED ONLY", value="show_unlocked", variable=self.mode_var, command=self.apply_filter, bg=locker.PANEL, fg=locker.TEXT, selectcolor=locker.FIELD, activebackground=locker.PANEL, activeforeground=locker.TEXT, font=("Segoe UI", 8, "bold")).pack(side="left", padx=(10, 0))
        tk.Radiobutton(filters, text="LOCKED ONLY", value="show_locked", variable=self.mode_var, command=self.apply_filter, bg=locker.PANEL, fg=locker.TEXT, selectcolor=locker.FIELD, activebackground=locker.PANEL, activeforeground=locker.TEXT, font=("Segoe UI", 8, "bold")).pack(side="left", padx=(10, 0))

        top.columnconfigure(0, weight=1)

        body = tk.Frame(outer, bg=locker.BG)
        body.pack(fill="both", expand=True, pady=(14, 0))

        left = tk.Frame(body, bg=locker.PANEL)
        left.pack(side="left", fill="both", expand=True)
        right = tk.Frame(body, bg=locker.PANEL, width=330)
        right.pack(side="left", fill="y", padx=(14, 0))
        right.pack_propagate(False)

        columns = ("name", "state", "kind", "size")
        self.tree = ttk.Treeview(left, columns=columns, show="headings", height=18)
        self.tree.heading("name", text="Name")
        self.tree.heading("state", text="State")
        self.tree.heading("kind", text="Kind")
        self.tree.heading("size", text="Size")
        self.tree.column("name", width=430, anchor="w")
        self.tree.column("state", width=120, anchor="w")
        self.tree.column("kind", width=110, anchor="w")
        self.tree.column("size", width=120, anchor="e")
        self.tree.pack(side="left", fill="both", expand=True, padx=(18, 0), pady=18)
        self.tree.bind("<<TreeviewSelect>>", lambda _event: self.update_details())
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        scroll.pack(side="left", fill="y", pady=18, padx=(0, 18))
        self.tree.configure(yscrollcommand=scroll.set)

        tk.Label(right, text="Selected Item", bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=18, pady=(18, 10))
        self.details = tk.Text(right, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", bd=0, wrap="word", font=("Consolas", 10), height=18)
        self.details.pack(fill="both", expand=True, padx=18)

        actions = tk.Frame(right, bg=locker.PANEL)
        actions.pack(fill="x", padx=18, pady=18)
        tk.Button(actions, text="REFRESH", command=self.refresh_items, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(fill="x", pady=(0, 8), ipady=8)
        tk.Button(actions, text="OPEN SELECTED", command=self.open_selected, bg=locker.WHITE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(fill="x", pady=(0, 8), ipady=8)
        tk.Button(actions, text="RELOCK COPY", command=lambda: self.relock_selected(remove_original=False), bg=locker.YELLOW, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(fill="x", pady=(0, 8), ipady=8)
        tk.Button(actions, text="RELOCK + REMOVE READABLE", command=lambda: self.relock_selected(remove_original=True), bg=locker.RED, fg=locker.WHITE, relief="flat", font=("Segoe UI", 9, "bold")).pack(fill="x", pady=(0, 8), ipady=8)
        tk.Button(actions, text="OPEN MAIN LOCKER", command=self.open_main_locker, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(fill="x", ipady=8)

        tk.Label(outer, textvariable=self.status, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(12, 0))

    def folder_path(self):
        return Path(self.folder_text.get().strip() or locker.ensure_perm_unlock_folder())

    def ensure_folder_ready(self):
        folder = self.folder_path()
        if folder.exists() and not folder.is_dir():
            raise ValueError("The PERM UNLOCK path must be a folder, not a file.")
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def pick_key(self):
        path = filedialog.askopenfilename(title="Load master USB key", filetypes=[("USB locker key", "*.key"), ("All files", "*.*")])
        if path:
            self.key_path.set(path)

    def open_folder(self):
        try:
            folder = self.ensure_folder_ready()
            os.startfile(folder)
        except Exception as exc:
            self.status.set("Could not open the PERM UNLOCK folder.")
            messagebox.showerror("Folder error", str(exc))

    def format_size(self, size):
        if size is None:
            return "-"
        value = float(size)
        units = ["B", "KB", "MB", "GB"]
        for unit in units:
            if value < 1024 or unit == units[-1]:
                return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
            value /= 1024
        return f"{size} B"

    def refresh_items(self):
        try:
            folder = self.ensure_folder_ready()
        except Exception as exc:
            self.items = []
            self.filtered_items = []
            self.tree.delete(*self.tree.get_children())
            self.update_details()
            self.status.set("Could not load the PERM UNLOCK folder.")
            messagebox.showerror("Folder error", str(exc))
            return
        items = []
        for child in sorted(folder.iterdir(), key=lambda path: (path.is_file(), path.name.lower())):
            kind = "Folder" if child.is_dir() else "File"
            state = "Locked" if locker.is_locked_path(child) else "Unlocked"
            size = None
            if child.is_file():
                try:
                    size = child.stat().st_size
                except Exception:
                    size = None
            items.append({"path": child, "name": child.name, "kind": kind, "state": state, "size": size})
        self.items = items
        self.apply_filter()
        self.status.set(f"Loaded {len(items)} item(s) from the PERM UNLOCK folder.")

    def apply_filter(self):
        mode = self.mode_var.get()
        if mode == "show_locked":
            self.filtered_items = [item for item in self.items if item["state"] == "Locked"]
        elif mode == "show_unlocked":
            self.filtered_items = [item for item in self.items if item["state"] == "Unlocked"]
        else:
            self.filtered_items = list(self.items)
        self.tree.delete(*self.tree.get_children())
        for index, item in enumerate(self.filtered_items):
            self.tree.insert("", "end", iid=str(index), values=(item["name"], item["state"], item["kind"], self.format_size(item["size"])))
        if self.filtered_items:
            self.tree.selection_set("0")
            self.tree.see("0")
        self.update_details()

    def selected_item(self):
        selection = self.tree.selection()
        if not selection:
            return None
        try:
            return self.filtered_items[int(selection[0])]
        except Exception:
            return None

    def update_details(self):
        item = self.selected_item()
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        if item is None:
            self.details.insert("1.0", "Select an item in the PERM UNLOCK folder.")
        else:
            lines = [
                f"Path: {item['path']}",
                f"State: {item['state']}",
                f"Kind: {item['kind']}",
                f"Size: {self.format_size(item['size'])}",
            ]
            if item["state"] == "Locked":
                try:
                    info = locker.locked_file_info(item["path"])
                    header = info["header"]
                    lines.extend(
                        [
                            "",
                            f"Lock format: {'Portable' if info['portable'] else 'Old Windows-only'}",
                            f"Original name: {header.get('original_name', '?')}",
                            f"Key ID: {header.get('key_id', '?')}",
                        ]
                    )
                except Exception as exc:
                    lines.extend(["", f"Could not read lock info: {exc}"])
            else:
                lines.extend(
                    [
                        "",
                        "Use RELOCK COPY to keep the readable item and create a new locked copy.",
                        "Use RELOCK + REMOVE READABLE to verify the new lock and then remove the readable original.",
                    ]
                )
            self.details.insert("1.0", "\n".join(lines))
        self.details.configure(state="disabled")

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

    def open_main_locker(self):
        try:
            locker.launch_main_app_process()
            self.status.set("Opened Main Locker.")
        except Exception as exc:
            self.status.set("Could not open Main Locker.")
            messagebox.showerror("Could not open Main Locker", str(exc))

    def confirmed_pin_if_needed(self):
        pin = self.pin_var.get()
        if not pin:
            return ""
        confirmation = simpledialog.askstring(
            "Confirm optional PIN",
            "Re-enter the exact PIN.\n\nIf you forget it, the relocked item cannot be opened.",
            show="*",
            parent=self,
        )
        if confirmation is None:
            self.status.set("Relock canceled before PIN confirmation.")
            return None
        if confirmation != pin:
            messagebox.showerror("PINs do not match", "The two PIN entries were different. Nothing was relocked.")
            self.status.set("PIN confirmation failed. Nothing was relocked.")
            return None
        return pin

    def open_selected(self):
        item = self.selected_item()
        if item is None:
            messagebox.showinfo("Nothing selected", "Choose an item first.")
            return
        target = item["path"]
        try:
            if item["state"] == "Locked":
                locker.launch_unlocker_process(target)
                self.status.set(f"Opened unlocker for {target.name}.")
                return
            os.startfile(target)
            self.status.set(f"Opened {target.name}.")
        except Exception as exc:
            self.status.set("Could not open the selected item.")
            messagebox.showerror("Open failed", str(exc))

    def relock_selected(self, remove_original):
        item = self.selected_item()
        if item is None:
            messagebox.showinfo("Nothing selected", "Choose an unlocked item first.")
            return
        path = item["path"]
        if item["state"] != "Unlocked":
            messagebox.showerror("Already locked", "That item is already locked.")
            return
        try:
            pin = self.confirmed_pin_if_needed()
            if pin is None:
                return
            key = self.load_key()
            out_path = locker.lock_file(path, key, pin)
            if remove_original:
                if not locker.verify_locked_file(out_path, path, key, pin):
                    out_path.unlink(missing_ok=True)
                    raise ValueError("Verification failed. The readable original was kept.")
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
                locker.log_event("perm_unlock_workbench_relock_remove", path, "ok", str(out_path))
            else:
                locker.log_event("perm_unlock_workbench_relock_copy", path, "ok", str(out_path))
            self.status.set(f"Created {out_path.name}")
            self.refresh_items()
            messagebox.showinfo(
                "Relock complete",
                f"Created:\n{out_path}\n\n"
                + ("Readable copy removed after verification." if remove_original else "Readable copy kept."),
            )
        except Exception as exc:
            locker.log_event("perm_unlock_workbench_relock", path if item else "missing", "failed", str(exc))
            self.status.set("Relock failed.")
            messagebox.showerror("Relock failed", str(exc))


if __name__ == "__main__":
    app = PermUnlockWorkbench()
    app.mainloop()
