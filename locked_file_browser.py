import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

import usb_file_locker as locker


class LockedFileBrowser(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Locked File Browser")
        self.geometry("1180x760")
        self.minsize(1020, 680)
        self.configure(bg=locker.BG)
        self.results = []
        self.filtered_results = []
        self.search_var = tk.StringVar()
        self.status = tk.StringVar(value="Ready. Scan for .locked files and open them fast.")
        self.scope_text = tk.StringVar(value="")
        self.scan_busy = False
        self.is_closing = False
        self.pending_after_ids = set()
        self.build_ui()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.schedule_after(250, self.start_fast_scan)

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=20)

        tk.Label(outer, text="Locked File Browser", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 25, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="Quickly find .locked files, check what they are, and jump into unlock mode.",
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 14))

        panel = tk.Frame(outer, bg=locker.PANEL)
        panel.pack(fill="both", expand=True)

        top = tk.Frame(panel, bg=locker.PANEL)
        top.pack(fill="x", padx=18, pady=(18, 10))
        tk.Button(top, text="FAST SCAN", command=self.start_fast_scan, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=12, ipady=8)
        tk.Button(top, text="HOME SCAN", command=self.start_home_scan, bg=locker.YELLOW, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(top, text="OPEN MAIN LOCKER", command=self.open_main_locker, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(top, text="OPEN PERM UNLOCK", command=self.open_perm_unlock_folder, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(top, text="UNLOCK SELECTED", command=self.unlock_selected, bg=locker.WHITE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=12, ipady=8)
        tk.Button(top, text="OPEN FOLDER", command=self.open_selected_folder, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", padx=(0, 10), ipadx=12, ipady=8)
        tk.Button(top, text="COPY PATH", command=self.copy_selected_path, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", padx=(0, 10), ipadx=12, ipady=8)

        search_row = tk.Frame(panel, bg=locker.PANEL)
        search_row.pack(fill="x", padx=18, pady=(0, 10))
        tk.Label(search_row, text="SEARCH", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        search = tk.Entry(search_row, textvariable=self.search_var, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 11))
        search.pack(side="left", fill="x", expand=True, padx=(12, 0), ipady=7)
        search.bind("<KeyRelease>", lambda _event: self.apply_filter())
        tk.Label(search_row, textvariable=self.scope_text, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 9)).pack(side="left", padx=(12, 0))

        body = tk.PanedWindow(panel, sashwidth=6, bg=locker.PANEL, bd=0, relief="flat")
        body.pack(fill="both", expand=True, padx=18, pady=(0, 12))

        left = tk.Frame(body, bg=locker.PANEL)
        right = tk.Frame(body, bg=locker.PANEL)
        body.add(left, stretch="always")
        body.add(right, minsize=320)

        columns = ("name", "kind", "format", "key", "folder")
        self.tree = ttk.Treeview(left, columns=columns, show="headings", height=18)
        self.tree.heading("name", text="Name")
        self.tree.heading("kind", text="Kind")
        self.tree.heading("format", text="Format")
        self.tree.heading("key", text="Key ID")
        self.tree.heading("folder", text="Folder")
        self.tree.column("name", width=250, anchor="w")
        self.tree.column("kind", width=110, anchor="w")
        self.tree.column("format", width=150, anchor="w")
        self.tree.column("key", width=130, anchor="w")
        self.tree.column("folder", width=440, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda _event: self.update_details())
        self.tree.bind("<Double-1>", lambda _event: self.unlock_selected())
        tree_scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        tree_scroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=tree_scroll.set)

        tk.Label(right, text="Selected File", bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 17, "bold")).pack(anchor="w")
        self.details = tk.Text(
            right,
            bg=locker.FIELD,
            fg=locker.TEXT,
            insertbackground=locker.TEXT,
            relief="flat",
            bd=0,
            height=24,
            wrap="word",
            font=("Consolas", 10),
        )
        self.details.pack(fill="both", expand=True, pady=(10, 0))
        self.details.configure(state="disabled")

        tk.Label(outer, textvariable=self.status, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(10, 0))

    def scan_roots(self, mode):
        if mode == "home":
            roots = [Path.home(), Path.home() / "OneDrive"]
            max_results = 2000
        else:
            roots = locker.common_user_dirs()
            max_results = 500
        unique_roots = []
        seen = set()
        for root in roots:
            try:
                resolved = Path(root).resolve()
            except Exception:
                resolved = Path(root)
            if resolved in seen or not resolved.exists():
                continue
            seen.add(resolved)
            unique_roots.append(resolved)
        return unique_roots, max_results

    def start_fast_scan(self):
        self.start_scan("fast")

    def start_home_scan(self):
        self.start_scan("home")

    def start_scan(self, mode):
        if self.is_closing:
            return
        if self.scan_busy:
            self.status.set("A scan is already running.")
            return
        roots, max_results = self.scan_roots(mode)
        scope_name = "HOME SCAN" if mode == "home" else "FAST SCAN"
        self.scope_text.set(f"{scope_name} - " + ", ".join(str(root) for root in roots[:3]))
        self.status.set(f"{scope_name} started...")
        self.scan_busy = True

        def worker():
            rows = []
            errors = []
            try:
                paths = locker.find_locked_files_in_roots(roots, max_results=max_results)
                for path_text in paths:
                    path = Path(path_text)
                    try:
                        info = locker.locked_file_info(path)
                        header = info["header"]
                        rows.append(
                            {
                                "path": str(path),
                                "name": path.name,
                                "kind": info["kind"].upper(),
                                "format": "Portable" if info["portable"] else "Old Windows-only",
                                "key_id": header.get("key_id", ""),
                                "folder": str(path.parent),
                                "details": [
                                    f"Path: {path}",
                                    f"Kind: {info['kind']}",
                                    f"Format: {'Portable' if info['portable'] else 'Old Windows-only'}",
                                    f"Original name: {header.get('original_name', '?')}",
                                    f"Original size: {header.get('original_size', '?')}",
                                    f"Key ID: {header.get('key_id', '?')}",
                                    f"Created at: {header.get('locked_at', '?')}",
                                ],
                            }
                        )
                    except Exception as exc:
                        errors.append(f"{path.name}: {exc}")
                        rows.append(
                            {
                                "path": str(path),
                                "name": path.name,
                                "kind": "Unreadable",
                                "format": "Error",
                                "key_id": "",
                                "folder": str(path.parent),
                                "details": [
                                    f"Path: {path}",
                                    "Kind: unreadable",
                                    f"Error: {exc}",
                                ],
                            }
                        )
            except Exception as exc:
                errors.append(str(exc))
            self.safe_after(lambda: self.finish_scan(scope_name, roots, rows, errors))

        threading.Thread(target=worker, name=f"LockedFileBrowser-{mode}", daemon=True).start()

    def finish_scan(self, scope_name, roots, rows, errors):
        if self.is_closing:
            return
        self.scan_busy = False
        self.results = sorted(rows, key=lambda item: item["path"].lower())
        self.apply_filter()
        self.status.set(
            f"{scope_name} complete. Found {len(rows)} locked file(s) across {len(roots)} root(s). "
            f"Issues: {len(errors)}."
        )
        if errors:
            locker.log_event("locked_file_browser_scan", scope_name, "ok", f"found={len(rows)} issues={len(errors)}")
        else:
            locker.log_event("locked_file_browser_scan", scope_name, "ok", f"found={len(rows)}")
        if not rows:
            messagebox.showinfo("No locked files found", f"No .locked files were found in the {scope_name.lower()} roots.")

    def safe_after(self, callback):
        if self.is_closing:
            return
        try:
            self.schedule_after(0, callback)
        except tk.TclError:
            pass

    def schedule_after(self, delay_ms, callback):
        if self.is_closing:
            return None
        holder = {}

        def runner():
            after_id = holder.get("id")
            if after_id is not None:
                self.pending_after_ids.discard(after_id)
            if self.is_closing:
                return
            callback()

        after_id = self.after(delay_ms, runner)
        holder["id"] = after_id
        self.pending_after_ids.add(after_id)
        return after_id

    def on_close(self):
        self.is_closing = True
        for after_id in list(self.pending_after_ids):
            try:
                self.after_cancel(after_id)
            except tk.TclError:
                pass
            finally:
                self.pending_after_ids.discard(after_id)
        self.destroy()

    def apply_filter(self):
        needle = self.search_var.get().strip().lower()
        if not needle:
            self.filtered_results = list(self.results)
        else:
            self.filtered_results = [
                item
                for item in self.results
                if needle in item["name"].lower()
                or needle in item["path"].lower()
                or needle in item["kind"].lower()
                or needle in item["format"].lower()
                or needle in item["key_id"].lower()
            ]
        self.tree.delete(*self.tree.get_children())
        for index, item in enumerate(self.filtered_results):
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(item["name"], item["kind"], item["format"], item["key_id"], item["folder"]),
            )
        if self.filtered_results:
            self.tree.selection_set("0")
            self.tree.see("0")
        self.update_details()

    def selected_item(self):
        selection = self.tree.selection()
        if not selection:
            return None
        try:
            index = int(selection[0])
            return self.filtered_results[index]
        except Exception:
            return None

    def update_details(self):
        item = self.selected_item()
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        if item is None:
            self.details.insert("1.0", "Select a locked file to see details.")
        else:
            self.details.insert("1.0", "\n".join(item["details"]))
        self.details.configure(state="disabled")

    def open_main_locker(self):
        try:
            locker.launch_main_app_process()
            self.status.set("Opened Main Locker.")
        except Exception as exc:
            self.status.set("Could not open Main Locker.")
            messagebox.showerror("Could not open Main Locker", str(exc))

    def unlock_selected(self):
        item = self.selected_item()
        if item is None:
            messagebox.showinfo("Nothing selected", "Choose a locked file first.")
            return
        try:
            locker.launch_unlocker_process(item["path"])
            self.status.set(f"Opened unlocker for {Path(item['path']).name}.")
        except Exception as exc:
            self.status.set("Could not open the unlocker.")
            messagebox.showerror("Could not open unlocker", str(exc))

    def open_selected_folder(self):
        item = self.selected_item()
        if item is None:
            messagebox.showinfo("Nothing selected", "Choose a locked file first.")
            return
        try:
            os.startfile(Path(item["path"]).parent)
            self.status.set("Opened the selected file folder.")
        except Exception as exc:
            self.status.set("Could not open the selected file folder.")
            messagebox.showerror("Could not open folder", str(exc))

    def copy_selected_path(self):
        item = self.selected_item()
        if item is None:
            messagebox.showinfo("Nothing selected", "Choose a locked file first.")
            return
        self.clipboard_clear()
        self.clipboard_append(item["path"])
        self.status.set("Copied selected locked-file path.")

    def open_perm_unlock_folder(self):
        try:
            os.startfile(locker.ensure_perm_unlock_folder())
            self.status.set("Opened the PERM UNLOCK folder.")
        except Exception as exc:
            self.status.set("Could not open the PERM UNLOCK folder.")
            messagebox.showerror("Could not open PERM UNLOCK", str(exc))


if __name__ == "__main__":
    app = LockedFileBrowser()
    app.mainloop()
