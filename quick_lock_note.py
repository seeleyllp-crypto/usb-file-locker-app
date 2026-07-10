import shutil
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog

import usb_file_locker as locker


class QuickLockNoteApp(tk.Tk):
    def __init__(self):
        super().__init__()
        if not locker.ensure_license_feature("quick-lock-note", parent=self):
            self.after(0, self.destroy)
            return
        self.title("Quick Lock Note")
        self.geometry("900x680")
        self.minsize(820, 620)
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
        self.note_name = tk.StringVar(value="locked_note")
        self.output_dir = tk.StringVar(value=str(locker.preferred_desktop_dir()))
        self.status = tk.StringVar(value="Load a USB key, type a note, and lock it.")
        self.build_ui()

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=22)

        tk.Label(outer, text="Quick Lock Note", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 25, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="Paste text here and make a locked note without opening the full vault screen.",
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 14))

        panel = tk.Frame(outer, bg=locker.PANEL)
        panel.pack(fill="both", expand=True)

        tk.Label(panel, text="MASTER USB KEY", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).grid(row=0, column=0, sticky="w", padx=18, pady=(18, 4))
        key_entry = tk.Entry(panel, textvariable=self.key_path, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 10))
        key_entry.grid(row=1, column=0, sticky="ew", padx=18, ipady=7)
        tk.Button(panel, text="BROWSE", command=self.pick_key, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).grid(row=1, column=1, padx=(0, 18), ipadx=10, ipady=6)

        tk.Label(panel, text="OPTIONAL PIN", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).grid(row=2, column=0, sticky="w", padx=18, pady=(12, 4))
        tk.Entry(panel, textvariable=self.pin_var, show="*", bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 10)).grid(row=3, column=0, sticky="ew", padx=18, ipady=7)

        tk.Label(panel, text="NOTE NAME", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).grid(row=4, column=0, sticky="w", padx=18, pady=(12, 4))
        tk.Entry(panel, textvariable=self.note_name, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 10)).grid(row=5, column=0, sticky="ew", padx=18, ipady=7)

        tk.Label(panel, text="SAVE LOCKED NOTE TO", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).grid(row=6, column=0, sticky="w", padx=18, pady=(12, 4))
        tk.Entry(panel, textvariable=self.output_dir, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 10)).grid(row=7, column=0, sticky="ew", padx=18, ipady=7)
        tk.Button(panel, text="BROWSE", command=self.pick_output, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).grid(row=7, column=1, padx=(0, 18), ipadx=10, ipady=6)

        tk.Label(panel, text="NOTE TEXT", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).grid(row=8, column=0, sticky="w", padx=18, pady=(12, 4))
        self.note_text = tk.Text(panel, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", bd=0, height=16, wrap="word", font=("Consolas", 10))
        self.note_text.grid(row=9, column=0, columnspan=2, sticky="nsew", padx=18, pady=(0, 12))

        row = tk.Frame(panel, bg=locker.PANEL)
        row.grid(row=10, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 18))
        tk.Button(row, text="LOCK NOTE", command=self.lock_note_now, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=16, ipady=8)
        tk.Button(row, text="CLEAR TEXT", command=lambda: self.note_text.delete("1.0", "end"), bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(row, text="OPEN MAIN LOCKER", command=self.open_main_locker, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)

        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(9, weight=1)
        tk.Label(outer, textvariable=self.status, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(10, 0))

    def pick_key(self):
        path = filedialog.askopenfilename(title="Load master USB key", filetypes=[("USB locker key", "*.key"), ("All files", "*.*")])
        if path:
            self.key_path.set(path)

    def pick_output(self):
        path = filedialog.askdirectory(title="Choose folder for locked note")
        if path:
            self.output_dir.set(path)

    def open_main_locker(self):
        try:
            locker.launch_main_app_process()
            self.status.set("Opened Main Locker.")
        except Exception as exc:
            self.status.set("Could not open Main Locker.")
            messagebox.showerror("Could not open Main Locker", str(exc))

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

    def ensure_output_dir_ready(self):
        destination = Path(self.output_dir.get().strip() or locker.preferred_desktop_dir())
        if destination.exists() and not destination.is_dir():
            raise ValueError("The locked note destination must be a folder, not a file.")
        destination.mkdir(parents=True, exist_ok=True)
        return destination

    def confirmed_pin_if_needed(self):
        pin = self.pin_var.get()
        if not pin:
            return ""
        confirmation = simpledialog.askstring(
            "Confirm optional PIN",
            "Re-enter the exact PIN.\n\nIf you forget it, this locked note cannot be opened.",
            show="*",
            parent=self,
        )
        if confirmation is None:
            self.status.set("Lock canceled before PIN confirmation.")
            return None
        if confirmation != pin:
            messagebox.showerror("PINs do not match", "The two PIN entries were different. Nothing was locked.")
            self.status.set("PIN confirmation failed. Nothing was locked.")
            return None
        return pin

    def lock_note_now(self):
        name = locker.safe_filename_piece(self.note_name.get().strip(), "locked_note")
        body = self.note_text.get("1.0", "end").rstrip()
        if not body.strip():
            messagebox.showerror("No note text", "Type or paste some note text first.")
            return
        destination = Path(self.output_dir.get().strip() or locker.preferred_desktop_dir())
        plain_path = locker.unique_path(locker.TEMP_DIR / f"{name}.txt")
        locked_path = None
        try:
            pin = self.confirmed_pin_if_needed()
            if pin is None:
                return
            destination = self.ensure_output_dir_ready()
            key = self.load_key()
            locker.TEMP_DIR.mkdir(parents=True, exist_ok=True)
            plain_path.write_text(body + "\n", encoding="utf-8")
            locked_path = locker.lock_file(plain_path, key, pin)
            final_path = locker.unique_path(destination / locked_path.name)
            shutil.move(str(locked_path), final_path)
            locker.log_event("quick_lock_note", final_path, "ok")
            self.status.set(f"Locked note saved to {final_path}")
            if messagebox.askyesno("Locked note created", f"Created:\n{final_path}\n\nOpen the folder?"):
                locker.os.startfile(final_path.parent)
        except Exception as exc:
            locker.log_event("quick_lock_note", destination, "failed", str(exc))
            self.status.set("Could not lock note.")
            messagebox.showerror("Lock note failed", str(exc))
        finally:
            try:
                plain_path.unlink(missing_ok=True)
            except Exception:
                pass
            if locked_path is not None:
                try:
                    Path(locked_path).unlink(missing_ok=True)
                except Exception:
                    pass


if __name__ == "__main__":
    app = QuickLockNoteApp()
    app.mainloop()
