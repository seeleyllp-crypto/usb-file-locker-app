import os
import secrets
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog

import usb_file_locker as locker


class PersonalVaultPad(tk.Tk):
    def __init__(self):
        super().__init__()
        if not locker.ensure_license_feature("personal-vault", parent=self):
            self.after(0, self.destroy)
            return
        self.title("Personal Vault Pad")
        self.geometry("1220x820")
        self.minsize(1060, 740)
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
        self.pin_visible = tk.BooleanVar(value=False)
        self.search_var = tk.StringVar(value="")
        self.type_var = tk.StringVar(value=locker.PERSONAL_TYPES[0])
        self.status = tk.StringVar(value="Load your USB key, then open the vault.")
        self.vault_summary = tk.StringVar(value=f"Vault file: {locker.VAULT_FILE}")
        self.list_status = tk.StringVar(value="No vault loaded yet.")
        self.key = None
        self.loaded_pin = ""
        self.loaded_key_id = None
        self.entries = []
        self.visible_indices = []
        self.selected_entry_id = None
        self.clipboard_job = None
        self.confirmed_new_vault_pin = None
        self.pin_entry = None
        self.item_list = None
        self.label_entry = None
        self.account_entry = None
        self.secret_text = None
        self.notes_text = None
        self.build_ui()
        self.search_var.trace_add("write", lambda *_args: self.refresh_list())

    def clear_loaded_session(self, preserve_status=False):
        self.key = None
        self.loaded_pin = ""
        self.loaded_key_id = None
        self.entries = []
        self.visible_indices = []
        self.selected_entry_id = None
        self.item_list.delete(0, "end")
        self.list_status.set("No vault loaded yet.")
        self.clear_fields(preserve_status=preserve_status)
        self.vault_summary.set(f"Vault file: {locker.VAULT_FILE}")

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=22)

        tk.Label(outer, text="Personal Vault Pad", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 28, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="A simpler vault for personal notes, passcodes, recovery codes, and private account details.",
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
        self.pin_entry = tk.Entry(top, textvariable=self.pin_var, show="*", bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 10), width=22)
        self.pin_entry.grid(row=1, column=2, sticky="ew", padx=(0, 10), ipady=7)
        tk.Checkbutton(
            top,
            text="SHOW PIN",
            variable=self.pin_visible,
            command=self.toggle_pin_visibility,
            bg=locker.PANEL,
            fg=locker.MUTED,
            selectcolor=locker.PANEL,
            activebackground=locker.PANEL,
            activeforeground=locker.TEXT,
            font=("Segoe UI", 8, "bold"),
        ).grid(row=1, column=3, sticky="w", padx=(0, 18))

        actions = tk.Frame(top, bg=locker.PANEL)
        actions.grid(row=2, column=0, columnspan=4, sticky="ew", padx=18, pady=(12, 18))
        tk.Button(actions, text="OPEN VAULT", command=self.open_vault, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=14, ipady=8)
        tk.Button(actions, text="NEW ITEM", command=self.clear_fields, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=14, ipady=8)
        tk.Button(actions, text="SAVE ITEM", command=self.add_or_update, bg=locker.WHITE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=14, ipady=8)
        tk.Button(actions, text="IMPORT TEXT", command=self.import_text_file, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=14, ipady=8)
        tk.Button(actions, text="OPEN MAIN LOCKER", command=self.open_main_locker, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=14, ipady=8)

        top.columnconfigure(0, weight=1)
        top.columnconfigure(2, weight=1)

        info = tk.Frame(outer, bg=locker.PANEL)
        info.pack(fill="x", pady=(14, 14))
        tk.Label(info, text="Vault Status", bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=18, pady=(16, 6))
        tk.Label(info, textvariable=self.vault_summary, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 10), justify="left", wraplength=1080).pack(anchor="w", padx=18, pady=(0, 16))

        body = tk.Frame(outer, bg=locker.BG)
        body.pack(fill="both", expand=True)

        left = tk.Frame(body, bg=locker.PANEL)
        left.pack(side="left", fill="both", expand=False, padx=(0, 12))

        tk.Label(left, text="SAVED ITEMS", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=12, pady=(14, 6))
        search_entry = tk.Entry(left, textvariable=self.search_var, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 10))
        search_entry.pack(fill="x", padx=12, ipady=7)
        self.item_list = tk.Listbox(
            left,
            width=40,
            bg=locker.FIELD,
            fg=locker.TEXT,
            selectbackground=locker.GREEN,
            selectforeground=locker.BLACK,
            highlightthickness=1,
            highlightcolor="#343946",
            highlightbackground="#343946",
            bd=0,
            font=("Segoe UI", 10),
        )
        self.item_list.pack(fill="both", expand=True, padx=12, pady=(10, 8))
        self.item_list.bind("<<ListboxSelect>>", self.on_select)
        tk.Label(left, textvariable=self.list_status, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8)).pack(anchor="w", padx=12, pady=(0, 12))

        right = tk.Frame(body, bg=locker.PANEL)
        right.pack(side="left", fill="both", expand=True)

        quick_row = tk.Frame(right, bg=locker.PANEL)
        quick_row.grid(row=0, column=0, columnspan=2, sticky="ew", padx=14, pady=(14, 0))
        tk.Label(quick_row, text="QUICK TYPES", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        for index, label in enumerate(["Passcode", "Recovery code", "Account", "Client record", "Private note"]):
            tk.Button(
                quick_row,
                text=label.upper(),
                command=lambda value=label: self.type_var.set(value),
                bg="#252936",
                fg=locker.TEXT,
                relief="flat",
                font=("Segoe UI", 8, "bold"),
            ).pack(side="left", padx=(8 if index else 10, 0), ipadx=8, ipady=5)

        self.field_label(right, "TYPE", 1, 0)
        type_menu = tk.OptionMenu(right, self.type_var, *locker.PERSONAL_TYPES)
        type_menu.config(bg=locker.FIELD, fg=locker.TEXT, activebackground="#252936", activeforeground=locker.TEXT, highlightthickness=0, bd=0, font=("Segoe UI", 10))
        type_menu["menu"].config(bg=locker.FIELD, fg=locker.TEXT)
        type_menu.grid(row=2, column=0, sticky="ew", padx=14)

        self.field_label(right, "NAME / LABEL", 1, 1)
        self.label_entry = tk.Entry(right, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 11))
        self.label_entry.grid(row=2, column=1, sticky="ew", padx=(0, 14), ipady=7)

        self.field_label(right, "ACCOUNT / USERNAME / SITE", 3, 0)
        self.account_entry = tk.Entry(right, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 11))
        self.account_entry.grid(row=4, column=0, columnspan=2, sticky="ew", padx=14, ipady=7)

        self.field_label(right, "SECRET / PASSCODE / RECOVERY CODE", 5, 0)
        self.secret_text = tk.Text(right, height=5, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", bd=0, font=("Segoe UI", 11), wrap="word")
        self.secret_text.grid(row=6, column=0, columnspan=2, sticky="ew", padx=14)

        secret_buttons = tk.Frame(right, bg=locker.PANEL)
        secret_buttons.grid(row=7, column=0, columnspan=2, sticky="ew", padx=14, pady=(8, 0))
        tk.Button(secret_buttons, text="COPY SECRET", command=lambda: self.copy_temporarily(self.secret_text.get("1.0", "end").strip(), "Secret"), bg=locker.WHITE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", ipadx=10, ipady=6)
        tk.Button(secret_buttons, text="COPY ACCOUNT", command=lambda: self.copy_temporarily(self.account_entry.get().strip(), "Account"), bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(8, 0), ipadx=10, ipady=6)
        tk.Button(secret_buttons, text="COPY NOTES", command=lambda: self.copy_temporarily(self.notes_text.get("1.0", "end").strip(), "Notes"), bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(8, 0), ipadx=10, ipady=6)

        self.field_label(right, "PRIVATE NOTES", 8, 0)
        self.notes_text = tk.Text(right, height=9, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", bd=0, font=("Segoe UI", 11), wrap="word")
        self.notes_text.grid(row=9, column=0, columnspan=2, sticky="nsew", padx=14)

        lower_actions = tk.Frame(right, bg=locker.PANEL)
        lower_actions.grid(row=10, column=0, columnspan=2, sticky="ew", padx=14, pady=14)
        tk.Button(lower_actions, text="DUPLICATE", command=self.duplicate_selected, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=12, ipady=8)
        tk.Button(lower_actions, text="DELETE", command=self.delete_selected, bg=locker.RED, fg=locker.WHITE, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(lower_actions, text="EXPORT LOCKED COPY", command=self.export_selected_locked, bg=locker.YELLOW, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(lower_actions, text="OPEN APP FOLDER", command=self.open_app_folder, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=12, ipady=8)

        right.columnconfigure(0, weight=1)
        right.columnconfigure(1, weight=1)
        right.rowconfigure(9, weight=1)

        tk.Label(outer, textvariable=self.status, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(14, 0))

    def field_label(self, parent, text, row, column):
        tk.Label(parent, text=text, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).grid(row=row, column=column, sticky="w", padx=14, pady=(12, 4))

    def toggle_pin_visibility(self):
        self.pin_entry.configure(show="" if self.pin_visible.get() else "*")

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
        self.key = key
        return key

    def entry_summary(self, entry):
        kind = entry.get("type", "Other")
        label = entry.get("label", "(no label)")
        account = entry.get("account", "").strip()
        return f"{kind}: {label}" + (f" - {account}" if account else "")

    def clone_entries(self):
        return [dict(entry) for entry in self.entries]

    def capture_editor_fields(self):
        return {
            "type": self.type_var.get(),
            "label": self.label_entry.get(),
            "account": self.account_entry.get(),
            "secret": self.secret_text.get("1.0", "end").rstrip("\n"),
            "notes": self.notes_text.get("1.0", "end").rstrip("\n"),
        }

    def restore_editor_fields(self, draft, clear_selection=False):
        if clear_selection:
            self.selected_entry_id = None
        self.type_var.set(draft.get("type") or locker.PERSONAL_TYPES[0])
        self.label_entry.delete(0, "end")
        self.label_entry.insert(0, draft.get("label", ""))
        self.account_entry.delete(0, "end")
        self.account_entry.insert(0, draft.get("account", ""))
        self.secret_text.delete("1.0", "end")
        self.secret_text.insert("1.0", draft.get("secret", ""))
        self.notes_text.delete("1.0", "end")
        self.notes_text.insert("1.0", draft.get("notes", ""))

    def sort_entries(self):
        self.entries.sort(key=lambda entry: (entry.get("updated_at", ""), entry.get("label", "")), reverse=True)

    def refresh_list(self, select_entry_id=None):
        self.visible_indices[:] = []
        self.item_list.delete(0, "end")
        query = self.search_var.get().strip().lower()
        for index, entry in enumerate(self.entries):
            haystack = " ".join(str(entry.get(field, "")) for field in ("type", "label", "account", "secret", "notes")).lower()
            if query and query not in haystack:
                continue
            self.visible_indices.append(index)
            self.item_list.insert("end", self.entry_summary(entry))
        shown = len(self.visible_indices)
        total = len(self.entries)
        self.list_status.set(f"Showing {shown} of {total} item(s).")
        desired_id = select_entry_id if select_entry_id is not None else self.selected_entry_id
        matched_selection = False
        if desired_id is not None:
            for list_index, entry_index in enumerate(self.visible_indices):
                if self.entries[entry_index].get("id") == desired_id:
                    self.item_list.selection_clear(0, "end")
                    self.item_list.selection_set(list_index)
                    self.item_list.see(list_index)
                    self.fill_fields(entry_index)
                    matched_selection = True
                    break
        if not matched_selection and self.visible_indices:
            self.item_list.selection_clear(0, "end")
            self.item_list.selection_set(0)
            self.fill_fields(self.visible_indices[0])
        elif not self.visible_indices:
            self.clear_fields(preserve_status=True)

    def open_vault(self):
        try:
            key = self.load_key()
            pin = self.pin_var.get()
            self.entries = locker.load_personal_vault(key, pin)
            self.sort_entries()
            self.key = key
            self.loaded_pin = pin
            self.loaded_key_id = key["key_id"]
            self.selected_entry_id = None
            self.confirmed_new_vault_pin = None
            self.refresh_list()
            if not self.visible_indices:
                self.clear_fields()
            protection = "USB key only" if not pin else "USB key + PIN"
            self.vault_summary.set(
                "\n".join(
                    [
                        f"Vault file: {locker.VAULT_FILE}",
                        f"Loaded with key ID: {key['key_id']}",
                        f"Protection mode: {protection}",
                        f"Saved items: {len(self.entries)}",
                    ]
                )
            )
            locker.log_event("vault_pad_open", locker.VAULT_FILE, "ok", f"entries={len(self.entries)}")
            self.status.set("Vault loaded.")
        except Exception as exc:
            self.clear_loaded_session(preserve_status=True)
            locker.log_event("vault_pad_open", locker.VAULT_FILE, "failed", str(exc))
            messagebox.showerror("Vault locked", f"Could not open the vault.\n\nUse the same USB key and exact optional PIN.\n\n{exc}")
            self.status.set("Vault open failed.")

    def ensure_loaded(self):
        if self.key is None:
            self.open_vault()
        return self.key is not None

    def clear_fields(self, preserve_status=False):
        self.selected_entry_id = None
        self.type_var.set(locker.PERSONAL_TYPES[0])
        self.label_entry.delete(0, "end")
        self.account_entry.delete(0, "end")
        self.secret_text.delete("1.0", "end")
        self.notes_text.delete("1.0", "end")
        if not preserve_status:
            self.status.set("Ready for a new vault item.")

    def fill_fields(self, index):
        if index < 0 or index >= len(self.entries):
            return
        entry = self.entries[index]
        self.selected_entry_id = entry.get("id")
        self.type_var.set(entry.get("type", locker.PERSONAL_TYPES[0]))
        self.label_entry.delete(0, "end")
        self.label_entry.insert(0, entry.get("label", ""))
        self.account_entry.delete(0, "end")
        self.account_entry.insert(0, entry.get("account", ""))
        self.secret_text.delete("1.0", "end")
        self.secret_text.insert("1.0", entry.get("secret", ""))
        self.notes_text.delete("1.0", "end")
        self.notes_text.insert("1.0", entry.get("notes", ""))

    def on_select(self, _event=None):
        selection = self.item_list.curselection()
        if selection:
            self.fill_fields(self.visible_indices[selection[0]])

    def confirm_new_vault_pin_if_needed(self):
        pin = self.pin_var.get()
        if locker.VAULT_FILE.exists() or not pin:
            return pin
        if self.confirmed_new_vault_pin == pin:
            return pin
        confirmation = simpledialog.askstring("Confirm PIN", "Re-enter the exact PIN for this new vault.", show="*", parent=self)
        if confirmation is None:
            self.status.set("Save canceled before PIN confirmation.")
            return None
        if confirmation != pin:
            messagebox.showerror("PINs do not match", "The two PIN entries were different. Nothing was saved.")
            self.status.set("New vault PIN confirmation failed.")
            return None
        self.confirmed_new_vault_pin = pin
        return pin

    def ensure_loaded_write_context(self):
        if self.key is None:
            raise ValueError("Open the vault first.")
        current_pin = self.pin_var.get()
        if current_pin != self.loaded_pin:
            raise ValueError(
                "The PIN box changed after the vault was opened.\n\n"
                "Click OPEN VAULT again with the exact USB key and PIN before saving changes."
            )
        if self.loaded_key_id and self.key.get("key_id") != self.loaded_key_id:
            raise ValueError("The loaded vault session no longer matches the original USB key.")
        return current_pin

    def confirmed_current_pin_if_needed(self, title, prompt, cancel_status):
        pin = self.pin_var.get()
        if not pin:
            return ""
        confirmation = simpledialog.askstring(title, prompt, show="*", parent=self)
        if confirmation is None:
            self.status.set(cancel_status)
            return None
        if confirmation != pin:
            messagebox.showerror("PINs do not match", "The two PIN entries were different. Nothing was exported.")
            self.status.set("PIN confirmation failed. Nothing was exported.")
            return None
        return pin

    def save_entries(self):
        pin = self.ensure_loaded_write_context()
        pin = self.confirm_new_vault_pin_if_needed()
        if pin is None:
            return False
        out_path = locker.save_personal_vault(self.entries, self.key, pin)
        self.vault_summary.set(
            "\n".join(
                [
                    f"Vault file: {out_path}",
                    f"Loaded with key ID: {self.key['key_id']}",
                    f"Protection mode: {'USB key only' if not pin else 'USB key + PIN'}",
                    f"Saved items: {len(self.entries)}",
                ]
            )
        )
        locker.log_event("vault_pad_save", out_path, "ok", f"entries={len(self.entries)}")
        self.status.set(f"Vault saved with {len(self.entries)} item(s).")
        return True

    def add_or_update(self):
        draft = self.capture_editor_fields()
        had_loaded_session = self.key is not None
        if not self.ensure_loaded():
            if not had_loaded_session:
                self.restore_editor_fields(draft, clear_selection=True)
                self.status.set("Vault open failed. Draft kept in the editor.")
            return
        if not had_loaded_session:
            self.restore_editor_fields(draft, clear_selection=True)
        backup_entries = self.clone_entries()
        backup_selected_id = self.selected_entry_id
        label = self.label_entry.get().strip()
        account = self.account_entry.get().strip()
        secret = self.secret_text.get("1.0", "end").strip()
        notes = self.notes_text.get("1.0", "end").strip()
        if not label and not account and not secret and not notes:
            messagebox.showerror("Empty item", "Type something to save first.")
            return
        entry = {
            "id": secrets.token_hex(6),
            "type": self.type_var.get(),
            "label": label or "(no label)",
            "account": account,
            "secret": secret,
            "notes": notes,
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        target_index = next((index for index, current in enumerate(self.entries) if current.get("id") == self.selected_entry_id), None)
        if target_index is None:
            self.entries.append(entry)
            self.selected_entry_id = entry["id"]
        else:
            entry["id"] = self.entries[target_index].get("id", entry["id"])
            self.entries[target_index] = entry
            self.selected_entry_id = entry["id"]
        self.sort_entries()
        try:
            if self.save_entries():
                self.refresh_list(self.selected_entry_id)
            else:
                self.entries = backup_entries
                self.selected_entry_id = backup_selected_id
        except Exception as exc:
            self.entries = backup_entries
            self.selected_entry_id = backup_selected_id
            locker.log_event("vault_pad_save", locker.VAULT_FILE, "failed", str(exc))
            messagebox.showerror("Save failed", str(exc))
            self.status.set("Save failed.")

    def delete_selected(self):
        selection = self.item_list.curselection()
        if not selection:
            messagebox.showerror("Nothing selected", "Pick an item to delete.")
            return
        if not messagebox.askyesno("Delete item", "Delete this personal vault item?"):
            return
        backup_entries = self.clone_entries()
        backup_selected_id = self.selected_entry_id
        del self.entries[self.visible_indices[selection[0]]]
        try:
            if self.save_entries():
                locker.log_event("vault_pad_delete", locker.VAULT_FILE, "ok")
                self.clear_fields()
                self.refresh_list()
            else:
                self.entries = backup_entries
                self.selected_entry_id = backup_selected_id
        except Exception as exc:
            self.entries = backup_entries
            self.selected_entry_id = backup_selected_id
            locker.log_event("vault_pad_delete", locker.VAULT_FILE, "failed", str(exc))
            messagebox.showerror("Delete failed", str(exc))
            self.status.set("Delete failed.")

    def duplicate_selected(self):
        selection = self.item_list.curselection()
        if not selection:
            messagebox.showerror("Nothing selected", "Pick an item to duplicate.")
            return
        backup_entries = self.clone_entries()
        backup_selected_id = self.selected_entry_id
        source = dict(self.entries[self.visible_indices[selection[0]]])
        source["id"] = secrets.token_hex(6)
        source["label"] = f"{source.get('label', '(no label)')} copy"
        source["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.entries.append(source)
        self.sort_entries()
        try:
            if self.save_entries():
                locker.log_event("vault_pad_duplicate", locker.VAULT_FILE, "ok")
                self.refresh_list(source["id"])
            else:
                self.entries = backup_entries
                self.selected_entry_id = backup_selected_id
        except Exception as exc:
            self.entries = backup_entries
            self.selected_entry_id = backup_selected_id
            locker.log_event("vault_pad_duplicate", locker.VAULT_FILE, "failed", str(exc))
            messagebox.showerror("Duplicate failed", str(exc))
            self.status.set("Duplicate failed.")

    def copy_temporarily(self, text_value, label):
        if not text_value.strip():
            self.status.set(f"No {label.lower()} to copy.")
            return
        self.clipboard_clear()
        self.clipboard_append(text_value)
        self.update()
        if self.clipboard_job is not None:
            self.after_cancel(self.clipboard_job)

        def clear_if_same(expected=text_value):
            try:
                current = self.clipboard_get()
            except Exception:
                current = None
            if current == expected:
                self.clipboard_clear()
                self.status.set("Clipboard cleared automatically.")

        self.clipboard_job = self.after(45000, clear_if_same)
        self.status.set(f"Copied {label.lower()}. Clipboard will clear in 45 seconds.")

    def open_app_folder(self):
        try:
            os.startfile(locker.SOURCE_DIR)
            self.status.set("Opened app folder.")
        except Exception as exc:
            self.status.set("Could not open the app folder.")
            messagebox.showerror("Could not open app folder", str(exc))

    def import_text_file(self):
        path = filedialog.askopenfilename(
            title="Import a text file into Personal Vault Pad",
            filetypes=[("Text-like files", "*.txt *.csv *.json *.log *.md"), ("All files", "*.*")],
        )
        if not path:
            return
        source = Path(path)
        try:
            try:
                content = source.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                content = source.read_text(encoding="utf-16")
        except Exception as exc:
            messagebox.showerror("Import failed", f"Could not read that file as text.\n\n{exc}")
            return
        self.clear_fields()
        lowered_name = source.name.lower()
        if "pass" in lowered_name or "code" in lowered_name:
            self.type_var.set("Passcode")
        elif "recover" in lowered_name or "backup" in lowered_name:
            self.type_var.set("Recovery code")
        elif "account" in lowered_name or "login" in lowered_name:
            self.type_var.set("Account")
        else:
            self.type_var.set("Private note")
        self.label_entry.insert(0, source.stem)
        self.notes_text.insert("1.0", content)
        locker.log_event("vault_pad_import_text", source, "ok")
        self.status.set(f"Imported text from {source.name}.")

    def export_selected_locked(self):
        selection = self.item_list.curselection()
        if not selection:
            messagebox.showerror("Nothing selected", "Pick an item to export.")
            return
        if not self.ensure_loaded():
            return
        entry = self.entries[self.visible_indices[selection[0]]]
        path = filedialog.asksaveasfilename(
            title="Save locked vault item",
            initialfile=f"{locker.safe_filename_piece(entry.get('label', 'vault_item'))}.txt.locked",
            defaultextension=".locked",
            filetypes=[("Locked file", "*.locked"), ("All files", "*.*")],
        )
        if not path:
            return
        content = "\n".join(
            [
                f"Type: {entry.get('type', '')}",
                f"Label: {entry.get('label', '')}",
                f"Account: {entry.get('account', '')}",
                "",
                "Secret:",
                entry.get("secret", ""),
                "",
                "Notes:",
                entry.get("notes", ""),
            ]
        ).strip() + "\n"
        temp_path = None
        locked_temp_path = None
        try:
            export_pin = self.confirmed_current_pin_if_needed(
                "Confirm export PIN",
                "Re-enter the exact PIN for this locked export.\n\nIf you forget it, the exported file cannot be opened.",
                "Locked export canceled before PIN confirmation.",
            )
            if export_pin is None:
                return
            handle, temp_name = locker.secure_mkstemp(prefix="vault-export-", suffix=".txt")
            os.close(handle)
            temp_path = Path(temp_name)
            temp_path.write_text(content, encoding="utf-8")
            locked_temp_path = locker.lock_file(temp_path, self.key, export_pin)
            final_path = Path(path)
            final_path.parent.mkdir(parents=True, exist_ok=True)
            if final_path.exists():
                final_path.unlink()
            locked_temp_path.replace(final_path)
            locker.log_event("vault_pad_export_locked", final_path, "ok")
            self.status.set(f"Locked export created: {final_path.name}")
            messagebox.showinfo("Locked export complete", f"Created locked file:\n{final_path}")
        except Exception as exc:
            locker.log_event("vault_pad_export_locked", path, "failed", str(exc))
            messagebox.showerror("Locked export failed", str(exc))
            self.status.set("Locked export failed.")
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            if locked_temp_path is not None and locked_temp_path.exists():
                locked_temp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    app = PersonalVaultPad()
    app.mainloop()
