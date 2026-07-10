import tkinter as tk
from tkinter import messagebox

import usb_file_locker as locker


ALERT_SECONDS = 15
REFRESH_MS = 15000


def summary_signature(summary):
    return (
        summary.get("level", ""),
        tuple((signal.get("level", ""), signal.get("title", ""), signal.get("summary", "")) for signal in summary.get("signals", [])),
    )


class GlobalBreachGuard(tk.Tk):
    def __init__(self):
        super().__init__()
        if not locker.ensure_license_feature("global-breach-guard", parent=self):
            self.after(0, self.destroy)
            return
        self.title("Global Breach Guard")
        self.geometry("520x360")
        self.minsize(460, 320)
        self.configure(bg=locker.BG)
        self.attributes("-topmost", True)
        self.status = tk.StringVar(value="Watching the signed audit trail...")
        self.level_text = tk.StringVar(value="Waiting for first scan...")
        self.summary_text = tk.StringVar(value="")
        self.watch_enabled = tk.BooleanVar(value=True)
        self.last_signature = None
        self.alert_window = None
        self.refresh_job = None
        self.build_ui()
        self.refresh_now(initial=True)

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=20, pady=18)

        tk.Label(outer, text="Global Breach Guard", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 24, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="Background breach watcher for the USB File Locker audit chain.",
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 12))

        card = tk.Frame(outer, bg=locker.PANEL)
        card.pack(fill="both", expand=True)

        self.level_label = tk.Label(card, textvariable=self.level_text, bg=locker.PANEL, fg=locker.GREEN, font=("Segoe UI", 13, "bold"), justify="left", wraplength=460)
        self.level_label.pack(anchor="w", padx=18, pady=(18, 8))
        tk.Label(card, textvariable=self.summary_text, bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 10), justify="left", wraplength=460).pack(anchor="w", padx=18)

        controls = tk.Frame(card, bg=locker.PANEL)
        controls.pack(fill="x", padx=18, pady=(18, 12))
        tk.Checkbutton(
            controls,
            text="WATCH GLOBALLY",
            variable=self.watch_enabled,
            bg=locker.PANEL,
            fg=locker.TEXT,
            selectcolor=locker.FIELD,
            activebackground=locker.PANEL,
            activeforeground=locker.TEXT,
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left")
        tk.Button(controls, text="REFRESH NOW", command=self.refresh_now, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=12, ipady=8)

        row = tk.Frame(card, bg=locker.PANEL)
        row.pack(fill="x", padx=18, pady=(0, 18))
        tk.Button(row, text="OPEN BREACH REPORT", command=self.open_report, bg=locker.WHITE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=12, ipady=8)
        tk.Button(row, text="OPEN AUDIT VIEWER", command=self.open_audit_viewer, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(row, text="OPEN MAIN LOCKER", command=self.open_main_locker, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(row, text="CLOSE", command=self.destroy, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=14, ipady=8)

        tk.Label(outer, textvariable=self.status, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(12, 0))

    def level_color(self, level):
        return {
            "clear": locker.GREEN,
            "warning": locker.YELLOW,
            "high": locker.RED,
            "critical": locker.RED,
        }.get(level, locker.TEXT)

    def open_report(self):
        try:
            locker.open_breach_detection_window(self)
            self.status.set("Opened the breach report.")
        except Exception as exc:
            self.status.set("Could not open the breach report.")
            messagebox.showerror("Could not open report", str(exc))

    def open_audit_viewer(self):
        try:
            locker.launch_companion_script("audit_log_viewer.py")
            self.status.set("Opened Audit Log Viewer.")
        except Exception as exc:
            self.status.set("Could not open Audit Log Viewer.")
            messagebox.showerror("Could not open Audit Log Viewer", str(exc))

    def open_main_locker(self):
        try:
            locker.launch_main_app_process()
            self.status.set("Opened Main Locker.")
        except Exception as exc:
            self.status.set("Could not open Main Locker.")
            messagebox.showerror("Could not open Main Locker", str(exc))

    def show_alert(self, summary):
        if self.alert_window is not None:
            try:
                if self.alert_window.winfo_exists():
                    self.alert_window.destroy()
            except Exception:
                pass
        alert = tk.Toplevel(self)
        self.alert_window = alert
        alert.title("Breach Alert")
        alert.geometry("620x230")
        alert.resizable(False, False)
        alert.configure(bg=locker.BG)
        alert.attributes("-topmost", True)

        outer = tk.Frame(alert, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=20, pady=18)

        level_label = "CRITICAL BREACH ALERT" if summary["level"] == "critical" else "HIGH-RISK BREACH ALERT"
        tk.Label(outer, text=level_label, bg=locker.BG, fg=locker.RED, font=("Segoe UI", 22, "bold")).pack(anchor="w")
        tk.Label(outer, text=summary["headline"], bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 10, "bold"), justify="left", wraplength=580).pack(anchor="w", pady=(6, 10))

        text = tk.Text(outer, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", bd=0, wrap="word", font=("Consolas", 10), height=5)
        text.pack(fill="both", expand=True)
        text.insert("1.0", locker.breach_detection_text(summary))
        text.configure(state="disabled")

        row = tk.Frame(outer, bg=locker.BG)
        row.pack(fill="x", pady=(12, 0))
        tk.Button(row, text="OPEN REPORT", command=lambda: (alert.destroy(), self.open_report()), bg=locker.WHITE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=12, ipady=8)
        tk.Button(row, text="DISMISS", command=alert.destroy, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=14, ipady=8)

        try:
            self.bell()
        except Exception:
            pass
        alert.after(ALERT_SECONDS * 1000, lambda: alert.destroy() if alert.winfo_exists() else None)

    def refresh_now(self, initial=False):
        try:
            summary = locker.breach_detection_summary()
            self.level_label.configure(fg=self.level_color(summary["level"]))
            prefix = {
                "clear": "GLOBAL STATUS: CLEAR",
                "warning": "GLOBAL STATUS: WARNING",
                "high": "GLOBAL STATUS: HIGH RISK",
                "critical": "GLOBAL STATUS: CRITICAL",
            }.get(summary["level"], "GLOBAL STATUS")
            self.level_text.set(f"{prefix}\n{summary['headline']}")
            self.summary_text.set(f"Checked {summary['record_count']} signed audit event(s).\n{summary['audit_message']}")
            self.status.set("Watching globally." if self.watch_enabled.get() else "Watch paused.")
            signature = summary_signature(summary)
            if self.watch_enabled.get() and not initial and signature != self.last_signature and summary["level"] in {"high", "critical"}:
                self.show_alert(summary)
            self.last_signature = signature
        except Exception as exc:
            self.level_label.configure(fg=locker.RED)
            self.level_text.set("GLOBAL STATUS: UNAVAILABLE")
            self.summary_text.set(str(exc))
            self.status.set("Breach guard refresh failed.")
        finally:
            if self.winfo_exists():
                if self.refresh_job is not None:
                    try:
                        self.after_cancel(self.refresh_job)
                    except Exception:
                        pass
                self.refresh_job = self.after(REFRESH_MS, self.refresh_now)


if __name__ == "__main__":
    app = GlobalBreachGuard()
    app.mainloop()
