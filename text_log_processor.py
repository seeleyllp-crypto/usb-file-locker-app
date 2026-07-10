from collections import Counter
from datetime import datetime, timezone
import re
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import usb_file_locker as locker


ROW_RE = re.compile(
    r"^\s*(?P<sequence>\d+)\s+(?P<time_utc>\S+)\s+(?P<event_id>\S+)\s+(?P<action>.+?)\s{2,}(?P<result>\S+)\s*$"
)
SUCCESS_WORDS = {"success", "ok", "passed", "pass"}
FAILURE_WORDS = {"failure", "failed", "error", "blocked", "denied"}


def parse_table_log(text):
    records = []
    skipped = []
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.rstrip("\r\n")
        stripped = line.strip()
        if not stripped:
            continue
        upper = stripped.upper()
        if upper.startswith("SEQ ") or set(stripped) == {"-"}:
            continue
        match = ROW_RE.match(line)
        if not match:
            skipped.append({"line_number": line_number, "text": line})
            continue
        record = match.groupdict()
        record["sequence"] = int(record["sequence"])
        record["line_number"] = line_number
        record["result_lower"] = record["result"].strip().lower()
        records.append(record)
    return records, skipped


def parse_utc_time(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def classify_result(value):
    lowered = str(value).strip().lower()
    if lowered in SUCCESS_WORDS:
        return "success"
    if lowered in FAILURE_WORDS:
        return "failure"
    return "other"


def build_analysis(records, skipped):
    action_counts = Counter(record["action"] for record in records)
    result_counts = Counter(classify_result(record["result"]) for record in records)
    sequence_counts = Counter(record["sequence"] for record in records)
    event_id_counts = Counter(record["event_id"] for record in records)
    duplicate_sequences = {key: value for key, value in sequence_counts.items() if value > 1}
    duplicate_event_ids = {key: value for key, value in event_id_counts.items() if value > 1}
    failure_rows = [record for record in records if classify_result(record["result"]) == "failure"]
    success_rows = [record for record in records if classify_result(record["result"]) == "success"]
    other_rows = [record for record in records if classify_result(record["result"]) == "other"]

    non_increasing = []
    previous_sequence = None
    for record in records:
        current_sequence = record["sequence"]
        if previous_sequence is not None and current_sequence <= previous_sequence:
            non_increasing.append(record)
        previous_sequence = current_sequence

    parsed_times = [parse_utc_time(record["time_utc"]) for record in records]
    parsed_times = [value for value in parsed_times if value is not None]
    first_time = min(parsed_times) if parsed_times else None
    last_time = max(parsed_times) if parsed_times else None
    duration = ""
    if first_time and last_time:
        delta = last_time - first_time
        total_seconds = int(delta.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        duration = f"{hours}h {minutes}m {seconds}s"

    return {
        "records": records,
        "skipped": skipped,
        "action_counts": action_counts,
        "result_counts": result_counts,
        "duplicate_sequences": duplicate_sequences,
        "duplicate_event_ids": duplicate_event_ids,
        "failure_rows": failure_rows,
        "success_rows": success_rows,
        "other_rows": other_rows,
        "non_increasing": non_increasing,
        "first_time": first_time,
        "last_time": last_time,
        "duration": duration,
    }


def format_timestamp(value):
    if value is None:
        return "unknown"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def analysis_report(analysis):
    records = analysis["records"]
    skipped = analysis["skipped"]
    lines = [
        "Text Log Processor Report",
        "",
        f"Parsed rows: {len(records)}",
        f"Skipped lines: {len(skipped)}",
        f"Success rows: {len(analysis['success_rows'])}",
        f"Failure rows: {len(analysis['failure_rows'])}",
        f"Other result rows: {len(analysis['other_rows'])}",
        f"Unique event IDs: {len({record['event_id'] for record in records})}",
        f"Time range: {format_timestamp(analysis['first_time'])} to {format_timestamp(analysis['last_time'])}",
    ]
    if analysis["duration"]:
        lines.append(f"Observed span: {analysis['duration']}")
    lines.append("")
    if analysis["duplicate_sequences"]:
        joined = ", ".join(f"{sequence} x{count}" for sequence, count in sorted(analysis["duplicate_sequences"].items()))
        lines.append(f"Duplicate sequence numbers: {joined}")
    else:
        lines.append("Duplicate sequence numbers: none")
    if analysis["duplicate_event_ids"]:
        joined = ", ".join(f"{event_id} x{count}" for event_id, count in sorted(analysis["duplicate_event_ids"].items()))
        lines.append(f"Duplicate event IDs: {joined}")
    else:
        lines.append("Duplicate event IDs: none")
    if analysis["non_increasing"]:
        joined = ", ".join(
            f"seq {record['sequence']} on line {record['line_number']}" for record in analysis["non_increasing"][:10]
        )
        if len(analysis["non_increasing"]) > 10:
            joined += ", ..."
        lines.append(f"Non-increasing sequence rows: {joined}")
    else:
        lines.append("Non-increasing sequence rows: none")
    lines.append("")
    lines.append("Top actions:")
    for action, count in analysis["action_counts"].most_common(10):
        lines.append(f"- {action}: {count}")
    if not analysis["action_counts"]:
        lines.append("- none")
    lines.append("")
    lines.append("Failure actions:")
    failure_action_counts = Counter(record["action"] for record in analysis["failure_rows"])
    if failure_action_counts:
        for action, count in failure_action_counts.most_common(10):
            lines.append(f"- {action}: {count}")
    else:
        lines.append("- none")
    if skipped:
        lines.append("")
        lines.append("Skipped lines:")
        for row in skipped[:15]:
            lines.append(f"- line {row['line_number']}: {row['text']}")
        if len(skipped) > 15:
            lines.append(f"- ... and {len(skipped) - 15} more skipped line(s)")
    return "\n".join(lines)


def failures_report(analysis):
    rows = analysis["failure_rows"]
    if not rows:
        return "No failure rows were found."
    lines = ["Failure Rows", ""]
    for record in rows:
        lines.append(
            f"seq {record['sequence']} | {record['time_utc']} | {record['action']} | {record['result']} | {record['event_id']}"
        )
    return "\n".join(lines)


class TextLogProcessor(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Text Log Processor")
        self.geometry("1400x920")
        self.minsize(1180, 760)
        self.configure(bg=locker.BG)
        self.status = tk.StringVar(value="Load or paste a text log, then click PROCESS NOW.")
        self.count_text = tk.StringVar(value="No rows loaded yet.")
        self.filter_var = tk.StringVar(value="all")
        self.search_var = tk.StringVar(value="")
        self.records = []
        self.filtered_records = []
        self.skipped = []
        self.analysis = build_analysis([], [])
        self.tree = None
        self.summary_box = None
        self.details_box = None
        self.raw_box = None
        self.build_ui()

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=22)

        tk.Label(outer, text="Text Log Processor", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 28, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="Paste or load table-style logs, then count actions, spot failures, catch duplicate sequence numbers, and export a cleaner report.",
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 14))

        top = tk.Frame(outer, bg=locker.PANEL)
        top.pack(fill="x")
        action_row = tk.Frame(top, bg=locker.PANEL)
        action_row.pack(fill="x", padx=18, pady=18)
        tk.Button(action_row, text="LOAD TXT FILE", command=self.load_text_file, bg=locker.WHITE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", ipadx=12, ipady=8)
        tk.Button(action_row, text="PASTE CLIPBOARD", command=self.load_clipboard, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(action_row, text="PROCESS NOW", command=self.process_text, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=14, ipady=8)
        tk.Button(action_row, text="EXPORT REPORT", command=self.export_report, bg=locker.YELLOW, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(action_row, text="COPY FAILURES", command=self.copy_failures, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=12, ipady=8)
        tk.Button(action_row, text="CLEAR", command=self.clear_all, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 0), ipadx=14, ipady=8)
        tk.Button(action_row, text="OPEN MAIN LOCKER", command=self.open_main_locker, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=12, ipady=8)

        summary = tk.Frame(outer, bg=locker.PANEL)
        summary.pack(fill="x", pady=(14, 14))
        tk.Label(summary, text="Summary", bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=18, pady=(16, 8))
        tk.Label(summary, textvariable=self.count_text, bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 9, "bold"), justify="left", wraplength=1320).pack(anchor="w", padx=18, pady=(0, 14))

        body = tk.PanedWindow(outer, orient="horizontal", sashwidth=8, bg=locker.BG, bd=0, relief="flat")
        body.pack(fill="both", expand=True)

        left = tk.Frame(body, bg=locker.PANEL)
        body.add(left, minsize=420)
        tk.Label(left, text="Raw Text Log", bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=18, pady=(18, 8))
        tk.Label(left, text="Paste the table log here or load a .txt file.", bg=locker.PANEL, fg=locker.MUTED, font=("Segoe UI", 9)).pack(anchor="w", padx=18, pady=(0, 12))
        raw_frame = tk.Frame(left, bg=locker.PANEL)
        raw_frame.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self.raw_box = tk.Text(raw_frame, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", bd=0, wrap="none", font=("Consolas", 10))
        self.raw_box.pack(side="left", fill="both", expand=True)
        raw_y = ttk.Scrollbar(raw_frame, orient="vertical", command=self.raw_box.yview)
        raw_y.pack(side="left", fill="y")
        raw_x = ttk.Scrollbar(left, orient="horizontal", command=self.raw_box.xview)
        raw_x.pack(fill="x", padx=18, pady=(0, 18))
        self.raw_box.configure(yscrollcommand=raw_y.set, xscrollcommand=raw_x.set)

        right = tk.Frame(body, bg=locker.BG)
        body.add(right, minsize=620)

        summary_card = tk.Frame(right, bg=locker.PANEL)
        summary_card.pack(fill="x")
        tk.Label(summary_card, text="Processed Report", bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=18, pady=(18, 8))
        self.summary_box = tk.Text(summary_card, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", bd=0, wrap="word", font=("Consolas", 10), height=14)
        self.summary_box.pack(fill="x", padx=18, pady=(0, 18))
        self.summary_box.configure(state="disabled")

        filters = tk.Frame(right, bg=locker.BG)
        filters.pack(fill="x", pady=(14, 12))
        tk.Label(filters, text="SEARCH", bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        search = tk.Entry(filters, textvariable=self.search_var, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", font=("Segoe UI", 10), width=32)
        search.pack(side="left", padx=(10, 18), ipady=7)
        tk.Label(filters, text="SHOW", bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        tk.Radiobutton(filters, text="ALL", value="all", variable=self.filter_var, command=self.apply_filter, bg=locker.BG, fg=locker.TEXT, selectcolor=locker.FIELD, activebackground=locker.BG, activeforeground=locker.TEXT, font=("Segoe UI", 8, "bold")).pack(side="left", padx=(10, 0))
        tk.Radiobutton(filters, text="SUCCESS", value="success", variable=self.filter_var, command=self.apply_filter, bg=locker.BG, fg=locker.TEXT, selectcolor=locker.FIELD, activebackground=locker.BG, activeforeground=locker.TEXT, font=("Segoe UI", 8, "bold")).pack(side="left", padx=(10, 0))
        tk.Radiobutton(filters, text="FAILURE", value="failure", variable=self.filter_var, command=self.apply_filter, bg=locker.BG, fg=locker.TEXT, selectcolor=locker.FIELD, activebackground=locker.BG, activeforeground=locker.TEXT, font=("Segoe UI", 8, "bold")).pack(side="left", padx=(10, 0))
        search.bind("<KeyRelease>", lambda _event: self.apply_filter())

        results = tk.Frame(right, bg=locker.PANEL)
        results.pack(fill="both", expand=True)

        columns = ("sequence", "time_utc", "event_id", "action", "result")
        self.tree = ttk.Treeview(results, columns=columns, show="headings", height=16)
        self.tree.heading("sequence", text="Seq")
        self.tree.heading("time_utc", text="UTC Time")
        self.tree.heading("event_id", text="Event ID")
        self.tree.heading("action", text="Action")
        self.tree.heading("result", text="Result")
        self.tree.column("sequence", width=75, anchor="e")
        self.tree.column("time_utc", width=170, anchor="w")
        self.tree.column("event_id", width=160, anchor="w")
        self.tree.column("action", width=260, anchor="w")
        self.tree.column("result", width=100, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True, padx=(18, 0), pady=18)
        self.tree.bind("<<TreeviewSelect>>", lambda _event: self.update_details())
        self.tree.tag_configure("failure", foreground="#ff8b94")
        self.tree.tag_configure("warning", foreground=locker.YELLOW)
        result_scroll = ttk.Scrollbar(results, orient="vertical", command=self.tree.yview)
        result_scroll.pack(side="left", fill="y", padx=(0, 18), pady=18)
        self.tree.configure(yscrollcommand=result_scroll.set)

        details_card = tk.Frame(right, bg=locker.PANEL)
        details_card.pack(fill="x", pady=(14, 0))
        tk.Label(details_card, text="Selected Row", bg=locker.PANEL, fg=locker.TEXT, font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=18, pady=(18, 8))
        self.details_box = tk.Text(details_card, bg=locker.FIELD, fg=locker.TEXT, insertbackground=locker.TEXT, relief="flat", bd=0, wrap="word", font=("Consolas", 10), height=10)
        self.details_box.pack(fill="x", padx=18, pady=(0, 18))
        self.details_box.configure(state="disabled")

        tk.Label(outer, textvariable=self.status, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(12, 0))

    def open_main_locker(self):
        try:
            locker.launch_main_app_process()
            self.status.set("Opened Main Locker.")
        except Exception as exc:
            self.status.set("Could not open Main Locker.")
            messagebox.showerror("Could not open Main Locker", str(exc))

    def set_summary_text(self, value):
        self.summary_box.configure(state="normal")
        self.summary_box.delete("1.0", "end")
        self.summary_box.insert("1.0", value)
        self.summary_box.configure(state="disabled")

    def set_details_text(self, value):
        self.details_box.configure(state="normal")
        self.details_box.delete("1.0", "end")
        self.details_box.insert("1.0", value)
        self.details_box.configure(state="disabled")

    def load_text_file(self):
        path = filedialog.askopenfilename(
            title="Load text log file",
            filetypes=[("Text logs", "*.txt *.log *.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            messagebox.showerror("Could not load file", str(exc))
            self.status.set("Could not load the text log file.")
            return
        self.raw_box.delete("1.0", "end")
        self.raw_box.insert("1.0", text)
        self.status.set(f"Loaded text log from {path}.")
        self.process_text()

    def load_clipboard(self):
        try:
            text = self.clipboard_get()
        except Exception as exc:
            messagebox.showerror("Clipboard unavailable", str(exc))
            self.status.set("Clipboard text could not be loaded.")
            return
        self.raw_box.delete("1.0", "end")
        self.raw_box.insert("1.0", text)
        self.status.set("Loaded text from clipboard.")
        self.process_text()

    def process_text(self):
        text = self.raw_box.get("1.0", "end").strip()
        if not text:
            self.records = []
            self.skipped = []
            self.analysis = build_analysis([], [])
            self.set_summary_text("No text loaded yet.")
            self.apply_filter()
            self.count_text.set("No rows loaded yet.")
            self.status.set("Nothing to process yet.")
            return
        records, skipped = parse_table_log(text)
        self.records = records
        self.skipped = skipped
        self.analysis = build_analysis(records, skipped)
        self.set_summary_text(analysis_report(self.analysis))
        self.count_text.set(
            f"Rows: {len(records)} | success: {len(self.analysis['success_rows'])} | failure: {len(self.analysis['failure_rows'])} | skipped: {len(skipped)}"
        )
        self.apply_filter()
        if records:
            self.status.set(f"Processed {len(records)} row(s).")
        else:
            self.status.set("No log rows matched the expected table format.")

    def apply_filter(self):
        query = self.search_var.get().strip().lower()
        desired = self.filter_var.get()
        filtered = []
        duplicate_sequences = set(self.analysis["duplicate_sequences"])
        for record in self.records:
            classified = classify_result(record["result"])
            if desired != "all" and classified != desired:
                continue
            haystack = " ".join(
                str(record.get(field, ""))
                for field in ("sequence", "time_utc", "event_id", "action", "result")
            ).lower()
            if query and query not in haystack:
                continue
            filtered.append(record)
        self.filtered_records = filtered
        self.tree.delete(*self.tree.get_children())
        for index, record in enumerate(filtered):
            tags = []
            classified = classify_result(record["result"])
            if classified == "failure":
                tags.append("failure")
            elif record["sequence"] in duplicate_sequences:
                tags.append("warning")
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    record["sequence"],
                    record["time_utc"],
                    record["event_id"],
                    record["action"],
                    record["result"],
                ),
                tags=tuple(tags),
            )
        if filtered:
            self.tree.selection_set("0")
            self.tree.see("0")
        self.update_details()

    def selected_record(self):
        selection = self.tree.selection()
        if not selection:
            return None
        try:
            return self.filtered_records[int(selection[0])]
        except Exception:
            return None

    def update_details(self):
        record = self.selected_record()
        if record is None:
            self.set_details_text("Pick a parsed row to inspect it here.")
            return
        duplicate_note = "yes" if record["sequence"] in self.analysis["duplicate_sequences"] else "no"
        duplicate_event = "yes" if record["event_id"] in self.analysis["duplicate_event_ids"] else "no"
        detail_lines = [
            f"Line number: {record['line_number']}",
            f"Sequence: {record['sequence']}",
            f"UTC time: {record['time_utc']}",
            f"Event ID: {record['event_id']}",
            f"Action: {record['action']}",
            f"Result: {record['result']}",
            "",
            f"Duplicate sequence: {duplicate_note}",
            f"Duplicate event ID: {duplicate_event}",
            f"Result class: {classify_result(record['result'])}",
        ]
        self.set_details_text("\n".join(detail_lines))

    def export_report(self):
        if not self.records and not self.skipped:
            messagebox.showinfo("Nothing to export", "Load or paste a text log first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save processed report",
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            initialfile="processed_log_report.txt",
        )
        if not path:
            return
        report = analysis_report(self.analysis)
        failure_text = failures_report(self.analysis)
        full_text = report + "\n\n" + failure_text + "\n"
        try:
            Path(path).write_text(full_text, encoding="utf-8")
            self.status.set(f"Saved processed report to {path}.")
        except Exception as exc:
            messagebox.showerror("Could not save report", str(exc))
            self.status.set("Could not save the processed report.")

    def copy_failures(self):
        text = failures_report(self.analysis)
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        self.status.set("Copied failure rows report.")

    def clear_all(self):
        self.raw_box.delete("1.0", "end")
        self.records = []
        self.filtered_records = []
        self.skipped = []
        self.analysis = build_analysis([], [])
        self.tree.delete(*self.tree.get_children())
        self.set_summary_text("No text loaded yet.")
        self.set_details_text("Pick a parsed row to inspect it here.")
        self.count_text.set("No rows loaded yet.")
        self.status.set("Cleared the processor.")


if __name__ == "__main__":
    app = TextLogProcessor()
    app.mainloop()
