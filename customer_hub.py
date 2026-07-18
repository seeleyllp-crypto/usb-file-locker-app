import json
import os
import queue
import re
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

import usb_file_locker as locker


PROGRESS_FILE = locker.APP_DIR / "customer_workspace_progress.json"
ACTION_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")


def normalize_customer_progress(payload):
    source = payload if isinstance(payload, dict) else {}
    values = source.get("completed_action_ids") if isinstance(source.get("completed_action_ids"), list) else []
    action_ids = sorted(
        {
            str(value)
            for value in values
            if isinstance(value, str) and ACTION_ID_RE.fullmatch(value)
        }
    )[:100]
    return {
        "schema_version": 1,
        "completed_action_ids": action_ids,
        "updated_at_utc": str(source.get("updated_at_utc") or "")[:40],
        "privacy_notice": "Only fixed customer action IDs and a UTC timestamp are stored locally.",
    }


def load_customer_progress(path=None):
    target = Path(path or PROGRESS_FILE)
    if not target.is_file():
        return normalize_customer_progress({})
    try:
        return normalize_customer_progress(json.loads(target.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return normalize_customer_progress({})


def save_customer_progress(completed_action_ids, path=None):
    target = Path(path or PROGRESS_FILE)
    payload = normalize_customer_progress(
        {
            "completed_action_ids": list(completed_action_ids),
            "updated_at_utc": locker.utc_now_text(),
        }
    )
    locker.write_text_atomic(target, json.dumps(payload, indent=2))
    return payload


def next_unfinished_action(workspace, completed_action_ids):
    source = workspace if isinstance(workspace, dict) else {}
    completed = set(completed_action_ids or ())
    actions = (source.get("action_center") or {}).get("items") or []
    for item in actions:
        if isinstance(item, dict) and item.get("id") not in completed:
            return item
    if actions:
        return {}
    fallback = source.get("next_best_action")
    return fallback if isinstance(fallback, dict) else {}


def customer_care_export(workspace, completed_action_ids=None):
    source = workspace if isinstance(workspace, dict) else {}
    snapshot = source.get("customer_snapshot") if isinstance(source.get("customer_snapshot"), dict) else {}
    score = source.get("workspace_score") if isinstance(source.get("workspace_score"), dict) else {}
    next_action = source.get("next_best_action") if isinstance(source.get("next_best_action"), dict) else {}
    routine = source.get("weekly_routine") if isinstance(source.get("weekly_routine"), dict) else {}
    help_center = source.get("help_center") if isinstance(source.get("help_center"), dict) else {}
    journey = source.get("journey_map") if isinstance(source.get("journey_map"), dict) else {}
    seat = source.get("seat_planner") if isinstance(source.get("seat_planner"), dict) else {}
    support = source.get("support_readiness") if isinstance(source.get("support_readiness"), dict) else {}
    ninety_day = source.get("ninety_day_plan") if isinstance(source.get("ninety_day_plan"), dict) else {}
    digest = source.get("change_digest") if isinstance(source.get("change_digest"), dict) else {}
    action_center = source.get("action_center") if isinstance(source.get("action_center"), dict) else {}

    def text(value, limit=320):
        return str(value or "").strip()[:limit]

    def number(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    valid_action_ids = {
        str(item.get("id"))
        for item in action_center.get("items", [])
        if isinstance(item, dict) and ACTION_ID_RE.fullmatch(str(item.get("id") or ""))
    }
    completed = sorted(
        {
            str(value)
            for value in (completed_action_ids or [])
            if isinstance(value, str) and value in valid_action_ids
        }
    )

    return {
        "schema_version": 1,
        "report_type": "VaultLink Privacy-Safe Customer Care Plan",
        "workspace_schema_version": number(source.get("workspace_schema_version")),
        "customer_snapshot": {
            key: text(snapshot.get(key)) if key in {"status", "rank_name"} else number(snapshot.get(key))
            for key in (
                "status",
                "rank",
                "rank_name",
                "workspace_score",
                "attention_count",
                "action_count",
                "unlocked_tool_count",
                "unlocked_benefit_count",
                "readiness_lane_count",
                "weekly_step_count",
                "journey_stage_count",
                "available_device_seats",
                "support_ready_count",
                "support_check_count",
                "ninety_day_phase_count",
                "glossary_term_count",
            )
        },
        "workspace_score": {
            "score": number(score.get("score")),
            "maximum": number(score.get("maximum")),
            "label": text(score.get("label")),
            "limitations": text(score.get("limitations")),
        },
        "next_best_action": {
            "id": text(next_action.get("id"), 80),
            "when": text(next_action.get("when"), 40),
            "severity": text(next_action.get("severity"), 40),
            "title": text(next_action.get("title")),
            "detail": text(next_action.get("detail"), 600),
            "target_path": text(next_action.get("target_path"), 120),
            "reason": text(next_action.get("reason"), 600),
        },
        "readiness_lanes": [
            {
                "id": text(item.get("id"), 80),
                "title": text(item.get("title")),
                "purpose": text(item.get("purpose"), 600),
                "awarded": number(item.get("awarded")),
                "maximum": number(item.get("maximum")),
                "percent": number(item.get("percent")),
                "state": text(item.get("state"), 40),
                "attention_count": number(item.get("attention_count")),
            }
            for item in source.get("readiness_lanes", [])
            if isinstance(item, dict)
        ],
        "weekly_routine": {
            "title": text(routine.get("title")),
            "progress_storage": text(routine.get("progress_storage"), 120),
            "items": [
                {
                    "id": text(item.get("id"), 80),
                    "day": text(item.get("day"), 40),
                    "title": text(item.get("title")),
                    "detail": text(item.get("detail"), 600),
                    "target_path": text(item.get("target_path"), 120),
                }
                for item in routine.get("items", [])
                if isinstance(item, dict)
            ],
        },
        "journey_map": {
            "title": text(journey.get("title")),
            "server_tracks_completion": bool(journey.get("server_tracks_completion")),
            "stages": [
                {
                    "id": text(item.get("id"), 80),
                    "order": number(item.get("order")),
                    "title": text(item.get("title")),
                    "state": text(item.get("state"), 40),
                    "detail": text(item.get("detail"), 600),
                    "target_path": text(item.get("target_path"), 120),
                }
                for item in journey.get("stages", [])
                if isinstance(item, dict)
            ],
        },
        "seat_planner": {
            "active": number(seat.get("active")),
            "maximum": number(seat.get("maximum")),
            "available": number(seat.get("available")),
            "usage_percent": number(seat.get("usage_percent")),
            "state": text(seat.get("state"), 40),
            "guidance": text(seat.get("guidance"), 600),
            "device_identity_included": bool(seat.get("device_identity_included")),
            "does_not_reserve_or_activate": bool(seat.get("does_not_reserve_or_activate")),
        },
        "support_readiness": {
            "ready_count": number(support.get("ready_count")),
            "total": number(support.get("total")),
            "state": text(support.get("state"), 40),
            "limitations": text(support.get("limitations"), 600),
            "items": [
                {
                    "id": text(item.get("id"), 80),
                    "title": text(item.get("title")),
                    "ready": bool(item.get("ready")),
                    "detail": text(item.get("detail"), 600),
                }
                for item in support.get("items", [])
                if isinstance(item, dict)
            ],
        },
        "ninety_day_plan": {
            "title": text(ninety_day.get("title")),
            "progress_storage": text(ninety_day.get("progress_storage"), 120),
            "phases": [
                {
                    "id": text(phase.get("id"), 80),
                    "label": text(phase.get("label"), 120),
                    "target_days": number(phase.get("target_days")),
                    "items": [
                        {
                            "id": text(item.get("id"), 80),
                            "title": text(item.get("title")),
                            "detail": text(item.get("detail"), 600),
                            "target_path": text(item.get("target_path"), 120),
                        }
                        for item in phase.get("items", [])
                        if isinstance(item, dict)
                    ],
                }
                for phase in ninety_day.get("phases", [])
                if isinstance(phase, dict)
            ],
        },
        "change_digest": {
            "api_version": text(digest.get("api_version"), 40),
            "installed_version": text(digest.get("installed_version"), 80),
            "latest_signed_version": text(digest.get("latest_signed_version"), 80),
            "desktop_state": text(digest.get("desktop_state"), 80),
            "service_mode": text(digest.get("service_mode"), 80),
            "license_state": text(digest.get("license_state"), 80),
            "changes_customer_pc": bool(digest.get("changes_customer_pc")),
        },
        "customer_glossary": [
            {
                "id": text(item.get("id"), 80),
                "term": text(item.get("term"), 120),
                "meaning": text(item.get("meaning"), 600),
            }
            for item in source.get("customer_glossary", [])
            if isinstance(item, dict)
        ],
        "entitlement_categories": [
            {
                "category": text(item.get("category"), 100),
                "count": number(item.get("count")),
                "items": [text(value) for value in item.get("items", []) if isinstance(value, str)],
            }
            for item in source.get("entitlement_categories", [])
            if isinstance(item, dict)
        ],
        "help_center": {
            "title": text(help_center.get("title")),
            "owner_reply_route": text(help_center.get("owner_reply_route"), 120),
            "free_text_not_included": bool(help_center.get("free_text_not_included")),
            "items": [
                {
                    "id": text(item.get("id"), 80),
                    "title": text(item.get("title")),
                    "first_step": text(item.get("first_step"), 600),
                    "target_path": text(item.get("target_path"), 120),
                    "support_category": text(item.get("support_category"), 80),
                }
                for item in help_center.get("items", [])
                if isinstance(item, dict)
            ],
        },
        "privacy_guarantees": [
            text(value, 600) for value in source.get("privacy_guarantees", []) if isinstance(value, str)
        ],
        "completed_action_ids": completed,
        "privacy_notice": (
            "This fixed-field plan excludes license proof, customer identity, machine identity, passwords, PINs, "
            "USB secrets, paths, filenames, file contents, payment data, and free-form support text."
        ),
    }


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
        ("READINESS", "readiness"),
        ("NEXT ACTION", "next_action"),
    )

    def __init__(self):
        super().__init__()
        self.title("VaultLink Customer Workspace")
        self.geometry("960x900")
        self.minsize(800, 720)
        self.configure(bg=locker.BG)
        self.settings = locker.load_settings()
        self.state = locker.load_license_state(self.settings)
        self.progress = load_customer_progress()
        self.completed_action_ids = set(self.progress.get("completed_action_ids") or [])
        self.results = queue.Queue()
        self.busy = False
        self.status_var = tk.StringVar(value="Loading public rank and signed-release information...")
        self.progress_var = tk.StringVar(value="0 completed on this Windows account")
        self.value_vars = {key: tk.StringVar(value="-") for _label, key in self.DETAIL_FIELDS}
        self.verify_button = None
        self.workspace_button = None
        self.export_button = None
        self.support_export_button = None
        self.recovery_export_button = None
        self.care_export_button = None
        self.next_action_button = None
        self.mark_done_button = None
        self.reset_progress_button = None
        self.refresh_button = None
        self.rank_box = None
        self.workspace_box = None
        self.workspace = None
        self.build_ui()
        self.render_details()
        self.after(150, self.refresh_public_info)

    def build_ui(self):
        outer = tk.Frame(self, bg=locker.BG)
        outer.pack(fill="both", expand=True, padx=24, pady=20)
        tk.Label(outer, text="VaultLink Customer Workspace", bg=locker.BG, fg=locker.TEXT, font=("Segoe UI", 24, "bold")).pack(anchor="w")
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
        self.workspace_button = tk.Button(controls, text="LOAD FULL WORKSPACE", command=self.load_workspace, bg=locker.BLUE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold"))
        self.workspace_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=7)
        self.refresh_button = tk.Button(controls, text="REFRESH PUBLIC INFO", command=self.refresh_public_info, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold"))
        self.refresh_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=7)
        tk.Button(controls, text="MAIN LOCKER", command=self.open_main_locker, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=10, ipady=7)
        tk.Button(controls, text="SUPPORT REDACTOR", command=self.open_support_redactor, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", padx=(0, 8), ipadx=10, ipady=7)
        tk.Button(controls, text="VERIFY DOWNLOAD", command=self.open_download_verification_center, bg=locker.BLUE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", padx=(0, 8), ipadx=10, ipady=7)

        links = tk.Frame(outer, bg=locker.BG)
        links.pack(fill="x", pady=(8, 0))
        for label, path in (
            ("ONLINE WORKSPACE", "/workspace"),
            ("DECISION WIZARD", "/decision"),
            ("ANSWERS", "/QNA"),
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
            ).pack(side="left", padx=(0 if path == "/workspace" else 8, 0), ipadx=10, ipady=6)

        tk.Label(outer, text="ALL SEVEN RANKS", bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(14, 6))
        self.rank_box = tk.Text(outer, height=5, bg=locker.FIELD, fg=locker.TEXT, relief="flat", wrap="word", font=("Segoe UI", 9), padx=12, pady=10, state="disabled")
        self.rank_box.pack(fill="x")

        workspace_head = tk.Frame(outer, bg=locker.BG)
        workspace_head.pack(fill="x", pady=(14, 6))
        tk.Label(workspace_head, text="CUSTOMER ACTION PLAN", bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        workspace_actions = tk.Frame(outer, bg=locker.BG)
        workspace_actions.pack(fill="x", pady=(0, 6))
        self.export_button = tk.Button(workspace_actions, text="EXPORT SAFE JSON", command=self.export_workspace, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold"), state="disabled")
        self.export_button.pack(side="left", ipadx=10, ipady=5)
        self.support_export_button = tk.Button(workspace_actions, text="EXPORT SUPPORT PACK", command=self.export_support_pack, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold"), state="disabled")
        self.support_export_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=5)
        self.recovery_export_button = tk.Button(workspace_actions, text="EXPORT RECOVERY CARD", command=self.export_recovery_card, bg="#252936", fg=locker.TEXT, relief="flat", font=("Segoe UI", 8, "bold"), state="disabled")
        self.recovery_export_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=5)
        self.care_export_button = tk.Button(workspace_actions, text="EXPORT CARE PLAN", command=self.export_care_plan, bg=locker.BLUE, fg=locker.BLACK, relief="flat", font=("Segoe UI", 8, "bold"), state="disabled")
        self.care_export_button.pack(side="left", padx=(8, 0), ipadx=10, ipady=5)
        self.next_action_button = tk.Button(workspace_actions, text="OPEN NEXT ACTION", command=self.open_next_action, bg=locker.GREEN, fg=locker.BLACK, relief="flat", font=("Segoe UI", 8, "bold"), state="disabled")
        self.next_action_button.pack(side="right", ipadx=10, ipady=5)
        progress_actions = tk.Frame(outer, bg=locker.BG)
        progress_actions.pack(fill="x", pady=(0, 6))
        tk.Label(
            progress_actions,
            textvariable=self.progress_var,
            bg=locker.BG,
            fg=locker.MUTED,
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left")
        self.reset_progress_button = tk.Button(
            progress_actions,
            text="RESET LOCAL PROGRESS",
            command=self.reset_local_progress,
            bg="#252936",
            fg=locker.TEXT,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
            state="disabled",
        )
        self.reset_progress_button.pack(side="right", ipadx=10, ipady=5)
        self.mark_done_button = tk.Button(
            progress_actions,
            text="MARK NEXT DONE",
            command=self.mark_next_done,
            bg=locker.BLUE,
            fg=locker.BLACK,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
            state="disabled",
        )
        self.mark_done_button.pack(side="right", padx=(0, 8), ipadx=10, ipady=5)
        workspace_shell = tk.Frame(outer, bg=locker.FIELD)
        workspace_shell.pack(fill="both", expand=True)
        workspace_scroll = tk.Scrollbar(workspace_shell, orient="vertical")
        workspace_scroll.pack(side="right", fill="y")
        self.workspace_box = tk.Text(
            workspace_shell,
            height=12,
            bg=locker.FIELD,
            fg=locker.TEXT,
            relief="flat",
            wrap="word",
            font=("Segoe UI", 9),
            padx=12,
            pady=10,
            state="disabled",
            yscrollcommand=workspace_scroll.set,
        )
        self.workspace_box.pack(side="left", fill="both", expand=True)
        workspace_scroll.configure(command=self.workspace_box.yview)
        tk.Label(outer, textvariable=self.status_var, bg=locker.BG, fg=locker.MUTED, font=("Segoe UI", 9), wraplength=760, justify="left").pack(anchor="w", pady=(10, 0))

    def server_url(self):
        return locker.validated_license_server_url(self.state.get("server_url") or locker.DEFAULT_LICENSE_SERVER)

    def render_details(self):
        details = locker.customer_center_details(self.state, self.settings)
        for key, variable in self.value_vars.items():
            variable.set(details.get(key, "-"))
        if self.workspace:
            snapshot = self.workspace.get("customer_snapshot") or {}
            actions = ((self.workspace.get("action_center") or {}).get("items") or [])
            next_action = next_unfinished_action(self.workspace, self.completed_action_ids)
            completed_count = sum(
                1
                for item in actions
                if isinstance(item, dict) and item.get("id") in self.completed_action_ids
            )
            self.value_vars["readiness"].set(
                f"{snapshot.get('workspace_score', 0)}/100 | "
                f"{snapshot.get('attention_count', 0)} attention item(s) | "
                f"{completed_count}/{len(actions)} locally complete"
            )
            self.value_vars["next_action"].set(next_action.get("title") or "All customer actions complete")
            self.progress_var.set(
                f"LOCAL ACTION PROGRESS | {completed_count} of {len(actions)} completed on this Windows account"
            )
        else:
            self.progress_var.set("LOCAL ACTION PROGRESS | Load the workspace to begin")
        has_proof = bool(self.state.get("license_key") and self.state.get("receipt"))
        if self.verify_button is not None:
            self.verify_button.configure(state="normal" if has_proof and not self.busy else "disabled")
        if self.workspace_button is not None:
            self.workspace_button.configure(state="normal" if self.state.get("license_key") and not self.busy else "disabled")
        export_state = "normal" if self.workspace and not self.busy else "disabled"
        for button in (self.export_button, self.support_export_button, self.recovery_export_button, self.care_export_button):
            if button is not None:
                button.configure(state=export_state)
        if self.next_action_button is not None:
            target = next_unfinished_action(self.workspace, self.completed_action_ids).get("target_path")
            self.next_action_button.configure(state="normal" if target and not self.busy else "disabled")
        if self.mark_done_button is not None:
            item = next_unfinished_action(self.workspace, self.completed_action_ids)
            self.mark_done_button.configure(state="normal" if item.get("id") and not self.busy else "disabled")
        if self.reset_progress_button is not None:
            self.reset_progress_button.configure(
                state="normal" if self.workspace and self.completed_action_ids and not self.busy else "disabled"
            )

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

    def render_workspace(self, payload):
        self.workspace = payload if isinstance(payload, dict) else None
        lines = []
        if self.workspace:
            summary = self.workspace.get("summary") or {}
            plan = summary.get("plan") or {}
            checkup = self.workspace.get("checkup") or {}
            action_center = self.workspace.get("action_center") or {}
            rank_tools = self.workspace.get("rank_tools") or {}
            score = self.workspace.get("workspace_score") or {}
            success_plan = self.workspace.get("success_plan") or {}
            benefit_map = self.workspace.get("benefit_map") or {}
            action_items = action_center.get("items") or []
            valid_action_ids = {
                str(item.get("id"))
                for item in action_items
                if isinstance(item, dict) and ACTION_ID_RE.fullmatch(str(item.get("id") or ""))
            }
            pruned_completed_ids = self.completed_action_ids.intersection(valid_action_ids)
            if pruned_completed_ids != self.completed_action_ids:
                self.completed_action_ids = pruned_completed_ids
                self.progress = save_customer_progress(self.completed_action_ids)
            next_action = next_unfinished_action(self.workspace, self.completed_action_ids)
            readiness_lanes = self.workspace.get("readiness_lanes") or []
            weekly_routine = (self.workspace.get("weekly_routine") or {}).get("items") or []
            entitlement_categories = self.workspace.get("entitlement_categories") or []
            help_items = (self.workspace.get("help_center") or {}).get("items") or []
            privacy_guarantees = self.workspace.get("privacy_guarantees") or []
            journey_stages = (self.workspace.get("journey_map") or {}).get("stages") or []
            seat_planner = self.workspace.get("seat_planner") or {}
            support_readiness = self.workspace.get("support_readiness") or {}
            ninety_day_plan = self.workspace.get("ninety_day_plan") or {}
            change_digest = self.workspace.get("change_digest") or {}
            customer_glossary = self.workspace.get("customer_glossary") or []
            completed_count = len(pruned_completed_ids)
            lines.extend(
                [
                    f"WORKSPACE SCORE | {score.get('score', 0)} / {score.get('maximum', 100)} - {str(score.get('label', 'unknown')).upper()}",
                    f"STATUS | {str(summary.get('status', 'unknown')).upper()}",
                    f"RANK | {plan.get('rank', '?')} - {plan.get('name', 'Unknown')}",
                    f"ATTENTION | {checkup.get('attention_count', 0)} item(s)",
                    f"RANK TOOLS | {rank_tools.get('unlocked_count', 0)} unlocked",
                    f"BENEFITS | {benefit_map.get('unlocked_count', 0)} included",
                    f"LOCAL PROGRESS | {completed_count}/{len(action_items)} completed on this Windows account",
                    "",
                    "NEXT BEST ACTION",
                    (
                        f"{str(next_action.get('when', 'maintain')).upper()} | "
                        f"{next_action.get('title', 'All customer actions complete')}"
                    ),
                    f"   {next_action.get('detail', 'Reset local progress to repeat the plan.')}",
                    "",
                    "CUSTOMER CONTINUITY JOURNEY",
                ]
            )
            for stage in journey_stages:
                lines.append(
                    f"{stage.get('order', '?')}. {stage.get('title', 'Stage')} | "
                    f"{str(stage.get('state', 'review')).upper()} | {stage.get('detail', '')}"
                )
            lines.extend(
                [
                    "",
                    "ANONYMOUS DEVICE-SEAT PLANNER",
                    (
                        f"{seat_planner.get('active', 0)} active | {seat_planner.get('available', 0)} available "
                        f"| {seat_planner.get('maximum', 0)} maximum | "
                        f"{seat_planner.get('usage_percent', 0)}% used"
                    ),
                    f"{seat_planner.get('guidance', '')}",
                    "This view does not identify, reserve, or activate a device.",
                    "",
                    "READINESS LANES",
                ]
            )
            for lane in readiness_lanes:
                lines.append(
                    f"{lane.get('title', 'Readiness')} | {lane.get('awarded', 0)}/{lane.get('maximum', 0)} "
                    f"| {str(lane.get('state', 'review')).upper()} | {lane.get('attention_count', 0)} attention"
                )
            lines.extend(["", "SEVEN-DAY CARE ROUTINE"])
            for item in weekly_routine:
                lines.append(f"{item.get('day', '')} | {item.get('title', '')}")
            lines.extend(["", "INCLUDED BENEFITS BY CATEGORY"])
            for item in entitlement_categories:
                lines.append(f"{item.get('category', 'Other')} | {item.get('count', 0)} included")
            lines.extend(["", "CUSTOMER HELP PATHS"])
            for item in help_items:
                lines.append(f"{item.get('title', 'Help')} | {item.get('first_step', '')}")
            lines.extend(["", "SUPPORT READINESS"])
            lines.append(
                f"{support_readiness.get('ready_count', 0)}/{support_readiness.get('total', 0)} ready "
                f"| {str(support_readiness.get('state', 'review')).upper()}"
            )
            for item in support_readiness.get("items") or []:
                state = "READY" if item.get("ready") else "REVIEW"
                lines.append(f"{state} | {item.get('title', 'Support check')} | {item.get('detail', '')}")
            lines.append(str(support_readiness.get("limitations", "")))
            lines.extend(["", "PRIVACY GUARANTEES"])
            for item in privacy_guarantees:
                lines.append(f"- {item}")
            lines.extend(
                [
                    "",
                    "30-DAY SUCCESS PLAN",
                ]
            )
            for label, key in (("TODAY", "today"), ("THIS WEEK", "this_week"), ("THIS MONTH", "this_month")):
                items = success_plan.get(key) or []
                lines.append(f"{label} | {len(items)} action(s)")
                for item in items:
                    lines.append(f"   - {item.get('title', 'Review item')}")
            lines.extend(["", "90-DAY CONTINUITY PLAN"])
            for phase in ninety_day_plan.get("phases") or []:
                phase_items = phase.get("items") or []
                lines.append(
                    f"{str(phase.get('label', 'Phase')).upper()} | "
                    f"TARGET DAY {phase.get('target_days', '?')} | {len(phase_items)} action(s)"
                )
                for item in phase_items:
                    done = " [DONE]" if item.get("id") in self.completed_action_ids else ""
                    lines.append(f"   - {item.get('title', 'Review item')}{done}")
            lines.extend(
                [
                    "",
                    "CURRENT CHANGE DIGEST",
                    f"API | {change_digest.get('api_version', 'unknown')}",
                    f"INSTALLED DESKTOP | {change_digest.get('installed_version', 'unknown')}",
                    f"LATEST SIGNED DESKTOP | {change_digest.get('latest_signed_version', 'unknown')}",
                    f"DESKTOP STATE | {str(change_digest.get('desktop_state', 'unknown')).upper()}",
                    f"SERVICE | {str(change_digest.get('service_mode', 'unknown')).upper()}",
                    f"LICENSE | {str(change_digest.get('license_state', 'unknown')).upper()}",
                    "This digest reports status only and does not change the customer PC.",
                    "",
                    "CUSTOMER GLOSSARY",
                ]
            )
            for item in customer_glossary:
                lines.append(f"{item.get('term', 'Term')} | {item.get('meaning', '')}")
            lines.extend(["", "PRIORITY ACTION DETAILS"])
            for index, item in enumerate(action_items, 1):
                state = "DONE" if item.get("id") in self.completed_action_ids else "TODO"
                lines.append(
                    f"{index}. [{state}] {str(item.get('when', 'maintain')).upper()} | {item.get('title', 'Review item')}\n"
                    f"   {item.get('detail', '')}"
                )
        text = "\n\n".join(lines) if lines else "Load the full workspace to build a privacy-safe customer action plan."
        self.workspace_box.configure(state="normal")
        self.workspace_box.delete("1.0", "end")
        self.workspace_box.insert("1.0", text)
        self.workspace_box.configure(state="disabled")
        self.render_details()

    def load_workspace(self):
        if self.busy:
            return
        self.settings = locker.load_settings()
        self.state = locker.load_license_state(self.settings)
        if not self.state.get("license_key"):
            self.status_var.set("Activate a license in the main locker's License Center first.")
            self.render_details()
            return
        self.set_busy(True)
        self.status_var.set("Building the full privacy-safe customer workspace...")
        state = locker.normalize_license_state(self.state)

        def worker():
            try:
                workspace = locker.load_customer_workspace_online(state)
                error = ""
            except Exception as exc:
                workspace = None
                error = str(exc)
            self.results.put(("workspace", workspace, None, error))

        threading.Thread(target=worker, name="CustomerWorkspaceLoad", daemon=True).start()
        self.after(75, self.poll_results)

    def export_payload(self, payload, title, initialfile, audit_action):
        if not self.workspace:
            self.status_var.set("Load the full customer workspace before exporting.")
            return
        destination = filedialog.asksaveasfilename(
            parent=self,
            title=title,
            defaultextension=".json",
            initialfile=initialfile,
            filetypes=[("JSON report", "*.json")],
        )
        if not destination:
            return
        try:
            locker.write_text_atomic(destination, json.dumps(payload, indent=2))
            self.status_var.set(f"{title} saved.")
            locker.log_event(audit_action, "local", "ok")
        except Exception as exc:
            locker.log_event(audit_action, "local", "failed")
            messagebox.showerror(f"Could not save {title.lower()}", str(exc), parent=self)

    def export_workspace(self):
        self.export_payload(
            self.workspace,
            "Privacy-safe customer workspace",
            "vaultlink-customer-workspace.json",
            "customer_workspace_export",
        )

    def export_support_pack(self):
        self.export_payload(
            (self.workspace or {}).get("support_pack") or {},
            "Privacy-safe support pack",
            "vaultlink-support-pack.json",
            "customer_support_pack_export",
        )

    def export_recovery_card(self):
        self.export_payload(
            (self.workspace or {}).get("recovery_card") or {},
            "Offline recovery card",
            "vaultlink-offline-recovery-card.json",
            "customer_recovery_card_export",
        )

    def export_care_plan(self):
        self.export_payload(
            customer_care_export(self.workspace, self.completed_action_ids),
            "Privacy-safe customer care plan",
            "vaultlink-customer-care-plan.json",
            "customer_care_plan_export",
        )

    def open_next_action(self):
        target = next_unfinished_action(self.workspace, self.completed_action_ids).get("target_path")
        if not isinstance(target, str) or not target.startswith("/") or target.startswith("//"):
            self.status_var.set("All customer actions are complete, or the workspace needs to be loaded.")
            return
        self.open_customer_page(target)

    def mark_next_done(self):
        item = next_unfinished_action(self.workspace, self.completed_action_ids)
        action_id = str(item.get("id") or "")
        if not ACTION_ID_RE.fullmatch(action_id):
            self.status_var.set("All customer actions are already complete.")
            return
        self.completed_action_ids.add(action_id)
        try:
            self.progress = save_customer_progress(self.completed_action_ids)
        except Exception as exc:
            locker.log_event("customer_progress_update", "local", "failed")
            messagebox.showerror("Could not save progress", str(exc), parent=self)
            return
        self.render_workspace(self.workspace)
        self.status_var.set(f"Marked '{item.get('title', 'customer action')}' complete on this Windows account.")
        locker.log_event("customer_progress_update", "local", "ok")

    def reset_local_progress(self):
        if not self.completed_action_ids:
            self.status_var.set("There is no local customer progress to reset.")
            return
        if not messagebox.askyesno(
            "Reset local progress?",
            "This clears completed action IDs stored on this Windows account. It does not change files, keys, or the license.",
            parent=self,
        ):
            return
        try:
            self.completed_action_ids.clear()
            self.progress = save_customer_progress(self.completed_action_ids)
        except Exception as exc:
            locker.log_event("customer_progress_reset", "local", "failed")
            messagebox.showerror("Could not reset progress", str(exc), parent=self)
            return
        self.render_workspace(self.workspace)
        self.status_var.set("Local customer action progress was reset.")
        locker.log_event("customer_progress_reset", "local", "ok")

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
        if mode == "workspace":
            self.render_workspace(first)
            self.status_var.set("Full customer workspace loaded from the API.")
            locker.log_event("customer_workspace_load", "api", "ok")
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

    def open_support_redactor(self):
        try:
            locker.launch_companion_script("support_redactor.py")
            self.status_var.set("Opened the local Support Redactor.")
        except Exception as exc:
            messagebox.showerror("Could not open Support Redactor", str(exc), parent=self)

    def open_download_verification_center(self):
        try:
            locker.launch_companion_script("download_verification_center.py")
            self.status_var.set("Opened the local Download Verification Center.")
        except Exception as exc:
            messagebox.showerror("Could not open Download Verification Center", str(exc), parent=self)


if __name__ == "__main__":
    CustomerHub().mainloop()
