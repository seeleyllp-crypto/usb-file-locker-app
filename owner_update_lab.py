import argparse
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

import build_signed_update as release_builder
import usb_file_locker as locker
import vaultlink_updater


BG = "#0f1116"
PANEL = "#171a22"
FIELD = "#0b0d12"
TEXT = "#f3f5f7"
MUTED = "#9ca4b3"
GREEN = "#28df73"
YELLOW = "#ffd166"
RED = "#ff5d6c"
BLUE = "#58b7e8"

SOURCE_DIR = Path(__file__).resolve().parent
LAB_DIR = locker.APP_DIR / "owner_update_lab"
CANDIDATE_DIR = LAB_DIR / "candidate"
REPORT_FILE = LAB_DIR / "verified_candidate.json"
PUBLISH_REPORT_FILE = LAB_DIR / "last_publish.json"
MAX_LIVE_PACKAGE_BYTES = 250 * 1024 * 1024
PINNED_APP_REMOTE = "https://github.com/seeleyllp-crypto/usb-file-locker-app.git"
PINNED_API_REMOTE = "https://github.com/seeleyllp-crypto/usb-file-locker-api.git"

DEFAULT_NOTES = [
    "Owner-only Update Lab separates private candidate testing from public releases.",
    "Publishing requires the registered removable owner USB, Windows signing key, and GitHub write access.",
    "The exact signed package that passed tests and Defender is copied into the API release repo.",
    "Keys, licenses, settings, vault data, audit logs, and locked files remain untouched.",
]


def command_creation_flags():
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def run_command(command, cwd, label, timeout=300):
    result = subprocess.run(
        [str(part) for part in command],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=command_creation_flags(),
    )
    output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    if result.returncode != 0:
        detail = output[-2500:] if output else f"exit code {result.returncode}"
        raise ValueError(f"{label} failed.\n\n{detail}")
    return output


def git_executable():
    candidates = [
        shutil.which("git"),
        r"C:\Program Files\Git\cmd\git.exe",
        r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\cmd\git.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    raise ValueError("Git was not found. Install Git or Visual Studio Git before publishing.")


def defender_executable():
    platform_root = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "Microsoft" / "Windows Defender" / "Platform"
    candidates = []
    if platform_root.is_dir():
        candidates.extend(sorted(platform_root.glob("*/MpCmdRun.exe"), reverse=True))
    candidates.append(Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise ValueError("Microsoft Defender command-line scanner was not found.")


def defender_scan(path):
    output = run_command(
        [defender_executable(), "-Scan", "-ScanType", "3", "-File", Path(path), "-DisableRemediation"],
        Path(path).parent,
        "Microsoft Defender scan",
        timeout=600,
    )
    if "no threats" not in output.lower():
        raise ValueError("Microsoft Defender did not return a clear no-threat result.")
    return "no threats"


def default_repo_path(folder_name):
    if SOURCE_DIR.name.lower() == folder_name.lower() and (SOURCE_DIR / ".git").is_dir():
        return SOURCE_DIR
    home = Path.home()
    candidates = [
        home / "OneDrive" / "Desktop" / folder_name,
        home / "Desktop" / folder_name,
        SOURCE_DIR.parent / folder_name,
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0]


def validate_repo(path, required_file):
    repo = Path(path).expanduser().resolve()
    if not repo.is_dir() or not (repo / required_file).is_file():
        raise ValueError(f"The selected folder does not contain {required_file}.")
    return repo


def source_fingerprint(source_dir):
    source_dir = Path(source_dir)
    digest = hashlib.sha256()
    for name in release_builder.PACKAGE_FILES:
        path = source_dir / name
        if not path.is_file():
            raise ValueError(f"Release source file is missing: {name}")
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    return digest.hexdigest()


def normalized_notes(value):
    if isinstance(value, str):
        raw_items = value.splitlines()
    else:
        raw_items = value or []
    notes = []
    for raw in raw_items:
        text = str(raw).strip()
        if text.startswith("-"):
            text = text[1:].strip()
        if text:
            notes.append(text)
    if not notes:
        notes = list(DEFAULT_NOTES)
    if len(notes) > 12:
        raise ValueError("Use no more than 12 release-note lines.")
    if any(len(note) > 240 for note in notes):
        raise ValueError("Each release-note line must be 240 characters or fewer.")
    return notes


def package_sensitive_entries(package_path):
    blocked_exact = {"settings.json", "audit_log.jsonl", "locker_log.jsonl", "license_state.json"}
    with zipfile.ZipFile(package_path) as archive:
        names = archive.namelist()
    return [
        name
        for name in names
        if Path(name).name.lower() in blocked_exact or name.lower().endswith((".dpapi", ".locked", ".lookeed"))
    ]


def verify_candidate_files(manifest_path, package_path):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    validated = vaultlink_updater.validate_manifest(manifest, package_path)
    blocked = package_sensitive_entries(package_path)
    if blocked:
        raise ValueError("The candidate package contains private app-data files.")
    return validated


def safe_reset_candidate_dir():
    LAB_DIR.mkdir(parents=True, exist_ok=True)
    resolved_lab = LAB_DIR.resolve()
    resolved_candidate = CANDIDATE_DIR.resolve()
    if resolved_candidate.parent != resolved_lab:
        raise ValueError("Candidate staging path is outside the owner Update Lab folder.")
    if resolved_candidate.exists():
        shutil.rmtree(resolved_candidate)
    resolved_candidate.mkdir(parents=True, exist_ok=True)
    return resolved_candidate


def test_count_from_output(output):
    match = re.search(r"Ran\s+(\d+)\s+tests?", output or "")
    return int(match.group(1)) if match else 0


def find_default_owner_key():
    settings = locker.load_settings()
    policy = locker.load_owner_policy(settings)
    if not policy:
        return ""
    for path in locker.recent_key_paths_from_settings(settings):
        try:
            release_builder.authorize_owner_release(path)
            return str(path)
        except Exception:
            continue
    for path in locker.bundled_key_candidates():
        try:
            release_builder.authorize_owner_release(path)
            return str(path)
        except Exception:
            continue
    return ""


def build_and_test_candidate(app_repo, api_repo, owner_key_path, minimum_supported, notes):
    app_repo = validate_repo(app_repo, "usb_file_locker.py")
    api_repo = validate_repo(api_repo, "main.py")
    notes = normalized_notes(notes)
    release_builder.authorize_owner_release(owner_key_path)
    locker.update_version_tuple(minimum_supported)
    require_clean_main_repo(app_repo, "App repository")
    require_clean_main_repo(api_repo, "API repository")
    app_remote = require_pinned_origin(app_repo, PINNED_APP_REMOTE, "App repository")
    api_remote = require_pinned_origin(api_repo, PINNED_API_REMOTE, "API repository")
    published_manifest_path = api_repo / "updates" / "windows-manifest.json"
    if published_manifest_path.is_file():
        published_manifest = json.loads(published_manifest_path.read_text(encoding="utf-8"))
        published_version = str(published_manifest.get("version", ""))
        if published_version and not locker.compare_update_versions(locker.DESKTOP_APP_VERSION, published_version):
            raise ValueError(
                f"Candidate version {locker.DESKTOP_APP_VERSION} must be newer than published version {published_version}."
            )
    app_head = committed_head(app_repo, "App repository")
    api_head = committed_head(api_repo, "API repository")

    python_files = [str(app_repo / name) for name in release_builder.PACKAGE_FILES if name.endswith(".py")]
    run_command([sys.executable, "-m", "py_compile", *python_files], app_repo, "Python compile check")
    desktop_test_output = run_command(
        [sys.executable, "-m", "unittest", "-q", "test_desktop_helpers.py"],
        app_repo,
        "Desktop test suite",
        timeout=600,
    )
    api_test_output = run_command(
        [sys.executable, "-m", "unittest", "-q"],
        api_repo,
        "API test suite",
        timeout=600,
    )

    candidate_dir = safe_reset_candidate_dir()
    result = release_builder.build_signed_release(
        app_repo,
        candidate_dir,
        minimum_supported,
        notes,
        owner_key_path,
    )
    manifest_path = Path(result["manifest"])
    package_path = Path(result["package"])
    validated = verify_candidate_files(manifest_path, package_path)
    defender_scan(app_repo)
    defender_scan(api_repo)
    defender_scan(package_path)

    report = {
        "schema_version": 1,
        "status": "verified",
        "tested_at_utc": locker.utc_now_text(),
        "version": result["version"],
        "minimum_supported_version": minimum_supported,
        "source_fingerprint": source_fingerprint(app_repo),
        "sha256": result["sha256"],
        "size_bytes": result["size_bytes"],
        "package_filename": Path(result["package"]).name,
        "manifest_filename": Path(result["manifest"]).name,
        "notes": notes,
        "test_count": test_count_from_output(desktop_test_output) + test_count_from_output(api_test_output),
        "desktop_test_count": test_count_from_output(desktop_test_output),
        "api_test_count": test_count_from_output(api_test_output),
        "app_head": app_head,
        "api_head": api_head,
        "app_remote": app_remote,
        "api_remote": api_remote,
        "compile": "passed",
        "signature": "verified",
        "defender_source": "no threats",
        "defender_api": "no threats",
        "defender_package": "no threats",
        "preserves_local_app_data": bool(validated.get("preserves_local_app_data")),
    }
    locker.write_text_atomic(REPORT_FILE, json.dumps(report, indent=2))
    return report


def load_candidate_report():
    if not REPORT_FILE.is_file():
        return None
    try:
        report = json.loads(REPORT_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None
    return report if isinstance(report, dict) else None


def candidate_is_current(report, app_repo, api_repo, minimum_supported, notes):
    if not isinstance(report, dict) or report.get("status") != "verified":
        return False, "No verified candidate is ready."
    checks = {
        "version": locker.DESKTOP_APP_VERSION,
        "minimum_supported_version": minimum_supported,
        "source_fingerprint": source_fingerprint(app_repo),
        "notes": normalized_notes(notes),
        "app_head": committed_head(app_repo, "App repository"),
        "api_head": committed_head(api_repo, "API repository"),
    }
    for field, expected in checks.items():
        if report.get(field) != expected:
            return False, f"The verified candidate is stale because {field.replace('_', ' ')} changed."
    manifest_path = CANDIDATE_DIR / str(report.get("manifest_filename", ""))
    package_path = CANDIDATE_DIR / str(report.get("package_filename", ""))
    if not manifest_path.is_file() or not package_path.is_file():
        return False, "The verified candidate files are missing."
    if release_builder.package_sha256(package_path) != report.get("sha256"):
        return False, "The candidate ZIP changed after testing."
    verify_candidate_files(manifest_path, package_path)
    return True, "Verified candidate matches the current source."


def git_output(repo, *args, label="Git command", timeout=300):
    return run_command([git_executable(), *args], repo, label, timeout=timeout)


def normalized_git_remote(value):
    return str(value or "").strip().rstrip("/").lower()


def require_pinned_origin(repo, expected, label):
    actual = git_output(repo, "remote", "get-url", "origin", label=f"{label} origin check").strip()
    if normalized_git_remote(actual) != normalized_git_remote(expected):
        raise ValueError(f"{label} origin is not the pinned VaultLink GitHub repository.")
    return actual


def require_clean_main_repo(repo, label):
    if git_output(repo, "status", "--porcelain", label=f"{label} status check").strip():
        raise ValueError(f"{label} has uncommitted or untracked files. Review and commit them before publishing.")
    branch = git_output(repo, "branch", "--show-current", label=f"{label} branch check").strip()
    if branch != "main":
        raise ValueError(f"{label} must be on the main branch before publishing.")


def committed_head(repo, label):
    return git_output(repo, "rev-parse", "HEAD", label=f"{label} commit check").strip()


def atomic_copy(source, destination):
    source = Path(source)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / f".{destination.name}.owner-update.tmp"
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def live_release_payload(server_url):
    url = locker.validated_license_server_url(server_url) + "/api/v1/updates/windows"
    request = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            raw = response.read(1024 * 1024)
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        raise ValueError(f"Could not verify the live update service.\n\n{exc}") from exc
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("update"), dict):
        raise ValueError("The live update service returned an unexpected response.")
    return payload


def verify_live_package(server_url, update):
    url = locker.validated_license_server_url(server_url) + str(update["download_path"])
    request = urllib.request.Request(url, headers={"Accept": "application/zip"}, method="GET")
    digest = hashlib.sha256()
    size = 0
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_LIVE_PACKAGE_BYTES:
                    raise ValueError("The live update package is larger than the owner verifier allows.")
                digest.update(chunk)
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        raise ValueError(f"Could not download the live update for verification.\n\n{exc}") from exc
    if size != int(update["size_bytes"]) or digest.hexdigest() != str(update["sha256"]).lower():
        raise ValueError("The live update download did not match its signed manifest.")
    return size, digest.hexdigest()


def publish_verified_candidate(app_repo, api_repo, owner_key_path, minimum_supported, notes, server_url):
    app_repo = validate_repo(app_repo, "usb_file_locker.py")
    api_repo = validate_repo(api_repo, "main.py")
    report = build_and_test_candidate(
        app_repo,
        api_repo,
        owner_key_path,
        minimum_supported,
        notes,
    )
    current, message = candidate_is_current(report, app_repo, api_repo, minimum_supported, notes)
    if not current:
        raise ValueError(message)
    require_clean_main_repo(app_repo, "App repository")
    require_clean_main_repo(api_repo, "API repository")
    require_pinned_origin(app_repo, PINNED_APP_REMOTE, "App repository")
    require_pinned_origin(api_repo, PINNED_API_REMOTE, "API repository")

    git_output(app_repo, "push", "origin", "main", label="App source push", timeout=600)

    source_manifest = CANDIDATE_DIR / report["manifest_filename"]
    source_package = CANDIDATE_DIR / report["package_filename"]
    updates_dir = api_repo / "updates"
    target_manifest = updates_dir / "windows-manifest.json"
    target_package = updates_dir / report["package_filename"]
    atomic_copy(source_manifest, target_manifest)
    atomic_copy(source_package, target_package)
    verify_candidate_files(target_manifest, target_package)
    defender_scan(target_package)
    defender_scan(updates_dir)

    git_output(
        api_repo,
        "add",
        "--",
        "updates/windows-manifest.json",
        f"updates/{target_package.name}",
        label="Stage signed update",
    )
    staged = subprocess.run(
        [str(git_executable()), "diff", "--cached", "--quiet"],
        cwd=str(api_repo),
        creationflags=command_creation_flags(),
    )
    if staged.returncode == 1:
        git_output(api_repo, "commit", "-m", f"Publish desktop {report['version']}", label="Commit signed update")
    elif staged.returncode != 0:
        raise ValueError("Could not inspect the staged update files.")
    git_output(api_repo, "push", "origin", "main", label="Publish signed update", timeout=600)

    deadline = time.time() + 360
    live = None
    while time.time() < deadline:
        try:
            payload = live_release_payload(server_url)
            update = payload["update"]
            if update.get("version") == report["version"] and update.get("sha256") == report["sha256"]:
                live = update
                break
        except Exception:
            pass
        time.sleep(8)
    if live is None:
        raise ValueError("GitHub push succeeded, but the live update service did not publish the candidate within six minutes.")
    live_size, live_hash = verify_live_package(server_url, live)
    publish_report = {
        "schema_version": 1,
        "status": "published",
        "published_at_utc": locker.utc_now_text(),
        "version": report["version"],
        "sha256": live_hash,
        "size_bytes": live_size,
        "source_fingerprint": report["source_fingerprint"],
        "defender": "no threats",
        "live_verified": True,
    }
    locker.write_text_atomic(PUBLISH_REPORT_FILE, json.dumps(publish_report, indent=2))
    return publish_report


class OwnerUpdateLab(tk.Tk):
    def __init__(self, owner_key_path=""):
        super().__init__()
        self.title("VaultLink Owner Update Lab")
        self.geometry("900x760")
        self.minsize(820, 680)
        self.configure(bg=BG)
        self.owner_key_var = tk.StringVar(value=owner_key_path or find_default_owner_key())
        self.app_repo_var = tk.StringVar(value=str(default_repo_path("USBFileLockerApp")))
        self.api_repo_var = tk.StringVar(value=str(default_repo_path("USBFileLockerAPI-Repo")))
        self.minimum_var = tk.StringVar(value="2026.07.12.9")
        self.version_var = tk.StringVar(value=f"Candidate version: {locker.DESKTOP_APP_VERSION}")
        self.candidate_var = tk.StringVar(value="No verified candidate loaded.")
        self.status_var = tk.StringVar(value="Owner authorization has not been checked yet.")
        self.results = queue.Queue()
        self.busy = False
        self.build_ui()
        self.refresh_candidate_state()

    def build_ui(self):
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True, padx=28, pady=24)
        tk.Label(outer, text="Owner Update Lab", bg=BG, fg=TEXT, font=("Segoe UI", 25, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="PRIVATE TEST CANDIDATE  |  OWNER USB  |  SIGNED RELEASE  |  DEFENDER VERIFIED",
            bg=BG,
            fg=GREEN,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", pady=(4, 14))
        tk.Label(outer, textvariable=self.version_var, bg=BG, fg=YELLOW, font=("Segoe UI", 11, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="Testing stays local. Publishing requires the registered owner USB, this Windows account's signing key, and GitHub write access.",
            bg=BG,
            fg=MUTED,
            wraplength=820,
            justify="left",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(4, 14))

        panel = tk.Frame(outer, bg=PANEL)
        panel.pack(fill="both", expand=True)
        form = tk.Frame(panel, bg=PANEL)
        form.pack(fill="x", padx=18, pady=(18, 10))
        form.columnconfigure(1, weight=1)
        self.add_path_row(form, 0, "OWNER USB KEY", self.owner_key_var, self.choose_owner_key, file_mode=True)
        self.add_path_row(form, 1, "APP SOURCE REPO", self.app_repo_var, lambda: self.choose_folder(self.app_repo_var))
        self.add_path_row(form, 2, "API RELEASE REPO", self.api_repo_var, lambda: self.choose_folder(self.api_repo_var))
        tk.Label(form, text="MINIMUM SUPPORTED", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).grid(row=3, column=0, sticky="w", pady=(8, 0))
        tk.Entry(form, textvariable=self.minimum_var, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 10)).grid(row=3, column=1, sticky="ew", padx=(12, 10), pady=(8, 0), ipady=7)

        tk.Label(panel, text="SIGNED RELEASE NOTES", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=18, pady=(2, 4))
        self.notes = tk.Text(panel, height=5, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 9), wrap="word")
        self.notes.pack(fill="x", padx=18)
        self.notes.insert("1.0", "\n".join(f"- {note}" for note in DEFAULT_NOTES))
        self.notes.bind("<KeyRelease>", lambda _event: self.refresh_candidate_state())

        state = tk.Frame(panel, bg="#11141b")
        state.pack(fill="x", padx=18, pady=(12, 0))
        tk.Label(state, text="CANDIDATE GATE", bg="#11141b", fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=12, pady=(10, 2))
        tk.Label(state, textvariable=self.candidate_var, bg="#11141b", fg=YELLOW, wraplength=780, justify="left", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=12, pady=(0, 10))

        actions = tk.Frame(panel, bg=PANEL)
        actions.pack(fill="x", padx=18, pady=(12, 8))
        self.test_button = tk.Button(actions, text="TEST CANDIDATE", command=self.start_test, bg=YELLOW, fg="#090b0f", relief="flat", font=("Segoe UI", 10, "bold"))
        self.test_button.pack(side="left", ipadx=16, ipady=9)
        self.publish_button = tk.Button(actions, text="PUBLISH VERIFIED UPDATE", command=self.start_publish, bg=GREEN, fg="#090b0f", relief="flat", font=("Segoe UI", 10, "bold"), state="disabled")
        self.publish_button.pack(side="left", padx=(10, 0), ipadx=16, ipady=9)
        tk.Button(actions, text="REFRESH", command=self.refresh_candidate_state, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 9, "bold")).pack(side="right", ipadx=12, ipady=8)

        secondary = tk.Frame(panel, bg=PANEL)
        secondary.pack(fill="x", padx=18, pady=(0, 8))
        tk.Button(secondary, text="OPEN CANDIDATE FOLDER", command=self.open_candidate_folder, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", ipadx=10, ipady=6)
        tk.Button(secondary, text="OPEN LIVE UPDATE CENTER", command=self.open_live_center, bg=BLUE, fg="#090b0f", relief="flat", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(10, 0), ipadx=10, ipady=6)

        self.log = scrolledtext.ScrolledText(panel, height=9, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Consolas", 9), state="disabled", wrap="word")
        self.log.pack(fill="both", expand=True, padx=18, pady=(0, 8))
        tk.Label(panel, textvariable=self.status_var, bg=PANEL, fg=MUTED, wraplength=800, justify="left", font=("Segoe UI", 9)).pack(anchor="w", padx=18, pady=(0, 14))

    def add_path_row(self, parent, row, label, variable, command, file_mode=False):
        tk.Label(parent, text=label, bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).grid(row=row, column=0, sticky="w", pady=(0 if row == 0 else 8, 0))
        entry = tk.Entry(parent, textvariable=variable, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 9))
        entry.grid(row=row, column=1, sticky="ew", padx=(12, 10), pady=(0 if row == 0 else 8, 0), ipady=7)
        entry.bind("<KeyRelease>", lambda _event: self.refresh_candidate_state())
        tk.Button(parent, text="BROWSE", command=command, bg="#252936", fg=TEXT, relief="flat", font=("Segoe UI", 8, "bold")).grid(row=row, column=2, pady=(0 if row == 0 else 8, 0), ipadx=9, ipady=6)

    def choose_owner_key(self):
        path = filedialog.askopenfilename(title="Choose registered owner USB key", filetypes=[("VaultLink master key", "*.key"), ("All files", "*.*")])
        if path:
            self.owner_key_var.set(path)
            self.refresh_candidate_state()

    def choose_folder(self, variable):
        path = filedialog.askdirectory(title="Choose repository folder", initialdir=variable.get() or str(Path.home()))
        if path:
            variable.set(path)
            self.refresh_candidate_state()

    def notes_value(self):
        return self.notes.get("1.0", "end")

    def append_log(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", str(text).rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def refresh_candidate_state(self):
        try:
            release_builder.authorize_owner_release(self.owner_key_var.get())
            owner_text = "Owner USB verified."
        except Exception as exc:
            owner_text = f"Owner authorization blocked: {exc}"
        report = load_candidate_report()
        try:
            current, candidate_text = candidate_is_current(
                report,
                validate_repo(self.app_repo_var.get(), "usb_file_locker.py"),
                validate_repo(self.api_repo_var.get(), "main.py"),
                self.minimum_var.get().strip(),
                self.notes_value(),
            )
        except Exception as exc:
            current, candidate_text = False, str(exc)
        self.publish_button.configure(state="normal" if current and not self.busy and owner_text == "Owner USB verified." else "disabled")
        self.candidate_var.set(f"{owner_text}  {candidate_text}")

    def set_busy(self, enabled, status):
        self.busy = bool(enabled)
        self.test_button.configure(state="disabled" if enabled else "normal")
        self.publish_button.configure(state="disabled")
        self.status_var.set(status)
        if not enabled:
            self.refresh_candidate_state()

    def run_background(self, action, worker):
        if self.busy:
            return
        self.set_busy(True, f"{action} is running...")
        self.append_log(f"[{time.strftime('%H:%M:%S')}] {action} started.")

        def run():
            try:
                result = worker()
                self.results.put((action, result, ""))
            except Exception as exc:
                self.results.put((action, None, str(exc)))

        threading.Thread(target=run, name=f"OwnerUpdateLab{action.replace(' ', '')}", daemon=True).start()
        self.after(100, self.poll_results)

    def poll_results(self):
        try:
            action, result, error = self.results.get_nowait()
        except queue.Empty:
            if self.busy:
                self.after(100, self.poll_results)
            return
        if error:
            self.append_log(f"{action} FAILED: {error}")
            self.set_busy(False, f"{action} failed. Nothing was published." if action == "Candidate test" else f"{action} failed.")
            messagebox.showerror(f"{action} failed", error, parent=self)
            return
        if action == "Candidate test":
            self.append_log(f"Candidate {result['version']} passed {result['test_count']} tests, signature validation, and Defender scans.")
            self.set_busy(False, "Candidate verified locally. The Publish button is now available.")
            messagebox.showinfo("Candidate verified", "The signed candidate passed compile checks, tests, package validation, and Microsoft Defender. It is still private.", parent=self)
        else:
            self.append_log(f"Published {result['version']} and verified the live download SHA-256.")
            self.set_busy(False, "Update published and live download verified.")
            messagebox.showinfo("Update published", f"VaultLink {result['version']} is live and its downloaded SHA-256 matches.", parent=self)

    def start_test(self):
        self.run_background(
            "Candidate test",
            lambda: build_and_test_candidate(
                self.app_repo_var.get(),
                self.api_repo_var.get(),
                self.owner_key_var.get(),
                self.minimum_var.get().strip(),
                self.notes_value(),
            ),
        )

    def start_publish(self):
        report = load_candidate_report() or {}
        version = report.get("version") or locker.DESKTOP_APP_VERSION
        if not messagebox.askyesno(
            "Publish verified update",
            f"Publish VaultLink {version} to customers?\n\n"
            "The app and API repositories must be clean. The exact tested ZIP and signed manifest will be pushed to GitHub, then verified on the live service.",
            parent=self,
        ):
            return
        settings = locker.load_settings()
        state = locker.load_license_state(settings)
        server_url = state.get("server_url") or locker.DEFAULT_LICENSE_SERVER
        self.run_background(
            "Verified publish",
            lambda: publish_verified_candidate(
                self.app_repo_var.get(),
                self.api_repo_var.get(),
                self.owner_key_var.get(),
                self.minimum_var.get().strip(),
                self.notes_value(),
                server_url,
            ),
        )

    def open_candidate_folder(self):
        CANDIDATE_DIR.mkdir(parents=True, exist_ok=True)
        os.startfile(CANDIDATE_DIR)

    def open_live_center(self):
        settings = locker.load_settings()
        state = locker.load_license_state(settings)
        server_url = locker.validated_license_server_url(state.get("server_url") or locker.DEFAULT_LICENSE_SERVER)
        os.startfile(server_url + "/update")


def main():
    parser = argparse.ArgumentParser(description="VaultLink owner-only update test and publish center.")
    parser.add_argument("--owner-key", default="")
    args = parser.parse_args()
    OwnerUpdateLab(args.owner_key).mainloop()


if __name__ == "__main__":
    main()
