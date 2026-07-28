import argparse
import base64
import hashlib
import io
import json
import lzma
import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import usb_file_locker as locker
import vaultlink_updater


UPDATE_KEY_ENTROPY = b"VaultLinkUpdateSigningKeyV1"
COMPACT_PAYLOAD_FILENAME = "vaultlink_payload.tar.xz"
PACKAGE_FILES = [
    "Ensure Dependencies.cmd",
    "README.md",
    "README.txt",
    "Run Audit Log Viewer.bat",
    "Run Backup Verification Center.bat",
    "Run Customer Hub.bat",
    "Run Diagnostics Center.bat",
    "Run Download Verification Center.bat",
    "Run Incident Response Center.bat",
    "Run Global Breach Guard.bat",
    "Run Key Inspector.bat",
    "Run License Issuer.bat",
    "Run Local Data Control Center.bat",
    "Run Local Control Center.bat",
    "Run Locked File Browser.bat",
    "Run PERM UNLOCK Workbench.bat",
    "Run Personal Vault Pad.bat",
    "Run Privacy Safety Hub.bat",
    "Run Quick Lock Note.bat",
    "Run Recovery Drill Center.bat",
    "Run Recovery Kit Builder.bat",
    "Run Security Maintenance Center.bat",
    "Run Storage & Retention Center.bat",
    "Run Support Redactor.bat",
    "Run Text Log Processor.bat",
    "Run Trust & Recovery Center.bat",
    "Run USB File Locker.bat",
    "Run Vault Health Center.bat",
    "audit_log_viewer.py",
    "backup_verification_center.py",
    "customer_hub.py",
    "diagnostics_center.py",
    "download_verification_center.py",
    "incident_response_center.py",
    "global_breach_guard.py",
    "key_inspector.py",
    "license_issuer.py",
    "local_data_control_center.py",
    "local_control_center.py",
    "locked_file_browser.py",
    "perm_unlock_workbench.py",
    "personal_vault_pad.py",
    "privacy_safety_hub.py",
    "quick_lock_note.py",
    "recovery_drill_center.py",
    "recovery_kit_builder.py",
    "requirements.txt",
    "security_maintenance_center.py",
    "settings.example.json",
    "storage_retention_center.py",
    "support_redactor.py",
    "text_log_processor.py",
    "trust_recovery_center.py",
    "usb_file_locker.py",
    "vault_health_center.py",
    "vaultlink_updater.py",
]

COMPACT_BOOTSTRAP_TEMPLATE = r'''import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path


DESKTOP_APP_VERSION = __VERSION__
PAYLOAD_FILENAME = "vaultlink_payload.tar.xz"
PAYLOAD_SHA256 = __PAYLOAD_SHA256__
EXPECTED_FILES = tuple(__EXPECTED_FILES__)
MAX_PAYLOAD_BYTES = 10 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_EXTRACTED_BYTES = 100 * 1024 * 1024


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def write_status(app_data, ok, message, backup=""):
    app_data.mkdir(parents=True, exist_ok=True)
    payload = {
        "ok": bool(ok),
        "version": DESKTOP_APP_VERSION,
        "message": str(message),
        "backup_dir": str(backup),
        "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    target = app_data / "update-status.json"
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(temporary, target)


def show_error(message):
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("VaultLink update failed", str(message), parent=root)
        root.destroy()
    except Exception:
        pass


def prior_desktop_backup(app_data):
    status_path = app_data / "update-status.json"
    try:
        status = json.loads(status_path.read_text(encoding="utf-8"))
        backup = Path(str(status.get("backup_dir", ""))).resolve()
        backup.relative_to((app_data / "update_backups").resolve())
        candidate = backup / "usb_file_locker.py"
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    except Exception:
        pass
    return None


def restore_prior_desktop(app_data, target):
    prior = prior_desktop_backup(app_data)
    if prior is None:
        return None
    destination = target / "usb_file_locker.py"
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.restore.tmp")
    try:
        shutil.copy2(prior, temporary)
        os.replace(temporary, destination)
        return prior.parent
    finally:
        temporary.unlink(missing_ok=True)


def extract_payload(payload_path, staging):
    if (
        not payload_path.is_file()
        or payload_path.is_symlink()
        or not 0 < payload_path.stat().st_size <= MAX_PAYLOAD_BYTES
    ):
        raise ValueError("The compact update payload is missing or outside the safety limit.")
    if file_sha256(payload_path) != PAYLOAD_SHA256:
        raise ValueError("The compact update payload SHA-256 did not match the signed bootstrap.")

    expected = set(EXPECTED_FILES)
    found = set()
    total_size = 0
    with tarfile.open(payload_path, "r:xz") as archive:
        members = archive.getmembers()
        if len(members) != len(EXPECTED_FILES):
            raise ValueError("The compact update payload file count is invalid.")
        for member in members:
            name = str(member.name)
            if (
                not member.isfile()
                or name not in expected
                or name in found
                or Path(name).name != name
                or "\\" in name
                or "\0" in name
                or not 0 <= member.size <= MAX_FILE_BYTES
            ):
                raise ValueError("The compact update payload contains an unexpected file.")
            total_size += member.size
            if total_size > MAX_EXTRACTED_BYTES:
                raise ValueError("The compact update payload expands beyond the safety limit.")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("A compact update file could not be read.")
            destination = staging / name
            with destination.open("xb") as output:
                remaining = member.size
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("A compact update file ended early.")
                    output.write(chunk)
                    remaining -= len(chunk)
                if source.read(1):
                    raise ValueError("A compact update file exceeded its declared size.")
            found.add(name)
    if found != expected:
        raise ValueError("The compact update payload is incomplete.")


def apply_payload(staging, target, app_data):
    if target.parent == target or (target / ".git").exists():
        raise ValueError("Refusing to install a compact update in this application folder.")
    backup = (
        app_data
        / "update_backups"
        / f"before-{DESKTOP_APP_VERSION}-{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}-compact"
    )
    backup.mkdir(parents=True, exist_ok=False)
    old_main = prior_desktop_backup(app_data)
    existed = {}
    for name in EXPECTED_FILES:
        destination = target / name
        if destination.exists() and (not destination.is_file() or destination.is_symlink()):
            raise ValueError(f"Cannot safely replace {name}.")
        existed[name] = destination.is_file()
        if existed[name]:
            source = old_main if name == "usb_file_locker.py" and old_main else destination
            shutil.copy2(source, backup / name)

    applied = []
    install_order = [name for name in EXPECTED_FILES if name != "usb_file_locker.py"]
    install_order.append("usb_file_locker.py")
    try:
        for name in install_order:
            destination = target / name
            temporary = destination.with_name(f".{destination.name}.{os.getpid()}.compact.tmp")
            try:
                shutil.copy2(staging / name, temporary)
                os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)
            applied.append(name)
    except Exception:
        for name in reversed(applied):
            destination = target / name
            saved = backup / name
            try:
                if existed[name] and saved.is_file():
                    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.rollback.tmp")
                    shutil.copy2(saved, temporary)
                    os.replace(temporary, destination)
                elif not existed[name]:
                    destination.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    return backup, len(applied)


def launch_desktop(target, completed=False):
    if os.environ.get("VAULTLINK_COMPACT_BOOTSTRAP_NO_RELAUNCH") == "1":
        return
    environment = dict(os.environ)
    if completed:
        environment["VAULTLINK_UPDATE_COMPLETED"] = DESKTOP_APP_VERSION
    subprocess.Popen(
        [sys.executable, str(target / "usb_file_locker.py")],
        cwd=str(target),
        env=environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def main():
    script_path = Path(__file__)
    if script_path.is_symlink():
        show_error("The update bootstrap cannot run from a linked file.")
        return 1
    target = script_path.resolve().parent
    app_data = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "USBFileLocker"
    payload_path = target / PAYLOAD_FILENAME
    staging = Path(tempfile.mkdtemp(prefix="vaultlink-compact-update-"))
    try:
        extract_payload(payload_path, staging)
        backup, file_count = apply_payload(staging, target, app_data)
    except Exception as exc:
        payload_path.unlink(missing_ok=True)
        restored_backup = restore_prior_desktop(app_data, target)
        try:
            write_status(app_data, False, str(exc), restored_backup or "")
        except Exception:
            pass
        show_error(str(exc))
        if restored_backup:
            try:
                launch_desktop(target, completed=False)
            except Exception:
                pass
        return 1
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    payload_path.unlink(missing_ok=True)
    try:
        write_status(
            app_data,
            True,
            f"Updated {file_count} app file(s) from the verified compact package.",
            backup,
        )
    except Exception as exc:
        show_error(f"The update installed, but its status receipt could not be saved.\n\n{exc}")
    try:
        launch_desktop(target, completed=True)
    except Exception as exc:
        show_error(f"The update installed, but VaultLink could not restart automatically.\n\n{exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def canonical_manifest_bytes(manifest):
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def package_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def compact_bootstrap_source(version, payload_sha256, expected_files):
    return (
        COMPACT_BOOTSTRAP_TEMPLATE.replace("__VERSION__", json.dumps(str(version)))
        .replace("__PAYLOAD_SHA256__", json.dumps(str(payload_sha256)))
        .replace("__EXPECTED_FILES__", json.dumps(list(expected_files), ensure_ascii=True))
    )


def build_compact_payload(source_dir, destination):
    with lzma.open(destination, "wb", format=lzma.FORMAT_XZ, preset=9 | lzma.PRESET_EXTREME) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            for name in PACKAGE_FILES:
                data = (source_dir / name).read_bytes()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o644
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                archive.addfile(info, io.BytesIO(data))


def authorize_owner_release(owner_key_path):
    owner_key_path = Path(owner_key_path)
    if not owner_key_path.is_file():
        raise ValueError("The registered owner USB key is not available.")
    settings = locker.load_settings()
    encoded_policy = settings.get("owner_usb_policy")
    if not encoded_policy:
        raise ValueError("A Windows-protected owner USB policy is required before an update can be signed or published.")
    try:
        encrypted_policy = base64.b64decode(encoded_policy.encode("ascii"), validate=True)
        policy = json.loads(locker.dpapi_unprotect(encrypted_policy, locker.OWNER_POLICY_ENTROPY).decode("utf-8"))
    except Exception as exc:
        raise ValueError("The Windows-protected owner USB policy could not be verified.") from exc
    if not isinstance(policy, dict):
        raise ValueError("The Windows-protected owner USB policy is invalid.")
    key = locker.load_key_file(owner_key_path)
    allowed, message = locker.owner_key_allowed(key, policy)
    if not allowed:
        raise ValueError(f"Owner USB authorization failed. {message}")
    origin = key.get("origin") or {}
    if origin.get("drive_type") != locker.DRIVE_REMOVABLE:
        raise ValueError("Update publishing requires the registered removable owner USB.")
    return {
        "key_id": key["key_id"],
        "volume_serial": origin.get("serial", ""),
    }


def load_owner_signing_key(owner_key_path):
    authorization = authorize_owner_release(owner_key_path)
    key_path = locker.APP_DIR / "owner_update_signing_key.dpapi"
    if not key_path.exists():
        raise ValueError(
            "The owner update-signing key is missing. Do not create a replacement key after releases are published."
        )
    raw = locker.dpapi_unprotect(key_path.read_bytes(), UPDATE_KEY_ENTROPY)
    if len(raw) != 32:
        raise ValueError("The owner update-signing key is invalid.")
    return Ed25519PrivateKey.from_private_bytes(raw), authorization


def build_package(source_dir, destination):
    missing = [name for name in PACKAGE_FILES if not (source_dir / name).is_file()]
    if missing:
        raise ValueError("Update package files are missing: " + ", ".join(missing))
    if (
        len(set(PACKAGE_FILES)) != len(PACKAGE_FILES)
        or "usb_file_locker.py" not in PACKAGE_FILES
        or any(Path(name).name != name or "\\" in name or "\0" in name for name in PACKAGE_FILES)
    ):
        raise ValueError("Update package file allowlist is invalid.")
    handle, temp_name = tempfile.mkstemp(prefix="vaultlink-update-", suffix=".zip", dir=destination.parent)
    os.close(handle)
    temp_path = Path(temp_name)
    payload_handle, payload_name = tempfile.mkstemp(
        prefix="vaultlink-payload-",
        suffix=".tar.xz",
        dir=destination.parent,
    )
    os.close(payload_handle)
    payload_path = Path(payload_name)
    try:
        build_compact_payload(source_dir, payload_path)
        payload_hash = package_sha256(payload_path)
        bootstrap = compact_bootstrap_source(
            locker.DESKTOP_APP_VERSION,
            payload_hash,
            PACKAGE_FILES,
        )
        with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            archive.writestr("usb_file_locker.py", bootstrap)
            archive.write(
                payload_path,
                arcname=COMPACT_PAYLOAD_FILENAME,
                compress_type=zipfile.ZIP_STORED,
            )
        os.replace(temp_path, destination)
    finally:
        temp_path.unlink(missing_ok=True)
        payload_path.unlink(missing_ok=True)


def build_signed_release(source_dir, updates_dir, minimum_supported, notes, owner_key_path):
    source_dir = Path(source_dir).resolve()
    updates_dir = Path(updates_dir).resolve()
    version = locker.DESKTOP_APP_VERSION
    locker.update_version_tuple(version)
    locker.update_version_tuple(minimum_supported)
    private_key, authorization = load_owner_signing_key(owner_key_path)
    public_raw = private_key.public_key().public_bytes_raw()
    key_id = hashlib.sha256(public_raw).hexdigest()[:16]
    if key_id != locker.UPDATE_SIGNING_KEY_ID:
        raise ValueError("The owner signing key does not match the public key embedded in the app.")

    updates_dir.parent.mkdir(parents=True, exist_ok=True)
    stage_dir = Path(tempfile.mkdtemp(prefix=".vaultlink-release-", dir=updates_dir.parent))
    package_filename = f"VaultLink-Windows-{version}.zip"
    staged_package = stage_dir / package_filename
    staged_manifest = stage_dir / "windows-manifest.json"
    try:
        build_package(source_dir, staged_package)
        release_notes = list(notes or [
            "Signed desktop update published through the owner-only Update Lab.",
            "Keys, licenses, settings, vault data, audit logs, and locked files remain untouched.",
        ])
        manifest = {
            "schema_version": 1,
            "product": "USB File Locker",
            "platform": "windows-source",
            "version": version,
            "minimum_supported_version": minimum_supported,
            "published_at_utc": locker.utc_now_text(),
            "package_filename": package_filename,
            "download_path": "/api/v1/updates/windows/download",
            "sha256": package_sha256(staged_package),
            "size_bytes": staged_package.stat().st_size,
            "signing_key_id": key_id,
            "notes": release_notes,
            "preserves_local_app_data": True,
        }
        manifest["signature"] = b64url(private_key.sign(canonical_manifest_bytes(manifest)))
        locker.write_text_atomic(staged_manifest, json.dumps(manifest, indent=2))
        vaultlink_updater.validate_manifest(manifest, staged_package)
        updates_dir.mkdir(parents=True, exist_ok=True)
        package_path = updates_dir / package_filename
        manifest_path = updates_dir / "windows-manifest.json"
        os.replace(staged_package, package_path)
        os.replace(staged_manifest, manifest_path)
        return {
            "version": version,
            "package": str(package_path),
            "manifest": str(manifest_path),
            "sha256": manifest["sha256"],
            "size_bytes": manifest["size_bytes"],
            "signing_key_id": key_id,
            "files": len(PACKAGE_FILES),
            "owner_key_id": authorization["key_id"],
        }
    finally:
        shutil.rmtree(stage_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Build and sign a VaultLink Windows update release.")
    parser.add_argument("--api-repo", required=True, help="Path to the standalone API repo.")
    parser.add_argument("--owner-key", required=True, help="Path to the registered removable owner USB key.")
    parser.add_argument("--minimum-supported", default="2026.07.12.9")
    parser.add_argument("--note", action="append", default=[])
    args = parser.parse_args()

    source_dir = Path(__file__).resolve().parent
    api_repo = Path(args.api_repo).resolve()
    if not (api_repo / "main.py").is_file():
        raise ValueError("The selected API repo does not contain main.py.")
    result = build_signed_release(
        source_dir,
        api_repo / "updates",
        args.minimum_supported,
        args.note,
        args.owner_key,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
