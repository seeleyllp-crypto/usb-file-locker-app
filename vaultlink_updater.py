import argparse
import ast
import base64
import ctypes
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


UPDATE_SIGNING_PUBLIC_KEY_B64 = "UhQt7KyhSd6na6ZL5zmvOTKMgQqdY3FUEdoKRX-iGKU"
UPDATE_SIGNING_KEY_ID = "4f8fb9b8dbffd4c0"
MAX_UPDATE_PACKAGE_BYTES = 50 * 1024 * 1024
MAX_UPDATE_ARCHIVE_FILES = 5000
MAX_UPDATE_EXTRACTED_BYTES = 100 * 1024 * 1024
MAX_EMBEDDED_APP_SOURCE_BYTES = 4 * 1024 * 1024
UPDATE_VERSION_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+){1,7}\Z")
FORBIDDEN_FILE_NAMES = {
    "settings.json",
    "audit_log.jsonl",
    "locker_log.jsonl",
    "audit_key.dpapi",
    "audit_verification.json",
    "purchase-license.json",
}


def decode_base64url(value):
    text = str(value or "").strip()
    if not text or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in text):
        raise ValueError("Update signature encoding is invalid.")
    return base64.urlsafe_b64decode(text + "=" * ((4 - len(text) % 4) % 4))


def canonical_manifest_bytes(manifest):
    payload = dict(manifest)
    payload.pop("signature", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def validated_update_version(value):
    version = str(value or "").strip()
    if len(version) > 80 or not UPDATE_VERSION_PATTERN.fullmatch(version):
        raise ValueError("Update version is invalid.")
    return version


def update_version_tuple(value):
    return tuple(int(part) for part in validated_update_version(value).split("."))


def update_version_is_newer(left, right):
    left_parts = update_version_tuple(left)
    right_parts = update_version_tuple(right)
    length = max(len(left_parts), len(right_parts))
    return (left_parts + (0,) * (length - len(left_parts))) > (
        right_parts + (0,) * (length - len(right_parts))
    )


def package_desktop_version(package_path):
    try:
        with zipfile.ZipFile(package_path, "r") as archive:
            matches = [
                info
                for info in archive.infolist()
                if not info.is_dir() and info.filename == "usb_file_locker.py"
            ]
            if len(matches) != 1:
                raise ValueError("Update package must contain exactly one desktop entrypoint.")
            if not 0 < matches[0].file_size <= MAX_EMBEDDED_APP_SOURCE_BYTES:
                raise ValueError("Update package desktop entrypoint size is invalid.")
            source = archive.read(matches[0]).decode("utf-8")
    except (OSError, UnicodeError, zipfile.BadZipFile) as exc:
        raise ValueError("Update package desktop entrypoint could not be inspected.") from exc
    try:
        module = ast.parse(source, filename="usb_file_locker.py")
    except SyntaxError as exc:
        raise ValueError("Update package desktop entrypoint is not valid Python syntax.") from exc
    versions = []
    for statement in module.body:
        targets = statement.targets if isinstance(statement, ast.Assign) else []
        if isinstance(statement, ast.AnnAssign):
            targets = [statement.target]
        if not any(isinstance(target, ast.Name) and target.id == "DESKTOP_APP_VERSION" for target in targets):
            continue
        value = statement.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            raise ValueError("Update package desktop version must be a literal string.")
        versions.append(validated_update_version(value.value))
    if len(versions) != 1:
        raise ValueError("Update package must declare exactly one desktop version.")
    return versions[0]


def validate_manifest(manifest, package_path):
    if not isinstance(manifest, dict):
        raise ValueError("Update manifest must be a JSON object.")
    allowed_fields = {
        "schema_version",
        "product",
        "platform",
        "version",
        "minimum_supported_version",
        "published_at_utc",
        "package_filename",
        "download_path",
        "sha256",
        "size_bytes",
        "signing_key_id",
        "notes",
        "preserves_local_app_data",
        "signature",
    }
    if set(manifest) != allowed_fields:
        raise ValueError("Update manifest fields are invalid.")
    if manifest.get("schema_version") != 1:
        raise ValueError("Update manifest schema is not supported.")
    if manifest.get("product") != "USB File Locker" or manifest.get("platform") != "windows-source":
        raise ValueError("Update manifest is for a different product or platform.")
    if manifest.get("signing_key_id") != UPDATE_SIGNING_KEY_ID:
        raise ValueError("Update was signed by an unknown release key.")
    if manifest.get("preserves_local_app_data") is not True:
        raise ValueError("Update does not promise to preserve app data.")
    version = validated_update_version(manifest.get("version"))
    minimum_supported = validated_update_version(manifest.get("minimum_supported_version"))
    if update_version_is_newer(minimum_supported, version):
        raise ValueError("Update compatibility floor cannot be newer than the update version.")
    filename = str(manifest.get("package_filename", ""))
    if Path(filename).name != filename or filename != package_path.name:
        raise ValueError("Update package filename does not match the signed manifest.")
    if filename != f"VaultLink-Windows-{version}.zip":
        raise ValueError("Update package filename does not match the declared version.")
    expected_hash = str(manifest.get("sha256", "")).lower()
    if len(expected_hash) != 64 or any(character not in "0123456789abcdef" for character in expected_hash):
        raise ValueError("Update package SHA-256 is invalid.")
    try:
        expected_size = int(manifest.get("size_bytes", 0))
    except (TypeError, ValueError) as exc:
        raise ValueError("Update package size is invalid.") from exc
    actual_size = package_path.stat().st_size
    if not 0 < actual_size <= MAX_UPDATE_PACKAGE_BYTES or actual_size != expected_size:
        raise ValueError("Update package size does not match the signed manifest.")
    public_key = Ed25519PublicKey.from_public_bytes(decode_base64url(UPDATE_SIGNING_PUBLIC_KEY_B64))
    try:
        public_key.verify(decode_base64url(manifest.get("signature")), canonical_manifest_bytes(manifest))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("Update manifest signature did not verify.") from exc
    digest = hashlib.sha256()
    with package_path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    if digest.hexdigest() != expected_hash:
        raise ValueError("Update package SHA-256 did not match the signed manifest.")
    embedded_version = package_desktop_version(package_path)
    if embedded_version != version:
        raise ValueError("Update package embedded desktop version does not match the signed manifest.")


def safe_member_path(name):
    if "\\" in name or "\0" in name:
        raise ValueError("Update package contains an unsafe path.")
    pure = PurePosixPath(name)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("Update package contains an unsafe path.")
    if ":" in pure.parts[0]:
        raise ValueError("Update package contains an unsafe drive path.")
    relative = Path(*pure.parts)
    if relative.parts[0].lower() in {".git", "__pycache__"}:
        raise ValueError("Update package contains a forbidden internal folder.")
    lower_name = relative.name.lower()
    if (
        lower_name in FORBIDDEN_FILE_NAMES
        or (lower_name.startswith("audit_log.") and lower_name.endswith(".jsonl"))
        or relative.suffix.lower() in {".key", ".locked", ".dpapi", ".usblock"}
    ):
        raise ValueError("Update package contains private runtime data.")
    return relative


def extract_verified_package(package_path, destination):
    if destination.exists():
        if not destination.is_dir() or destination.is_symlink():
            raise ValueError("Update extraction destination is not a safe directory.")
        if any(destination.iterdir()):
            raise ValueError("Update extraction destination must be empty.")
    else:
        destination.mkdir(parents=True, exist_ok=False)
    destination_root = destination.resolve()
    with zipfile.ZipFile(package_path, "r") as archive:
        infos = archive.infolist()
        file_count = sum(1 for info in infos if not info.is_dir())
        total_size = sum(info.file_size for info in infos if not info.is_dir())
        if len(infos) > MAX_UPDATE_ARCHIVE_FILES or total_size > MAX_UPDATE_EXTRACTED_BYTES:
            raise ValueError("Update package expands beyond the allowed safety limit.")
        for info in infos:
            relative = safe_member_path(info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ValueError("Update packages containing links are not supported.")
            target = (destination / relative).resolve()
            try:
                target.relative_to(destination_root)
            except ValueError as exc:
                raise ValueError("Update package tried to write outside the staging folder.") from exc
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info, "r") as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
    return file_count


def wait_for_parent_exit(parent_pid, timeout_seconds=45):
    if parent_pid <= 0:
        return
    synchronize = 0x00100000
    handle = ctypes.windll.kernel32.OpenProcess(synchronize, False, parent_pid)
    if not handle:
        return
    try:
        ctypes.windll.kernel32.WaitForSingleObject(handle, int(timeout_seconds * 1000))
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def validate_target(target):
    resolved = target.resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise ValueError("Update target folder does not exist.")
    if resolved.parent == resolved:
        raise ValueError("Refusing to update a filesystem root.")
    return resolved


def apply_update(extracted, target, version):
    app_data = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "USBFileLocker"
    backup = app_data / "update_backups" / f"before-{version}-{time.strftime('%Y%m%d-%H%M%S')}"
    backup.mkdir(parents=True, exist_ok=False)
    files = [path for path in extracted.rglob("*") if path.is_file()]
    files.sort(key=lambda path: (path.name.lower() == "vaultlink_updater.py", path.as_posix().lower()))
    if not files:
        raise ValueError("Update package did not contain any app files.")
    for source in files:
        if source.is_symlink():
            raise ValueError("Update package staging contains an unsupported link.")
        relative = source.relative_to(extracted)
        safe_member_path(relative.as_posix())
        destination = (target / relative).resolve()
        try:
            destination.relative_to(target)
        except ValueError as exc:
            raise ValueError("Update tried to write outside the app folder.") from exc
        if destination.exists():
            if not destination.is_file() or destination.is_symlink():
                raise ValueError(f"Cannot safely replace {relative.as_posix()}.")
            backup_path = backup / relative
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(destination, backup_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp_path = destination.with_name(f".{destination.name}.vaultlink-update.tmp")
        try:
            shutil.copy2(source, temp_path)
            os.replace(temp_path, destination)
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
    return backup, len(files)


def write_status(ok, version, message, backup=""):
    app_data = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "USBFileLocker"
    app_data.mkdir(parents=True, exist_ok=True)
    payload = {
        "ok": bool(ok),
        "version": str(version),
        "message": str(message),
        "backup_dir": str(backup),
        "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    target = app_data / "update-status.json"
    temp_path = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    temp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(temp_path, target)


def show_error(message):
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("VaultLink update failed", message, parent=root)
        root.destroy()
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="Apply a signed VaultLink update package.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--parent-pid", type=int, default=0)
    args = parser.parse_args()

    manifest_path = Path(args.manifest).resolve()
    package_path = Path(args.package).resolve()
    target = validate_target(Path(args.target))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    version = str(manifest.get("version", "unknown")) if isinstance(manifest, dict) else "unknown"
    extracted = Path(tempfile.mkdtemp(prefix="vaultlink-update-extracted-"))
    try:
        validate_manifest(manifest, package_path)
        extract_verified_package(package_path, extracted)
        wait_for_parent_exit(args.parent_pid)
        backup, file_count = apply_update(extracted, target, version)
        write_status(True, version, f"Updated {file_count} app file(s).", backup)
        env = dict(os.environ)
        env["VAULTLINK_UPDATE_COMPLETED"] = version
        subprocess.Popen(
            [sys.executable, str(target / "usb_file_locker.py")],
            cwd=str(target),
            env=env,
            creationflags=0x08000000,
        )
        return 0
    except Exception as exc:
        write_status(False, version, str(exc))
        show_error(str(exc))
        return 1
    finally:
        shutil.rmtree(extracted, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
