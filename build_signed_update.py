import argparse
import base64
import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import usb_file_locker as locker
import vaultlink_updater


UPDATE_KEY_ENTROPY = b"VaultLinkUpdateSigningKeyV1"
PACKAGE_FILES = [
    "Ensure Dependencies.cmd",
    "README.md",
    "README.txt",
    "Run Audit Log Viewer.bat",
    "Run Global Breach Guard.bat",
    "Run Key Inspector.bat",
    "Run License Issuer.bat",
    "Run Locked File Browser.bat",
    "Run PERM UNLOCK Workbench.bat",
    "Run Personal Vault Pad.bat",
    "Run Privacy Safety Hub.bat",
    "Run Quick Lock Note.bat",
    "Run Text Log Processor.bat",
    "Run USB File Locker.bat",
    "audit_log_viewer.py",
    "global_breach_guard.py",
    "key_inspector.py",
    "license_issuer.py",
    "locked_file_browser.py",
    "perm_unlock_workbench.py",
    "personal_vault_pad.py",
    "privacy_safety_hub.py",
    "quick_lock_note.py",
    "requirements.txt",
    "settings.example.json",
    "text_log_processor.py",
    "usb_file_locker.py",
    "vaultlink_updater.py",
]


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


def load_owner_signing_key():
    key_path = locker.APP_DIR / "owner_update_signing_key.dpapi"
    if not key_path.exists():
        raise ValueError(
            "The owner update-signing key is missing. Do not create a replacement key after releases are published."
        )
    raw = locker.dpapi_unprotect(key_path.read_bytes(), UPDATE_KEY_ENTROPY)
    if len(raw) != 32:
        raise ValueError("The owner update-signing key is invalid.")
    return Ed25519PrivateKey.from_private_bytes(raw)


def build_package(source_dir, destination):
    missing = [name for name in PACKAGE_FILES if not (source_dir / name).is_file()]
    if missing:
        raise ValueError("Update package files are missing: " + ", ".join(missing))
    handle, temp_name = tempfile.mkstemp(prefix="vaultlink-update-", suffix=".zip", dir=destination.parent)
    os.close(handle)
    temp_path = Path(temp_name)
    try:
        with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name in PACKAGE_FILES:
                archive.write(source_dir / name, arcname=name)
        os.replace(temp_path, destination)
    finally:
        temp_path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description="Build and sign a VaultLink Windows update release.")
    parser.add_argument("--api-repo", required=True, help="Path to the standalone API repo.")
    parser.add_argument("--minimum-supported", default="2026.07.10")
    parser.add_argument("--note", action="append", default=[])
    args = parser.parse_args()

    source_dir = Path(__file__).resolve().parent
    api_repo = Path(args.api_repo).resolve()
    if not (api_repo / "main.py").is_file():
        raise ValueError("The selected API repo does not contain main.py.")
    updates_dir = api_repo / "updates"
    updates_dir.mkdir(parents=True, exist_ok=True)
    version = locker.DESKTOP_APP_VERSION
    locker.update_version_tuple(version)
    locker.update_version_tuple(args.minimum_supported)
    package_filename = f"VaultLink-Windows-{version}.zip"
    package_path = updates_dir / package_filename
    build_package(source_dir, package_path)

    private_key = load_owner_signing_key()
    public_raw = private_key.public_key().public_bytes_raw()
    key_id = hashlib.sha256(public_raw).hexdigest()[:16]
    if key_id != locker.UPDATE_SIGNING_KEY_ID:
        raise ValueError("The owner signing key does not match the public key embedded in the app.")
    notes = args.note or [
        "API breach log listing and owner downloads.",
        "Signed automatic update checking and staged installation.",
        "Privacy-safe audit reports remain free of secrets, file contents, and full paths.",
    ]
    manifest = {
        "schema_version": 1,
        "product": "USB File Locker",
        "platform": "windows-source",
        "version": version,
        "minimum_supported_version": args.minimum_supported,
        "published_at_utc": locker.utc_now_text(),
        "package_filename": package_filename,
        "download_path": "/api/v1/updates/windows/download",
        "sha256": package_sha256(package_path),
        "size_bytes": package_path.stat().st_size,
        "signing_key_id": key_id,
        "notes": notes,
        "preserves_local_app_data": True,
    }
    manifest["signature"] = b64url(private_key.sign(canonical_manifest_bytes(manifest)))
    manifest_path = updates_dir / "windows-manifest.json"
    locker.write_text_atomic(manifest_path, json.dumps(manifest, indent=2))
    vaultlink_updater.validate_manifest(manifest, package_path)
    print(
        json.dumps(
            {
                "version": version,
                "package": str(package_path),
                "manifest": str(manifest_path),
                "sha256": manifest["sha256"],
                "size_bytes": manifest["size_bytes"],
                "signing_key_id": key_id,
                "files": len(PACKAGE_FILES),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
