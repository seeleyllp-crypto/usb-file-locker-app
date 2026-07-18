import argparse
import base64
import hashlib
import json
import os
import shutil
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
    "Run Backup Verification Center.bat",
    "Run Customer Hub.bat",
    "Run Diagnostics Center.bat",
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
