import base64
import hashlib
import json
import os
import queue
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import audit_log_viewer
import build_signed_update
import customer_hub
import license_issuer
import owner_update_lab
import usb_file_locker as locker
import vaultlink_updater
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


VALID_TEST_LICENSE = "vlk1." + ("A" * 24) + "." + ("B" * 24)


class FakeVar:
    def __init__(self):
        self.value = ""

    def set(self, value):
        self.value = value


class FakeButton:
    def __init__(self, state="normal"):
        self.state = state

    def configure(self, **kwargs):
        if "state" in kwargs:
            self.state = kwargs["state"]

    def cget(self, name):
        if name == "state":
            return self.state
        raise KeyError(name)


class DesktopHelperTests(unittest.TestCase):
    def test_first_account_and_announcement_sync_starts_early(self):
        self.assertEqual(locker.INITIAL_LICENSE_REFRESH_MS, 1000)

    def test_every_launcher_bootstraps_dependencies(self):
        app_dir = Path(__file__).resolve().parent
        launchers = sorted(app_dir.glob("Run *.bat"))
        self.assertEqual(len(launchers), 13)
        for launcher in launchers:
            with self.subTest(launcher=launcher.name):
                content = launcher.read_text(encoding="utf-8")
                self.assertIn('call "%~dp0Ensure Dependencies.cmd"', content)
                self.assertIn("%PYTHON_CMD%", content)
        self.assertIn("customer_hub.py", build_signed_update.PACKAGE_FILES)
        self.assertIn("Run Customer Hub.bat", build_signed_update.PACKAGE_FILES)
        self.assertNotIn("owner_update_lab.py", build_signed_update.PACKAGE_FILES)
        self.assertNotIn("Run Owner Update Lab.bat", build_signed_update.PACKAGE_FILES)
        self.assertTrue(issubclass(customer_hub.CustomerHub, customer_hub.tk.Tk))

    def test_owner_release_authorization_requires_protected_policy_and_removable_usb(self):
        with tempfile.TemporaryDirectory(prefix="vaultlink_owner_auth_") as temp_dir:
            key_path = Path(temp_dir) / "master_usb_file_locker.key"
            key_path.write_text("test key placeholder", encoding="utf-8")
            policy = {"key_id": "owner-test", "volume_serial": "USB-123"}
            removable_key = {
                "key_id": "owner-test",
                "path": str(key_path),
                "origin": {"drive_type": locker.DRIVE_REMOVABLE, "serial": "USB-123"},
            }
            encoded_policy = base64.b64encode(b"windows-protected-policy").decode("ascii")

            with mock.patch.object(locker, "load_settings", return_value={}):
                with self.assertRaisesRegex(ValueError, "Windows-protected owner USB policy"):
                    build_signed_update.authorize_owner_release(key_path)

            with mock.patch.object(locker, "load_settings", return_value={"owner_usb_policy": encoded_policy}), \
                    mock.patch.object(locker, "dpapi_unprotect", return_value=json.dumps(policy).encode("utf-8")), \
                    mock.patch.object(locker, "load_key_file", return_value=removable_key), \
                    mock.patch.object(locker, "owner_key_allowed", return_value=(True, "")):
                authorization = build_signed_update.authorize_owner_release(key_path)
            self.assertEqual(authorization["key_id"], "owner-test")
            self.assertEqual(authorization["volume_serial"], "USB-123")

            fixed_key = dict(removable_key)
            fixed_key["origin"] = {"drive_type": locker.DRIVE_FIXED, "serial": "USB-123"}
            with mock.patch.object(locker, "load_settings", return_value={"owner_usb_policy": encoded_policy}), \
                    mock.patch.object(locker, "dpapi_unprotect", return_value=json.dumps(policy).encode("utf-8")), \
                    mock.patch.object(locker, "load_key_file", return_value=fixed_key), \
                    mock.patch.object(locker, "owner_key_allowed", return_value=(True, "")):
                with self.assertRaisesRegex(ValueError, "removable owner USB"):
                    build_signed_update.authorize_owner_release(key_path)

        self.assertTrue(callable(owner_update_lab.build_and_test_candidate))
        self.assertTrue(callable(owner_update_lab.publish_verified_candidate))

    def test_owner_candidate_verifier_returns_the_validated_manifest(self):
        with tempfile.TemporaryDirectory(prefix="vaultlink_candidate_verify_") as temp_dir:
            temp_path = Path(temp_dir)
            manifest_path = temp_path / "windows-manifest.json"
            package_path = temp_path / "VaultLink-Windows-test.zip"
            manifest = {"version": "9999.1", "preserves_local_app_data": True}
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with zipfile.ZipFile(package_path, "w") as archive:
                archive.writestr("README.txt", "safe test package")
            with mock.patch.object(owner_update_lab.vaultlink_updater, "validate_manifest", return_value=None) as validate:
                validated = owner_update_lab.verify_candidate_files(manifest_path, package_path)
            validate.assert_called_once_with(manifest, package_path)
            self.assertEqual(validated, manifest)

    def test_license_key_validation_and_state_replacement(self):
        self.assertTrue(locker.valid_api_license_key(VALID_TEST_LICENSE))
        self.assertFalse(locker.valid_api_license_key("PSI-OLD-STYLE-KEY"))
        with self.assertRaisesRegex(ValueError, "starts with vlk1"):
            locker.require_valid_api_license_key("PSI-OLD-STYLE-KEY")

        original = locker.normalize_license_state(
            {
                "server_url": locker.DEFAULT_LICENSE_SERVER,
                "license_key": VALID_TEST_LICENSE,
                "receipt": "vlr1." + ("C" * 24) + "." + ("D" * 24),
                "status": "active",
                "plan_id": "family-safety",
                "features": ["privacy-safety-hub"],
            }
        )
        replacement_key = "vlk1." + ("E" * 24) + "." + ("F" * 24)
        replaced = locker.license_state_with_key(original, replacement_key)
        self.assertEqual(replaced["license_key"], replacement_key)
        self.assertEqual(replaced["receipt"], "")
        self.assertEqual(replaced["features"], [])
        self.assertEqual(replaced["status"], "saved")

    def test_license_sync_uses_heartbeat_and_applies_server_metadata(self):
        state = locker.normalize_license_state(
            {
                "license_key": VALID_TEST_LICENSE,
                "receipt": "vlr1." + ("C" * 24) + "." + ("D" * 24),
                "status": "active",
                "features": ["privacy-safety-hub"],
            }
        )
        response = {
            "ok": True,
            "active": True,
            "status": "active",
            "plan": {
                "id": "personal-plus",
                "name": "$50 Personal Plus",
                "entitlements": ["privacy-safety-hub"],
            },
            "license": {"license_id": "LIC-SYNC"},
            "activation": {"valid_until_utc": "2099-01-01T00:00:00Z"},
            "device_usage": {"active": 2, "maximum": 4},
            "api_version": "0.11.0",
            "sync": {
                "recommended_interval_seconds": 60,
                "decision_id": "0123456789abcdef",
            },
            "release": {
                "latest_version": "2026.07.12.6",
                "minimum_supported_version": "2026.07.11.3",
                "update_available": False,
            },
            "service_status": {
                "mode": "maintenance",
                "message": "Short scheduled maintenance.",
                "updated_at_utc": "2026-07-12T20:00:00Z",
            },
            "announcements": {
                "count": 1,
                "items": [
                    {
                        "announcement_id": "ANN-0123456789ABCDEF",
                        "severity": "update",
                        "title": "Desktop update",
                        "message": "A signed desktop update is ready.",
                    }
                ],
            },
            "server_time_utc": locker.utc_now_text(),
        }
        with mock.patch.object(locker, "license_api_post_json", return_value=response) as post:
            updated = locker.verify_license_online(state, timeout=5)
        self.assertEqual(post.call_args.args[1], "/api/v1/licenses/sync")
        self.assertEqual(post.call_args.kwargs["timeout"], 5)
        self.assertTrue(locker.license_is_active(updated))
        self.assertEqual(updated["api_version"], "0.11.0")
        self.assertEqual(updated["last_decision_id"], "0123456789abcdef")
        self.assertEqual((updated["device_active"], updated["device_maximum"]), (2, 4))
        self.assertEqual(updated["latest_desktop_version"], "2026.07.12.6")
        self.assertEqual(updated["service_status"]["mode"], "maintenance")
        self.assertEqual(updated["announcements"][0]["announcement_id"], "ANN-0123456789ABCDEF")

    def test_owner_notices_show_once_and_save_only_anonymous_ids(self):
        app = object.__new__(locker.USBFileLocker)
        app.license_state = locker.normalize_license_state(
            {
                "license_key": VALID_TEST_LICENSE,
                "receipt": "vlr1." + ("C" * 24) + "." + ("D" * 24),
                "status": "active",
                "receipt_expires_at": "2099-01-01T00:00:00Z",
                "announcements": [
                    {
                        "announcement_id": "ANN-0123456789ABCDEF",
                        "severity": "security",
                        "title": "Security notice",
                        "message": "Install the signed update.",
                    }
                ],
                "service_status": {
                    "mode": "degraded",
                    "message": "Some API requests may be slower.",
                    "updated_at_utc": "2026-07-12T20:00:00Z",
                },
            }
        )
        app.settings = {}
        app.status = FakeVar()
        with (
            mock.patch.object(locker, "license_is_active", return_value=True),
            mock.patch.object(locker, "save_settings") as save,
            mock.patch.object(locker, "log_event") as log,
            mock.patch.object(locker.messagebox, "showwarning") as warning,
        ):
            locker.USBFileLocker.show_new_owner_notices(app)
            locker.USBFileLocker.show_new_owner_notices(app)

        warning.assert_called_once()
        save.assert_called_once()
        log.assert_called_once()
        self.assertIn("ANN-0123456789ABCDEF", app.settings["seen_owner_announcement_ids"])
        self.assertNotIn("Security notice", json.dumps(app.settings))

    def test_customer_center_summary_hides_license_proof_and_private_identity(self):
        state = locker.normalize_license_state(
            {
                "license_key": VALID_TEST_LICENSE,
                "receipt": "vlr1." + ("C" * 24) + "." + ("D" * 24),
                "machine_id": "PRIVATE-MACHINE-ID",
                "status": "active",
                "plan_name": "$100 Family Safety",
                "device_active": 2,
                "device_maximum": 4,
                "api_version": "0.12.0",
                "latest_desktop_version": "2026.07.12.8",
                "last_checked_utc": "2026-07-12T22:00:00Z",
                "service_status": {"mode": "normal", "message": "All services are operating normally."},
                "announcements": [
                    {
                        "announcement_id": "ANN-0123456789ABCDEF",
                        "title": "Update",
                        "message": "A release is ready.",
                    }
                ],
            }
        )
        details = locker.customer_center_details(state, {"auto_install_signed_updates": True})
        serialized = json.dumps(details)
        self.assertEqual(details["device_seats"], "2/4")
        self.assertEqual(details["owner_messages"], "1")
        self.assertEqual(details["automatic_updates"], "ON")
        self.assertNotIn(VALID_TEST_LICENSE, serialized)
        self.assertNotIn(state["receipt"], serialized)
        self.assertNotIn("PRIVATE-MACHINE-ID", serialized)

    def test_bug_report_api_sends_only_explicit_text_and_license_proof(self):
        state = locker.normalize_license_state(
            {
                "license_key": VALID_TEST_LICENSE,
                "receipt": "vlr1." + ("C" * 24) + "." + ("D" * 24),
                "status": "active",
                "features": [],
                "receipt_expires_at": "2099-01-01T00:00:00Z",
                "last_checked_utc": locker.utc_now_text(),
            }
        )
        response = {"ok": True, "created": True, "ticket": {"ticket_id": "TKT-TEST12345678"}}
        with mock.patch.object(locker, "license_api_post_json", return_value=response) as post:
            result = locker.create_support_ticket_online(
                state,
                "bug",
                "Button stopped",
                "The lock button stopped after two files.",
                "Add files, then click LOCK COPY.",
            )
        self.assertTrue(result["created"])
        self.assertEqual(post.call_args.args[1], "/api/v1/support-tickets")
        payload = post.call_args.args[2]
        self.assertEqual(payload["subject"], "Button stopped")
        self.assertEqual(payload["app_version"], locker.DESKTOP_APP_VERSION)
        for forbidden in ("logs", "files", "paths", "pin", "password", "usb_secret"):
            self.assertNotIn(forbidden, payload)

        with mock.patch.object(
            locker,
            "license_api_post_json",
            return_value={"ok": True, "count": 1, "items": [response["ticket"]]},
        ) as post:
            listed = locker.list_my_support_tickets_online(state)
        self.assertEqual(listed["count"], 1)
        self.assertEqual(post.call_args.args[1], "/api/v1/support-tickets/mine")

    def test_owner_news_uses_license_proof_and_shop_url_has_no_credentials(self):
        state = locker.normalize_license_state(
            {
                "license_key": VALID_TEST_LICENSE,
                "receipt": "vlr1." + ("C" * 24) + "." + ("D" * 24),
                "status": "active",
                "features": [],
                "receipt_expires_at": "2099-01-01T00:00:00Z",
                "last_checked_utc": locker.utc_now_text(),
                "server_url": locker.DEFAULT_LICENSE_SERVER,
            }
        )
        response = {
            "ok": True,
            "count": 1,
            "plan_rank": 1,
            "items": [
                {
                    "announcement_id": "ANN-TEST12345678",
                    "severity": "info",
                    "title": "Owner news",
                    "message": "A safe read-only message.",
                }
            ],
        }
        with mock.patch.object(locker, "license_api_post_json", return_value=response) as post:
            result = locker.list_owner_announcements_online(state)
        self.assertEqual(result["count"], 1)
        self.assertEqual(post.call_args.args[1], "/api/v1/announcements/mine")
        payload = post.call_args.args[2]
        self.assertEqual(payload["app_version"], locker.DESKTOP_APP_VERSION)
        self.assertIn("license_key", payload)
        self.assertIn("receipt", payload)
        for forbidden in ("logs", "files", "paths", "pin", "password", "usb_secret"):
            self.assertNotIn(forbidden, payload)

        shop_url = locker.shop_url_for_state(state)
        self.assertEqual(shop_url, locker.DEFAULT_LICENSE_SERVER + "/shop")
        self.assertNotIn(state["license_key"], shop_url)
        self.assertNotIn(state["receipt"], shop_url)

        app = SimpleNamespace(status=FakeVar())
        with (
            mock.patch.object(locker, "load_settings", return_value={}),
            mock.patch.object(locker, "load_license_state", return_value=state),
            mock.patch.object(locker.os, "startfile") as startfile,
            mock.patch.object(locker, "log_event"),
        ):
            locker.USBFileLocker.open_customer_status(app)
        status_url = startfile.call_args.args[0]
        self.assertEqual(status_url, locker.DEFAULT_LICENSE_SERVER + "/status")
        self.assertNotIn(state["license_key"], status_url)
        self.assertNotIn(state["receipt"], status_url)

    def test_stale_feature_gate_enforces_revocation_but_keeps_valid_cache_on_outage(self):
        active = locker.normalize_license_state(
            {
                "license_key": VALID_TEST_LICENSE,
                "receipt": "vlr1." + ("C" * 24) + "." + ("D" * 24),
                "status": "active",
                "features": ["privacy-safety-hub"],
                "receipt_expires_at": "2099-01-01T00:00:00Z",
                "last_checked_utc": "",
            }
        )
        revoked = locker.normalize_license_state({**active, "status": "revoked", "last_error": "Revoked"})
        with (
            mock.patch.object(locker, "load_license_state", return_value=active),
            mock.patch.object(locker, "verify_license_online", return_value=revoked),
            mock.patch.object(locker, "save_license_state", side_effect=lambda _settings, state: state),
        ):
            refreshed = locker.refresh_license_for_feature_gate(settings={}, max_age_seconds=0)
        self.assertEqual(refreshed["status"], "revoked")
        self.assertFalse(locker.license_feature_allowed("privacy-safety-hub", state=refreshed))

        with (
            mock.patch.object(locker, "load_license_state", return_value=active),
            mock.patch.object(locker, "verify_license_online", side_effect=ValueError("offline")),
            mock.patch.object(locker, "save_license_state", side_effect=lambda _settings, state: state),
        ):
            cached = locker.refresh_license_for_feature_gate(settings={}, max_age_seconds=0)
        self.assertTrue(locker.license_is_active(cached))
        self.assertEqual(cached["last_error"], "offline")

    def test_signed_update_manifest_rejects_tampering_and_checks_download_hash(self):
        private_key = Ed25519PrivateKey.generate()
        public_raw = private_key.public_key().public_bytes_raw()
        public_b64 = base64.urlsafe_b64encode(public_raw).rstrip(b"=").decode("ascii")
        key_id = hashlib.sha256(public_raw).hexdigest()[:16]
        package_bytes = b"PK-signed-vaultlink-update"
        manifest = {
            "schema_version": 1,
            "product": "USB File Locker",
            "platform": "windows-source",
            "version": "9999.1",
            "minimum_supported_version": "2026.07.10",
            "published_at_utc": "2026-07-11T15:00:00Z",
            "package_filename": "VaultLink-Windows-9999.1.zip",
            "download_path": "/api/v1/updates/windows/download",
            "sha256": hashlib.sha256(package_bytes).hexdigest(),
            "size_bytes": len(package_bytes),
            "signing_key_id": key_id,
            "notes": ["Signed regression update"],
            "preserves_local_app_data": True,
        }
        manifest["signature"] = base64.urlsafe_b64encode(
            private_key.sign(locker.canonical_update_manifest_bytes(manifest))
        ).rstrip(b"=").decode("ascii")
        with (
            mock.patch.object(locker, "UPDATE_SIGNING_PUBLIC_KEY_B64", public_b64),
            mock.patch.object(locker, "UPDATE_SIGNING_KEY_ID", key_id),
        ):
            validated = locker.validate_windows_update_manifest(
                {"api_version": "test", "update": manifest}
            )
            self.assertTrue(validated["update_available"])
            self.assertEqual(validated["api_version"], "test")

            tampered = dict(manifest)
            tampered["notes"] = ["Tampered notes"]
            with self.assertRaisesRegex(ValueError, "signature did not verify"):
                locker.validate_windows_update_manifest({"update": tampered})

            response = mock.MagicMock()
            response.read.return_value = package_bytes
            context = mock.MagicMock()
            context.__enter__.return_value = response
            context.__exit__.return_value = False
            with tempfile.TemporaryDirectory(prefix="vaultlink_update_download_") as folder:
                target = Path(folder) / manifest["package_filename"]
                with mock.patch.object(locker.API_URL_OPENER, "open", return_value=context):
                    saved = locker.download_windows_update_package(
                        locker.DEFAULT_LICENSE_SERVER,
                        validated,
                        target,
                    )
                self.assertEqual(saved.read_bytes(), package_bytes)

    def test_updater_rejects_zip_slip_and_preserves_local_app_data(self):
        with tempfile.TemporaryDirectory(prefix="vaultlink_updater_safety_") as folder:
            root = Path(folder)
            bad_zip = root / "bad.zip"
            with zipfile.ZipFile(bad_zip, "w") as archive:
                archive.writestr("../outside.txt", "unsafe")
            with self.assertRaisesRegex(ValueError, "unsafe path"):
                vaultlink_updater.extract_verified_package(bad_zip, root / "bad-output")

            extracted = root / "extracted"
            target = root / "target"
            local_app_data = root / "local-app-data"
            extracted.mkdir()
            target.mkdir()
            (extracted / "usb_file_locker.py").write_text("new app", encoding="utf-8")
            (target / "usb_file_locker.py").write_text("old app", encoding="utf-8")
            (target / "settings.json").write_text("private settings", encoding="utf-8")
            with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(local_app_data)}):
                backup, count = vaultlink_updater.apply_update(extracted, target.resolve(), "9999.1")
            self.assertEqual(count, 1)
            self.assertEqual((target / "usb_file_locker.py").read_text(encoding="utf-8"), "new app")
            self.assertEqual((target / "settings.json").read_text(encoding="utf-8"), "private settings")
            self.assertEqual((backup / "usb_file_locker.py").read_text(encoding="utf-8"), "old app")

    def test_opt_in_auto_update_starts_only_after_verified_check(self):
        app = SimpleNamespace(settings={}, status=FakeVar())
        with (
            mock.patch.object(locker, "save_settings") as save,
            mock.patch.object(locker, "log_event") as log,
        ):
            locker.USBFileLocker.set_auto_install_updates(app, True)
        self.assertTrue(app.settings["auto_update_check"])
        self.assertTrue(app.settings["auto_install_signed_updates"])
        save.assert_called_once()
        log.assert_called_once()

        manifest = {
            "version": "9999.1",
            "update_available": True,
            "current_version_supported": True,
        }
        app = SimpleNamespace(
            update_results=queue.Queue(),
            update_operation="check",
            update_button=FakeButton(state="disabled"),
            latest_update_manifest=None,
            settings={"auto_install_signed_updates": True},
            status=FakeVar(),
            refresh_update_window=mock.Mock(),
            install_latest_update=mock.Mock(),
        )
        app.update_results.put(("check", manifest, "", True))
        with (
            mock.patch.object(locker, "save_settings"),
            mock.patch.object(locker, "log_event"),
            mock.patch.object(locker.messagebox, "askyesno") as ask,
        ):
            locker.USBFileLocker.poll_update_results(app)
        app.install_latest_update.assert_called_once_with(automatic=True)
        ask.assert_not_called()

    def test_updater_extracts_into_mkdtemp_directory_and_rejects_nonempty_reuse(self):
        with tempfile.TemporaryDirectory(prefix="vaultlink_updater_mkdtemp_") as folder:
            root = Path(folder)
            package = root / "update.zip"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("usb_file_locker.py", "updated app")

            extracted = Path(tempfile.mkdtemp(prefix="vaultlink-update-extracted-", dir=root))
            count = vaultlink_updater.extract_verified_package(package, extracted)
            self.assertEqual(count, 1)
            self.assertEqual((extracted / "usb_file_locker.py").read_text(encoding="utf-8"), "updated app")

            reused = root / "reused"
            reused.mkdir()
            (reused / "unexpected.txt").write_text("do not overwrite", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must be empty"):
                vaultlink_updater.extract_verified_package(package, reused)

    def test_api_url_requires_https_except_localhost(self):
        self.assertEqual(
            locker.validated_license_server_url("https://example.com/"),
            "https://example.com",
        )
        self.assertEqual(
            locker.validated_license_server_url("http://127.0.0.1:8000"),
            "http://127.0.0.1:8000",
        )
        for unsafe in (
            "http://example.com",
            "https://user:pass@example.com",
            "https://example.com/api",
            "javascript:alert(1)",
        ):
            with self.assertRaises(ValueError, msg=unsafe):
                locker.validated_license_server_url(unsafe)

    def test_license_issuer_sends_admin_token_only_as_header(self):
        with mock.patch.object(
            locker,
            "license_api_post_json",
            return_value={"ok": True, "license_key": VALID_TEST_LICENSE},
        ) as post:
            result = locker.issue_license_online(
                locker.DEFAULT_LICENSE_SERVER,
                "admin-secret",
                "family-safety",
                customer_label="Customer",
                license_note="Private renewal note",
                max_devices=2,
            )
        self.assertTrue(result["ok"])
        _server, path, payload = post.call_args.args
        self.assertEqual(path, "/api/v1/licenses/issue")
        self.assertNotIn("admin_token", payload)
        self.assertEqual(payload["license_note"], "Private renewal note")
        self.assertEqual(
            post.call_args.kwargs["extra_headers"]["X-License-Admin-Token"],
            "admin-secret",
        )

    def test_license_management_uses_admin_header_and_device_deactivation(self):
        with mock.patch.object(
            locker,
            "license_api_get_json",
            return_value={"ok": True, "items": [], "count": 0},
        ) as get_json:
            response = locker.list_admin_licenses_online(
                locker.DEFAULT_LICENSE_SERVER,
                "admin-secret",
            )
        self.assertEqual(response["count"], 0)
        self.assertEqual(get_json.call_args.args[1], "/api/v1/admin/licenses")
        self.assertEqual(
            get_json.call_args.kwargs["extra_headers"]["X-License-Admin-Token"],
            "admin-secret",
        )

        with mock.patch.object(
            locker,
            "license_api_get_json",
            return_value={"ok": True, "licenses": {}, "devices": {}},
        ) as get_json:
            dashboard = locker.get_admin_dashboard_online(
                locker.DEFAULT_LICENSE_SERVER,
                "admin-secret",
            )
        self.assertTrue(dashboard["ok"])
        self.assertEqual(get_json.call_args.args[1], "/api/v1/admin/dashboard")
        self.assertEqual(
            get_json.call_args.kwargs["extra_headers"]["X-License-Admin-Token"],
            "admin-secret",
        )

        with mock.patch.object(
            locker,
            "license_api_post_json",
            return_value={"ok": True, "revoked": True},
        ) as post:
            response = locker.revoke_license_online(
                locker.DEFAULT_LICENSE_SERVER,
                "admin-secret",
                VALID_TEST_LICENSE,
                "Customer requested removal",
            )
        self.assertTrue(response["revoked"])
        _server, path, payload = post.call_args.args
        self.assertEqual(path, "/api/v1/licenses/revoke")
        self.assertNotIn("admin_token", payload)
        self.assertEqual(payload["revocation_note"], "Customer requested removal")
        self.assertEqual(
            post.call_args.kwargs["extra_headers"]["X-License-Admin-Token"],
            "admin-secret",
        )

        with mock.patch.object(
            locker,
            "license_api_post_json",
            return_value={"ok": True, "devices_reset": 2},
        ) as post:
            response = locker.reset_license_devices_online(
                locker.DEFAULT_LICENSE_SERVER,
                "admin-secret",
                VALID_TEST_LICENSE,
            )
        self.assertEqual(response["devices_reset"], 2)
        _server, path, payload = post.call_args.args
        self.assertEqual(path, "/api/v1/licenses/reset-devices")
        self.assertEqual(payload, {"license_key": VALID_TEST_LICENSE})
        self.assertEqual(
            post.call_args.kwargs["extra_headers"]["X-License-Admin-Token"],
            "admin-secret",
        )

        state = locker.normalize_license_state(
            {
                "server_url": locker.DEFAULT_LICENSE_SERVER,
                "license_key": VALID_TEST_LICENSE,
                "receipt": "vlr1." + ("A" * 20) + "." + ("B" * 20),
            }
        )
        with mock.patch.object(
            locker,
            "license_api_post_json",
            return_value={"ok": True, "deactivated": True, "status": "deactivated"},
        ) as post:
            response = locker.deactivate_license_online(state)
        self.assertTrue(response["deactivated"])
        _server, path, payload = post.call_args.args
        self.assertEqual(path, "/api/v1/licenses/deactivate")
        self.assertEqual(payload["license_key"], VALID_TEST_LICENSE)
        self.assertTrue(payload["receipt"].startswith("vlr1."))

    def test_admin_audit_listing_uses_admin_header_only(self):
        with mock.patch.object(
            locker,
            "license_api_get_json",
            return_value={"ok": True, "items": [], "count": 0},
        ) as get_json:
            response = locker.list_admin_audit_exports_online(
                locker.DEFAULT_LICENSE_SERVER,
                "admin-secret",
            )
        self.assertEqual(response["count"], 0)
        _server, path = get_json.call_args.args
        self.assertEqual(path, "/api/v1/admin/audit-exports")
        self.assertNotIn("admin-secret", path)
        self.assertEqual(
            get_json.call_args.kwargs["extra_headers"]["X-License-Admin-Token"],
            "admin-secret",
        )

    def test_admin_audit_download_checks_identity_and_writes_json(self):
        export_id = "AUD-0123456789ABCDEF"
        raw = json.dumps({"export_id": export_id, "report": {"privacy_notice": "safe"}}).encode("utf-8")
        response = mock.MagicMock()
        response.read.return_value = raw
        context = mock.MagicMock()
        context.__enter__.return_value = response
        context.__exit__.return_value = False
        with tempfile.TemporaryDirectory(prefix="vaultlink_admin_download_") as folder:
            target = Path(folder) / "download.json"
            with mock.patch.object(locker.API_URL_OPENER, "open", return_value=context) as open_url:
                saved = locker.download_admin_audit_export_online(
                    locker.DEFAULT_LICENSE_SERVER,
                    "admin-secret",
                    export_id,
                    target,
                )
            self.assertEqual(saved, target)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["export_id"], export_id)
            request = open_url.call_args.args[0]
            self.assertNotIn("admin-secret", request.full_url)
            self.assertEqual(dict(request.header_items())["X-license-admin-token"], "admin-secret")

        with self.assertRaisesRegex(ValueError, "valid API audit export"):
            locker.download_admin_audit_export_online(
                locker.DEFAULT_LICENSE_SERVER,
                "admin-secret",
                "../../secret",
                "ignored.json",
            )

    def test_license_issuer_exposes_all_seven_ranks(self):
        self.assertEqual(
            list(license_issuer.PLAN_CHOICES.values()),
            [
                "starter",
                "home",
                "personal-plus",
                "family-safety",
                "small-office",
                "family-office",
                "pro-baseline",
            ],
        )
        self.assertEqual(set(license_issuer.PLAN_CHOICES.values()), locker.LICENSE_PLAN_IDS)
        self.assertIn("$20,000+ Pro Baseline", license_issuer.PLAN_CHOICES)

    def test_license_activation_reenables_buttons_without_overriding_usb_lock(self):
        apps_button = FakeButton(state="disabled")
        lock_button = FakeButton(state="disabled")
        owner_enable = FakeButton()
        owner_disable = FakeButton()
        owner_verify = FakeButton()
        fake = SimpleNamespace(
            owner_policy=None,
            key={"key_id": "KEY-1"},
            access_status=FakeVar(),
            key_status=FakeVar(),
            key_required_buttons=[lock_button],
            create_key_button=FakeButton(),
            owner_enable_button=owner_enable,
            owner_disable_button=owner_disable,
            owner_verify_button=owner_verify,
            license_gated_buttons={
                apps_button: "privacy-safety-hub",
                lock_button: "portable-locking",
            },
            license_state={"features": ["privacy-safety-hub", "portable-locking"]},
            busy=False,
            busy_buttons=[lock_button],
        )
        fake.active_key_matches_owner_policy = lambda: fake.key is not None

        with mock.patch.object(
            locker,
            "license_feature_allowed",
            side_effect=lambda feature_id, state=None: feature_id in state.get("features", []),
        ):
            locker.USBFileLocker.apply_access_state(fake)
            self.assertEqual(apps_button.state, "normal")
            self.assertEqual(lock_button.state, "normal")

            fake.key = None
            locker.USBFileLocker.apply_access_state(fake)
            self.assertEqual(apps_button.state, "normal")
            self.assertEqual(lock_button.state, "disabled")

            fake.license_state = {"features": []}
            locker.USBFileLocker.apply_access_state(fake)
            self.assertEqual(apps_button.state, "disabled")
            self.assertEqual(lock_button.state, "disabled")

            fake.license_state = {"features": ["privacy-safety-hub", "portable-locking"]}
            fake.key = {"key_id": "KEY-1"}
            fake.busy = True
            locker.USBFileLocker.apply_access_state(fake)
            self.assertEqual(apps_button.state, "normal")
            self.assertEqual(lock_button.state, "disabled")

    def test_audit_worker_reports_through_queue_without_tk_calls(self):
        fake = SimpleNamespace(api_export_results=queue.Queue())
        upload_response = {"export_id": "AUD-TEST"}
        with (
            mock.patch.object(locker, "upload_audit_report_online", return_value=upload_response),
            mock.patch.object(
                locker,
                "download_audit_export_online",
                return_value=Path("downloaded.json"),
            ),
        ):
            audit_log_viewer.AuditLogViewer._run_api_export(fake, {}, "chosen.json")
        success, destination, response = fake.api_export_results.get_nowait()
        self.assertTrue(success)
        self.assertEqual(destination, "downloaded.json")
        self.assertEqual(response, upload_response)

        with mock.patch.object(
            locker,
            "upload_audit_report_online",
            side_effect=ValueError("network failed"),
        ):
            audit_log_viewer.AuditLogViewer._run_api_export(fake, {}, "chosen.json")
        success, destination, response = fake.api_export_results.get_nowait()
        self.assertFalse(success)
        self.assertEqual(destination, "chosen.json")
        self.assertIn("network failed", response["message"])

    def test_cloud_audit_fingerprint_ignores_its_own_upload_events(self):
        report = {
            "defender_status": {"available": True, "ProtectedNow": True},
            "usb_file_locker_audit": {
                "valid": True,
                "events": [
                    {
                        "sequence": 1,
                        "action": "lock",
                        "result": "success",
                        "hash": "a" * 64,
                    }
                ],
            },
            "pc_safety_check_audit": {"valid": True, "events": []},
        }
        original = locker.audit_report_snapshot_fingerprint(report)
        report["usb_file_locker_audit"]["events"].append(
            {
                "sequence": 2,
                "action": "audit_api_auto_upload",
                "result": "success",
                "hash": "b" * 64,
            }
        )
        self.assertEqual(locker.audit_report_snapshot_fingerprint(report), original)
        report["usb_file_locker_audit"]["events"].append(
            {
                "sequence": 3,
                "action": "unlock",
                "result": "success",
                "hash": "c" * 64,
            }
        )
        self.assertNotEqual(locker.audit_report_snapshot_fingerprint(report), original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
