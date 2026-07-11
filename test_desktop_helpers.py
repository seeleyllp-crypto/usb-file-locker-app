import queue
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import audit_log_viewer
import usb_file_locker as locker


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
                "plan_id": "pro",
                "features": ["privacy-safety-hub"],
            }
        )
        replacement_key = "vlk1." + ("E" * 24) + "." + ("F" * 24)
        replaced = locker.license_state_with_key(original, replacement_key)
        self.assertEqual(replaced["license_key"], replacement_key)
        self.assertEqual(replaced["receipt"], "")
        self.assertEqual(replaced["features"], [])
        self.assertEqual(replaced["status"], "saved")

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
                "pro",
                customer_label="Customer",
                max_devices=2,
            )
        self.assertTrue(result["ok"])
        _server, path, payload = post.call_args.args
        self.assertEqual(path, "/api/v1/licenses/issue")
        self.assertNotIn("admin_token", payload)
        self.assertEqual(
            post.call_args.kwargs["extra_headers"]["X-License-Admin-Token"],
            "admin-secret",
        )

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
