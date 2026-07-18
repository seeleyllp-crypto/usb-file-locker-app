import ast
import base64
import hashlib
import http.client
import json
import os
import queue
import stat
import tempfile
import threading
import unittest
import urllib.parse
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import audit_log_viewer
import backup_verification_center
import build_signed_update
import customer_hub
import diagnostics_center
import download_verification_center
import incident_response_center
import license_issuer
import local_control_center
import local_data_control_center
import owner_update_lab
import recovery_drill_center
import recovery_kit_builder
import security_maintenance_center
import storage_retention_center
import support_redactor
import trust_recovery_center
import usb_file_locker as locker
import vault_health_center
import vaultlink_updater
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


VALID_TEST_LICENSE = "vlk1." + ("A" * 24) + "." + ("B" * 24)


def download_verification_fixture():
    return (
        {
            "sha256": hashlib.sha256(b"stable verified download").hexdigest(),
            "size_band": "under 1 MB",
            "extension": ".exe",
            "expected_sha256_provided": False,
            "hash_comparison": "not_provided",
            "signature": {
                "state": "valid",
                "status": "Valid",
                "signer_subject": "CN=Fixture Publisher",
            },
            "structure": {
                "detected_type": "windows_pe",
                "extension_header_match": "match",
                "pe_architecture": "x64",
                "warning_ids": ["executable_or_script_extension"],
                "archive": None,
            },
        },
        {
            "state": "no_threats",
            "scan_mode": "custom file scan with remediation disabled",
        },
    )


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

    def test_support_redactor_removes_sensitive_values_but_keeps_error_context(self):
        source = "\n".join(
            [
                "ModuleNotFoundError: No module named 'cryptography'",
                "license_key: vlk1.AAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBB",
                "receipt=vlr1.CCCCCCCCCCCCCCCC.DDDDDDDDDDDDDDDD",
                "email: alice@example.com",
                r"path: C:\Users\Alice Smith\Documents\private.txt",
                r"key: F:\master_usb_file_locker.key",
                "ip: 192.168.1.42",
                "ipv6: 2001:db8::1",
                "machine_id: 123e4567-e89b-12d3-a456-426614174000",
                "url: https://example.test/support?token=secret&email=alice@example.com",
                "phone: (312) 555-0199",
                "card: 4111 1111 1111 1111",
            ]
        )
        result = support_redactor.redact_support_text(source)
        self.assertTrue(result["changed"])
        self.assertGreaterEqual(result["total"], 10)
        self.assertIn("ModuleNotFoundError: No module named 'cryptography'", result["text"])
        self.assertIn(r"C:\Users\[USER]\Documents\private.txt", result["text"])
        for secret in (
            "vlk1.",
            "vlr1.",
            "alice@example.com",
            r"F:\master_usb_file_locker.key",
            "192.168.1.42",
            "2001:db8::1",
            "123e4567-e89b-12d3-a456-426614174000",
            "token=secret",
            "(312) 555-0199",
            "4111 1111 1111 1111",
        ):
            self.assertNotIn(secret, result["text"])

    def test_support_redactor_handles_auth_tokens_and_secret_urls(self):
        source = "\n".join(
            [
                "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
                "jwt=eyJabcdefghijk.eyJabcdefghijk.abcdefghijklmnop",
                "repo_token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
                "webhook=https://discord.com/api/webhooks/123456789/secret-token",
                '{"password":"json-secret","machine_id":"TEST-MACHINE-PRIVATE"}',
                "connection=Server=db.test;Password=connection-secret;Database=app",
            ]
        )
        result = support_redactor.redact_support_text(source)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", result["text"])
        self.assertNotIn("eyJabcdefghijk", result["text"])
        self.assertNotIn("ghp_", result["text"])
        self.assertNotIn("discord.com/api/webhooks", result["text"])
        self.assertNotIn("json-secret", result["text"])
        self.assertNotIn("TEST-MACHINE-PRIVATE", result["text"])
        self.assertNotIn("connection-secret", result["text"])
        self.assertIn("[SECRET_URL]", result["text"])

    def test_support_redactor_keeps_non_secret_versions_and_non_card_numbers(self):
        source = "VaultLink 2026.07.17.6\nBuild 1234 5678 9012 3456\nHTTP 183 file already exists"
        result = support_redactor.redact_support_text(source)
        self.assertFalse(result["changed"])
        self.assertEqual(result["text"], source)
        self.assertEqual(result["total"], 0)
        self.assertIn("No known sensitive patterns", support_redactor.redaction_summary(result))

    def test_support_redactor_enforces_bounded_input(self):
        with self.assertRaisesRegex(ValueError, "5 MB"):
            support_redactor.redact_support_text("x" * (support_redactor.MAX_INPUT_BYTES + 1))

    def test_support_redactor_audit_calls_never_include_customer_text_or_paths(self):
        source = Path(support_redactor.__file__).read_text(encoding="utf-8")
        audit_lines = [line.strip() for line in source.splitlines() if "locker.log_event(" in line]
        self.assertEqual(len(audit_lines), 9)
        for line in audit_lines:
            self.assertIn('"local"', line)
            self.assertNotIn("path_text", line)
            self.assertNotIn("source", line)
            self.assertNotIn("self.result", line)

    def test_download_verifier_normalizes_and_compares_sha256(self):
        expected = hashlib.sha256(b"download verification").hexdigest()
        self.assertEqual(
            download_verification_center.normalize_expected_sha256(f"SHA-256: {expected.upper()}"),
            expected,
        )
        self.assertEqual(download_verification_center.normalize_expected_sha256(""), "")
        with self.assertRaisesRegex(ValueError, "64 hexadecimal"):
            download_verification_center.normalize_expected_sha256("not-a-hash")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "private customer filename.exe"
            path.write_bytes(b"download verification")
            with mock.patch.object(
                download_verification_center,
                "inspect_authenticode_signature",
                return_value={
                    "state": "unsigned",
                    "status": "NotSigned",
                    "label": "Not digitally signed",
                    "status_message": "",
                    "signer_subject": "",
                    "signer_issuer": "",
                },
            ):
                result = download_verification_center.verify_download(path, expected)
            self.assertEqual(result["sha256"], expected)
            self.assertEqual(result["hash_comparison"], "match")
            receipt = download_verification_center.build_privacy_safe_receipt(result)
            serialized = json.dumps(receipt)
            self.assertNotIn(path.name, serialized)
            self.assertNotIn(str(path), serialized)
            self.assertEqual(receipt["sha256"], expected)
            self.assertEqual(receipt["defender_state"], "not_run")
            self.assertIn("does not guarantee", " ".join(receipt["limitations"]))

    def test_download_verifier_detects_file_change_and_rejects_large_or_linked_input(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.bin"
            path.write_bytes(b"fixed bytes")
            identity = download_verification_center._file_identity(path)
            changed = dict(identity, mtime_ns=identity["mtime_ns"] + 1)
            with mock.patch.object(
                download_verification_center,
                "_file_identity",
                side_effect=[identity, changed],
            ):
                with self.assertRaisesRegex(ValueError, "changed while"):
                    download_verification_center.compute_file_sha256(path)
            link = Path(folder) / "sample-link.bin"
            try:
                link.symlink_to(path)
            except OSError:
                link = None
            if link is not None:
                with self.assertRaisesRegex(ValueError, "Linked files"):
                    download_verification_center.validate_selected_file(link)
            with mock.patch.object(
                download_verification_center,
                "_file_identity",
                return_value={
                    "size": download_verification_center.MAX_FILE_BYTES + 1,
                    "mtime_ns": 1,
                    "inode": 1,
                },
            ):
                with self.assertRaisesRegex(ValueError, "8 GB"):
                    download_verification_center.validate_selected_file(path)

    def test_download_verifier_uses_argument_safe_signature_and_defender_commands(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "name with spaces and ' quote.exe"
            path.write_bytes(b"safe test file")
            identity = download_verification_center._file_identity(path)
            signature_process = SimpleNamespace(
                returncode=0,
                stdout='{"Status":"Valid","StatusMessage":"OK","Subject":"CN=Publisher","Issuer":"CN=Issuer"}\n',
                stderr="",
            )
            with mock.patch.object(
                download_verification_center,
                "_powershell_executable",
                return_value=Path("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
            ), mock.patch.object(
                download_verification_center.subprocess,
                "run",
                return_value=signature_process,
            ) as run:
                signature = download_verification_center.inspect_authenticode_signature(path)
            self.assertEqual(signature["state"], "valid")
            signature_args = run.call_args.args[0]
            self.assertIn("-EncodedCommand", signature_args)
            self.assertNotIn(str(path), signature_args)
            self.assertNotIn("shell", run.call_args.kwargs)

            defender_process = SimpleNamespace(
                returncode=0,
                stdout="Scan finished. Found no threats.",
                stderr="",
            )
            with mock.patch.object(
                download_verification_center,
                "defender_executable",
                return_value=Path("C:/ProgramData/Defender/MpCmdRun.exe"),
            ), mock.patch.object(
                download_verification_center.subprocess,
                "run",
                return_value=defender_process,
            ) as run:
                defender = download_verification_center.scan_file_with_defender(path)
            self.assertEqual(defender["state"], "no_threats")
            defender_args = run.call_args.args[0]
            self.assertIn(str(path), defender_args)
            self.assertIn("-DisableRemediation", defender_args)
            self.assertNotIn("shell", run.call_args.kwargs)
            self.assertEqual(identity, download_verification_center._file_identity(path))

    def test_download_verifier_detects_pe_architecture_and_misleading_double_extension(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "invoice.pdf.exe"
            data = bytearray(512)
            data[:2] = b"MZ"
            data[60:64] = (128).to_bytes(4, "little")
            data[128:132] = b"PE\x00\x00"
            data[132:134] = (0x8664).to_bytes(2, "little")
            path.write_bytes(data)
            structure = download_verification_center.inspect_file_structure(path)
            self.assertEqual(structure["detected_type"], "windows_pe")
            self.assertEqual(structure["pe_architecture"], "x64")
            self.assertEqual(structure["extension_header_match"], "match")
            self.assertTrue(structure["double_extension"])
            self.assertIn("misleading_double_extension", structure["warning_ids"])
            self.assertIn("executable_or_script_extension", structure["warning_ids"])
            labels = download_verification_center.warning_labels(structure["warning_ids"])
            self.assertTrue(any("combines" in label.lower() for label in labels))

    def test_download_verifier_reviews_zip_structure_without_extracting_or_exporting_names(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            archive_path = root / "review.zip"
            escaped_target = root.parent / "vaultlink-test-escape.exe"
            escaped_target.unlink(missing_ok=True)
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../vaultlink-test-escape.exe", b"harmless text fixture")
                archive.writestr("nested.zip", b"not a real nested archive")
                archive.writestr("word/vbaProject.bin", b"harmless macro-name fixture")
                link = zipfile.ZipInfo("safe-link")
                link.create_system = 3
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(link, "target")
            structure = download_verification_center.inspect_file_structure(archive_path)
            self.assertFalse(escaped_target.exists())
            self.assertEqual(structure["detected_type"], "zip_archive")
            self.assertEqual(structure["archive"]["entry_count"], 4)
            self.assertEqual(structure["archive"]["reviewed_entry_count"], 4)
            self.assertTrue(
                {
                    "archive_traversal_paths",
                    "archive_links",
                    "archive_nested_archives",
                    "archive_office_macros",
                    "archive_executable_entries",
                }.issubset(structure["warning_ids"])
            )
            result = {
                "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                "size_band": "under 1 MB",
                "extension": ".zip",
                "expected_sha256_provided": False,
                "hash_comparison": "not_provided",
                "signature": {
                    "state": "unsigned",
                    "status": "NotSigned",
                    "signer_subject": "",
                },
                "structure": structure,
            }
            receipt = download_verification_center.build_privacy_safe_receipt(result)
            serialized = json.dumps(receipt)
            self.assertNotIn("vaultlink-test-escape.exe", serialized)
            self.assertNotIn("vbaProject.bin", serialized)
            self.assertIsNone(receipt["structure"]["archive"].get("entry_names"))
            self.assertEqual(receipt["structure"]["archive"]["traversal_entry_count"], 1)

    def test_download_verifier_flags_extension_header_mismatch(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.pdf"
            path.write_text("plain text fixture", encoding="utf-8")
            structure = download_verification_center.inspect_file_structure(path)
            self.assertEqual(structure["detected_type"], "text")
            self.assertEqual(structure["extension_header_match"], "mismatch")
            self.assertIn("extension_header_mismatch", structure["warning_ids"])

    def test_download_verifier_loads_only_bounded_sanitized_receipts(self):
        result, defender = download_verification_fixture()
        receipt = download_verification_center.build_privacy_safe_receipt(result, defender)
        receipt.update(
            {
                "unknown_private_field": "PRIVATE IMPORTED TEXT",
                "filename": "private-customer-name.exe",
                "path": r"C:\Users\Private\Downloads\private-customer-name.exe",
            }
        )
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            receipt_path = root / "receipt.json"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            loaded = download_verification_center.load_verification_receipt(receipt_path)
            serialized = json.dumps(loaded)
            self.assertEqual(loaded["sha256"], result["sha256"])
            self.assertEqual(loaded["integrity_state"], "unsealed_legacy")
            self.assertEqual(
                loaded["signer_fingerprint"],
                hashlib.sha256(b"CN=Fixture Publisher").hexdigest(),
            )
            for private_value in (
                "PRIVATE IMPORTED TEXT",
                "private-customer-name.exe",
                r"C:\Users\Private",
                "CN=Fixture Publisher",
                str(receipt_path),
            ):
                self.assertNotIn(private_value, serialized)

            invalid_cases = {
                "not-json.txt": "{}",
                "malformed.json": "{",
                "wrong-schema.json": json.dumps(
                    {"schema_version": 9, "report_type": "other", "sha256": "a" * 64}
                ),
                "bad-hash.json": json.dumps(
                    {
                        "schema_version": 1,
                        "report_type": "vaultlink-download-verification",
                        "sha256": "not-a-hash",
                    }
                ),
            }
            for name, content in invalid_cases.items():
                path = root / name
                path.write_text(content, encoding="utf-8")
                with self.subTest(name=name), self.assertRaises(ValueError):
                    download_verification_center.load_verification_receipt(path)

            invalid_utf8 = root / "invalid-utf8.json"
            invalid_utf8.write_bytes(b"\xff\xfe\x00")
            with self.assertRaisesRegex(ValueError, "UTF-8 JSON"):
                download_verification_center.load_verification_receipt(invalid_utf8)

            oversized = root / "oversized.json"
            oversized.write_bytes(b"{" + (b" " * download_verification_center.MAX_RECEIPT_BYTES) + b"}")
            with self.assertRaisesRegex(ValueError, "256 KB"):
                download_verification_center.load_verification_receipt(oversized)

            linked = root / "linked.json"
            try:
                linked.symlink_to(receipt_path)
            except OSError:
                linked = None
            if linked is not None:
                with self.assertRaisesRegex(ValueError, "Linked receipt"):
                    download_verification_center.load_verification_receipt(linked)

    def test_download_verifier_seals_receipts_and_rejects_tampering(self):
        result, defender = download_verification_fixture()
        receipt = download_verification_center.build_privacy_safe_receipt(result, defender)

        def protect(value, _entropy):
            return b"TEST-DPAPI:" + bytes(byte ^ 0xA5 for byte in value)

        def unprotect(value, _entropy):
            self.assertTrue(value.startswith(b"TEST-DPAPI:"))
            return bytes(byte ^ 0xA5 for byte in value[len(b"TEST-DPAPI:"):])

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            key_path = root / "receipt-key.dpapi"
            receipt_path = root / "sealed-receipt.json"
            with (
                mock.patch.object(
                    download_verification_center,
                    "RECEIPT_SIGNING_KEY_FILE",
                    key_path,
                ),
                mock.patch.object(download_verification_center.locker, "dpapi_protect", side_effect=protect),
                mock.patch.object(download_verification_center.locker, "dpapi_unprotect", side_effect=unprotect),
            ):
                sealed = download_verification_center.seal_verification_receipt(receipt)
                receipt_path.write_text(json.dumps(sealed), encoding="utf-8")
                loaded = download_verification_center.load_verification_receipt(receipt_path)
                second = download_verification_center.seal_verification_receipt(receipt)

                self.assertEqual(sealed["schema_version"], 2)
                self.assertEqual(loaded["integrity_state"], "valid_this_profile")
                self.assertEqual(
                    sealed["integrity_seal"]["key_id"],
                    second["integrity_seal"]["key_id"],
                )
                protected_key = key_path.read_bytes()
                self.assertNotIn(unprotect(protected_key, None), protected_key)
                self.assertNotIn("private_key", json.dumps(sealed).lower())
                self.assertIn("public key", sealed["integrity_note"])
                self.assertTrue(
                    any("same local signing key" in item for item in sealed["limitations"])
                )

                tampered = json.loads(json.dumps(sealed))
                tampered["defender_state"] = "attention"
                receipt_path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "may have been edited"):
                    download_verification_center.load_verification_receipt(receipt_path)

                missing_seal = dict(sealed)
                missing_seal.pop("integrity_seal")
                receipt_path.write_text(json.dumps(missing_seal), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "missing its integrity seal"):
                    download_verification_center.load_verification_receipt(receipt_path)

                malformed = json.loads(json.dumps(sealed))
                malformed["integrity_seal"]["public_key"] = "bad"
                receipt_path.write_text(json.dumps(malformed), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "wrong length"):
                    download_verification_center.load_verification_receipt(receipt_path)

            other_key_path = root / "other-profile-key.dpapi"
            sealed_path = root / "valid-other-profile.json"
            sealed_path.write_text(json.dumps(sealed), encoding="utf-8")
            with (
                mock.patch.object(
                    download_verification_center,
                    "RECEIPT_SIGNING_KEY_FILE",
                    other_key_path,
                ),
                mock.patch.object(download_verification_center.locker, "dpapi_protect", side_effect=protect),
                mock.patch.object(download_verification_center.locker, "dpapi_unprotect", side_effect=unprotect),
            ):
                external = download_verification_center.load_verification_receipt(sealed_path)
            self.assertEqual(external["integrity_state"], "valid_other_profile")

    def test_download_verifier_receipt_inspection_exports_only_fixed_fields(self):
        result, defender = download_verification_fixture()
        receipt = download_verification_center.build_privacy_safe_receipt(result, defender)
        receipt["private_unknown"] = "PRIVATE IMPORTED TEXT"
        receipt["size_band"] = "PRIVATE SIZE TEXT"
        receipt["extension"] = ".privateextension"
        receipt["signer_subject"] = "CN=PRIVATE SIGNER TEXT"
        receipt["structure"]["detected_type"] = "PRIVATE DETECTED TYPE"
        receipt["structure"]["pe_architecture"] = "PRIVATE ARCHITECTURE"
        normalized = download_verification_center.normalize_verification_receipt(receipt)
        report = download_verification_center.build_receipt_inspection_report(normalized)
        summary = download_verification_center.receipt_inspection_summary(report)
        serialized = json.dumps(report)

        self.assertEqual(report["integrity_state"], "unsealed_legacy")
        self.assertEqual(report["size_band"], "unknown")
        self.assertEqual(report["extension_category"], "other")
        self.assertEqual(report["structure"]["detected_type"], "unknown")
        self.assertEqual(report["structure"]["pe_architecture"], "unknown")
        self.assertIn(result["sha256"], summary)
        for private_value in (
            "PRIVATE IMPORTED TEXT",
            "PRIVATE SIZE TEXT",
            ".privateextension",
            "PRIVATE SIGNER TEXT",
            "PRIVATE DETECTED TYPE",
            "PRIVATE ARCHITECTURE",
            "signer_fingerprint",
            "public_key",
        ):
            self.assertNotIn(private_value, serialized)
            self.assertNotIn(private_value, summary)
        with self.assertRaisesRegex(ValueError, "integrity state"):
            download_verification_center.build_receipt_inspection_report(
                {**normalized, "integrity_state": "invented"}
            )

    def test_download_verifier_folder_audit_is_bounded_aggregate_and_non_recursive(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in (
                "private-local-receipt.json",
                "private-external-receipt.JSON",
                "private-legacy-receipt.json",
                "private-invalid-receipt.json",
            ):
                (root / name).write_text("{}", encoding="utf-8")
            oversized = root / "private-oversized-receipt.json"
            oversized.write_bytes(
                b"{" + (b" " * download_verification_center.MAX_RECEIPT_BYTES) + b"}"
            )
            (root / "private-note.txt").write_text("not a receipt", encoding="utf-8")
            subfolder = root / "private-subfolder"
            subfolder.mkdir()
            (subfolder / "must-not-be-inspected.json").write_text("{}", encoding="utf-8")
            linked = root / "private-linked-receipt.json"
            try:
                linked.symlink_to(root / "private-local-receipt.json")
            except OSError:
                linked = None

            def fake_load(path):
                name = Path(path).name.lower()
                if "invalid" in name:
                    raise ValueError("PRIVATE VALIDATION ERROR")
                if "external" in name:
                    return {"integrity_state": "valid_other_profile"}
                if "legacy" in name:
                    return {"integrity_state": "unsealed_legacy"}
                return {"integrity_state": "valid_this_profile"}

            with mock.patch.object(
                download_verification_center,
                "load_verification_receipt",
                side_effect=fake_load,
            ):
                report, local_details = (
                    download_verification_center.audit_receipt_folder_with_local_details(
                        root
                    )
                )
            counts = report["counts"]
            self.assertEqual(counts["json_candidates"], 5)
            self.assertEqual(counts["receipts_inspected"], 3)
            self.assertEqual(counts["valid_this_profile"], 1)
            self.assertEqual(counts["valid_other_profile"], 1)
            self.assertEqual(counts["unsealed_legacy"], 1)
            self.assertEqual(counts["invalid_or_tampered"], 1)
            self.assertEqual(counts["oversized_receipts_skipped"], 1)
            self.assertEqual(counts["other_entries_skipped"], 2)
            self.assertEqual(
                counts["links_or_junctions_skipped"],
                1 if linked is not None else 0,
            )
            self.assertEqual(report["scope"], "selected_folder_top_level_only")
            self.assertFalse(report["entry_limit_reached"])
            self.assertFalse(report["candidate_limit_reached"])
            self.assertFalse(report["byte_limit_reached"])
            local_map = {
                item["name"]: item["status"]
                for item in local_details
            }
            self.assertEqual(
                local_map["private-local-receipt.json"],
                "valid_this_profile",
            )
            self.assertEqual(
                local_map["private-external-receipt.JSON"],
                "valid_other_profile",
            )
            self.assertEqual(
                local_map["private-legacy-receipt.json"],
                "unsealed_legacy",
            )
            self.assertEqual(
                local_map["private-invalid-receipt.json"],
                "invalid_or_tampered",
            )
            self.assertEqual(
                local_map["private-oversized-receipt.json"],
                "oversized_skipped",
            )
            self.assertEqual(
                local_map["private-subfolder"],
                "subfolder_skipped",
            )
            self.assertEqual(
                download_verification_center._local_receipt_display_name(
                    "private\r\nreceipt.json"
                ),
                "private  receipt.json",
            )
            all_rows = download_verification_center.filter_receipt_folder_local_details(
                local_details
            )
            self.assertEqual(len(all_rows), len(local_details))
            self.assertEqual(
                [
                    item["name"]
                    for item in download_verification_center.filter_receipt_folder_local_details(
                        local_details,
                        query="EXTERNAL",
                    )
                ],
                ["private-external-receipt.JSON"],
            )
            self.assertEqual(
                {
                    item["status"]
                    for item in download_verification_center.filter_receipt_folder_local_details(
                        local_details,
                        category="problems",
                    )
                },
                {"invalid_or_tampered"},
            )
            self.assertEqual(
                {
                    item["status"]
                    for item in download_verification_center.filter_receipt_folder_local_details(
                        local_details,
                        category="valid",
                    )
                },
                {"valid_other_profile", "valid_this_profile"},
            )
            self.assertEqual(
                [
                    item["status"]
                    for item in download_verification_center.filter_receipt_folder_local_details(
                        local_details,
                        category="legacy",
                    )
                ],
                ["unsealed_legacy"],
            )
            skipped_statuses = {
                item["status"]
                for item in download_verification_center.filter_receipt_folder_local_details(
                    local_details,
                    category="skipped",
                )
            }
            self.assertTrue(
                {
                    "non_json_skipped",
                    "oversized_skipped",
                    "subfolder_skipped",
                }.issubset(skipped_statuses)
            )
            needs_review_rows = (
                download_verification_center.filter_receipt_folder_local_details(
                    local_details,
                    category="needs_review",
                )
            )
            self.assertTrue(needs_review_rows)
            self.assertTrue(
                all(
                    item["status"]
                    in download_verification_center.FOLDER_REVIEW_NEEDS_REVIEW_STATUSES
                    for item in needs_review_rows
                )
            )
            self.assertNotIn(
                "valid_this_profile",
                {item["status"] for item in needs_review_rows},
            )
            result_sorted = (
                download_verification_center.filter_receipt_folder_local_details(
                    local_details,
                    sort_mode="result",
                )
            )
            self.assertEqual(
                [
                    (
                        download_verification_center.FOLDER_REVIEW_STATUS_LABELS[
                            item["status"]
                        ].casefold(),
                        item["name"].casefold(),
                    )
                    for item in result_sorted
                ],
                sorted(
                    (
                        download_verification_center.FOLDER_REVIEW_STATUS_LABELS[
                            item["status"]
                        ].casefold(),
                        item["name"].casefold(),
                    )
                    for item in result_sorted
                ),
            )
            priority_sorted = (
                download_verification_center.filter_receipt_folder_local_details(
                    local_details,
                    sort_mode="priority",
                )
            )
            priority_keys = [
                (
                    download_verification_center.FOLDER_REVIEW_TRIAGE_PRIORITY[
                        download_verification_center.receipt_folder_review_triage(
                            item["status"]
                        )["level"]
                    ],
                    item["name"].casefold(),
                )
                for item in priority_sorted
            ]
            self.assertEqual(priority_keys, sorted(priority_keys))
            self.assertEqual(
                set(download_verification_center.FOLDER_REVIEW_STATUS_LABELS),
                set(download_verification_center.FOLDER_REVIEW_TRIAGE),
            )
            for status in download_verification_center.FOLDER_REVIEW_STATUS_LABELS:
                guidance = (
                    download_verification_center.receipt_folder_review_triage(status)
                )
                self.assertIn(
                    guidance["level"],
                    download_verification_center.FOLDER_REVIEW_TRIAGE_PRIORITY,
                )
                self.assertTrue(guidance["level_label"])
                self.assertTrue(guidance["meaning"])
                self.assertTrue(guidance["next_action"])
            critical_guidance = (
                download_verification_center.receipt_folder_review_triage(
                    "invalid_or_tampered"
                )
            )
            self.assertEqual(critical_guidance["level"], "critical")
            self.assertIn("Do not rely", critical_guidance["next_action"])
            self.assertNotIn("private-invalid-receipt", json.dumps(critical_guidance))
            with self.assertRaisesRegex(ValueError, "result"):
                download_verification_center.receipt_folder_review_triage(
                    "private-unknown-result"
                )
            with self.assertRaisesRegex(ValueError, "filter"):
                download_verification_center.filter_receipt_folder_local_details(
                    local_details,
                    category="private-unknown-filter",
                )
            with self.assertRaisesRegex(ValueError, "sort mode"):
                download_verification_center.filter_receipt_folder_local_details(
                    local_details,
                    sort_mode="private-unknown-sort",
                )
            serialized = json.dumps(report)
            summary = download_verification_center.receipt_folder_audit_summary(report)
            for private_value in (
                str(root),
                "private-local-receipt.json",
                "private-external-receipt",
                "private-subfolder",
                "must-not-be-inspected",
                "PRIVATE VALIDATION ERROR",
            ):
                self.assertNotIn(private_value, serialized)
                self.assertNotIn(private_value, summary)

            capped = root / "capped"
            capped.mkdir()
            for index in range(3):
                (capped / f"receipt-{index}.json").write_text("{}", encoding="utf-8")
            with (
                mock.patch.object(
                    download_verification_center,
                    "MAX_RECEIPT_FOLDER_JSON_FILES",
                    2,
                ),
                mock.patch.object(
                    download_verification_center,
                    "load_verification_receipt",
                    return_value={"integrity_state": "unsealed_legacy"},
                ),
            ):
                capped_report, capped_details = (
                    download_verification_center.audit_receipt_folder_with_local_details(
                        capped
                    )
                )
            self.assertEqual(capped_report["counts"]["json_candidates"], 2)
            self.assertEqual(capped_report["counts"]["receipts_inspected"], 2)
            self.assertTrue(capped_report["candidate_limit_reached"])
            limit_rows = (
                download_verification_center.filter_receipt_folder_local_details(
                    capped_details,
                    category="limits",
                )
            )
            self.assertEqual(len(limit_rows), 1)
            self.assertEqual(
                limit_rows[0]["status"],
                "candidate_limit_not_inspected",
            )

            receipt = download_verification_center.build_privacy_safe_receipt(
                *download_verification_fixture()
            )
            receipt_path = root / "changed-receipt.json"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            identity = download_verification_center._file_identity(receipt_path)
            changed = dict(identity, mtime_ns=identity["mtime_ns"] + 1)
            with mock.patch.object(
                download_verification_center,
                "_file_identity",
                side_effect=[identity, changed],
            ):
                with self.assertRaisesRegex(ValueError, "changed while"):
                    download_verification_center.load_verification_receipt(receipt_path)

    def test_download_verifier_compares_only_fixed_receipt_signals(self):
        result, defender = download_verification_fixture()
        prior = download_verification_center.normalize_verification_receipt(
            download_verification_center.build_privacy_safe_receipt(result, defender)
        )
        exact = download_verification_center.compare_verification_receipt(
            result,
            defender,
            prior,
        )
        self.assertEqual(exact["verdict"], "exact_fixed_field_match")
        self.assertEqual(exact["change_count"], 0)
        self.assertTrue(exact["same_sha256"])

        changed_bytes = dict(result, sha256=hashlib.sha256(b"different bytes").hexdigest())
        different = download_verification_center.compare_verification_receipt(
            changed_bytes,
            defender,
            prior,
        )
        self.assertEqual(different["verdict"], "different_file_bytes")
        self.assertIn("sha256_changed", different["change_ids"])

        changed_signals = json.loads(json.dumps(result))
        changed_signals["signature"]["state"] = "unsigned"
        changed_signals["signature"]["signer_subject"] = ""
        changed_signals["structure"]["warning_ids"] = []
        signal_change = download_verification_center.compare_verification_receipt(
            changed_signals,
            {"state": "attention"},
            prior,
        )
        self.assertEqual(signal_change["verdict"], "same_bytes_signals_changed")
        self.assertTrue(
            {
                "signature_state_changed",
                "signer_changed",
                "warning_ids_changed",
                "defender_state_changed",
            }.issubset(signal_change["change_ids"])
        )
        exported = json.dumps(signal_change)
        self.assertNotIn("Fixture Publisher", exported)
        self.assertNotIn("signer_subject", exported)
        self.assertNotIn("private-customer-name.exe", exported)
        self.assertNotIn(r"C:\Users\Private", exported)
        self.assertIn("not a public code-signing certificate", signal_change["limitations"][0])
        self.assertEqual(signal_change["prior_receipt_integrity"], "unsealed_legacy")
        self.assertIn("VaultLink Verification Receipt Comparison", download_verification_center.verification_summary(result, defender, exact))

    def test_download_verifier_receipt_comparison_ui_and_audit_are_privacy_safe(self):
        source = Path(download_verification_center.__file__).read_text(encoding="utf-8")
        self.assertIn('text="EXPORT SEALED RECEIPT"', source)
        self.assertIn('text="INSPECT RECEIPT"', source)
        self.assertIn('text="COPY RECEIPT CHECK"', source)
        self.assertIn('text="AUDIT RECEIPT FOLDER"', source)
        self.assertIn('text="EXPORT FOLDER AUDIT"', source)
        self.assertIn('text="VIEW LOCAL REVIEW"', source)
        self.assertIn('text="CLEAR LOCAL LIST"', source)
        self.assertIn('text="SEARCH RECEIPT FILENAMES"', source)
        self.assertIn('"Needs review": "needs_review"', source)
        self.assertIn('"Problems only": "problems"', source)
        self.assertIn('"Valid seals": "valid"', source)
        self.assertIn('"Legacy receipts": "legacy"', source)
        self.assertIn('"Skipped entries": "skipped"', source)
        self.assertIn('"Limit-stopped entries": "limits"', source)
        self.assertIn('"Priority then filename": "priority"', source)
        self.assertIn('text="CLEAR FILTERS"', source)
        self.assertIn('text="NEXT REVIEW ITEM"', source)
        self.assertIn('table.heading("priority", text="Priority")', source)
        self.assertIn('text="COMPARE PRIOR RECEIPT"', source)
        self.assertIn('text="EXPORT COMPARISON"', source)
        self.assertIn('state="disabled"', source)
        self.assertIn('("RECEIPT INSPECTION", self.inspection_var)', source)
        self.assertIn('("RECEIPT COMPARISON", self.comparison_var)', source)
        audit_lines = [line.strip() for line in source.splitlines() if "locker.log_event(" in line]
        self.assertEqual(len(audit_lines), 21)
        for line in audit_lines:
            self.assertNotIn("path_text", line)
            self.assertNotIn("prior", line)
            self.assertNotIn("self.comparison_result", line)
            self.assertNotIn("self.selected_path", line)
            self.assertNotIn("search_var", line)
            self.assertNotIn("filter_var", line)
            self.assertNotIn("sort_var", line)
            self.assertNotIn("folder_audit_local_details", line)
            self.assertNotIn("item_status", line)
            self.assertNotIn("triage_", line)

    def test_customer_workspace_uses_composite_api_without_receipt_or_machine_identity(self):
        state = locker.normalize_license_state(
            {
                "license_key": VALID_TEST_LICENSE,
                "receipt": "PRIVATE-RECEIPT-MUST-NOT-BE-SENT",
                "server_url": "https://api.example.test",
            }
        )
        response = {
            "ok": True,
            "workspace_schema_version": 4,
            "summary": {"status": "active", "plan": {"rank": 3, "name": "Personal Plus"}},
            "action_center": {"count": 9, "items": []},
        }
        with mock.patch.object(locker, "license_api_post_json", return_value=response) as post:
            result = locker.load_customer_workspace_online(state, "2026.07.14.6")
        self.assertIs(result, response)
        server_url, path, payload = post.call_args.args
        self.assertEqual(server_url, "https://api.example.test")
        self.assertEqual(path, "/api/v1/licenses/customer-workspace")
        self.assertEqual(payload["license_key"], VALID_TEST_LICENSE)
        self.assertEqual(payload["app_version"], "2026.07.14.6")
        serialized_payload = json.dumps(payload)
        self.assertNotIn("PRIVATE-RECEIPT-MUST-NOT-BE-SENT", serialized_payload)
        self.assertNotIn("machine_id", payload)
        self.assertNotIn("machine_name", payload)

        with mock.patch.object(
            locker,
            "license_api_post_json",
            return_value={"workspace_schema_version": 5, "summary": {}},
        ):
            with self.assertRaisesRegex(ValueError, "unsupported customer workspace"):
                locker.load_customer_workspace_online(state)

    def test_customer_care_export_is_fixed_field_and_private(self):
        payload = {
            "workspace_schema_version": 4,
            "customer_snapshot": {"workspace_score": 82, "private": "PRIVATE-NESTED-SNAPSHOT"},
            "workspace_score": {"score": 82, "maximum": 100, "private": "PRIVATE-NESTED-SCORE"},
            "next_best_action": {"id": "update", "title": "Check signed release", "license_key": "PRIVATE-NESTED-KEY"},
            "action_center": {
                "items": [
                    {"id": "update", "title": "Check signed release", "secret": "PRIVATE-NESTED-ACTION"},
                    {"id": "backup", "title": "Review backup"},
                ]
            },
            "readiness_lanes": [{"id": "protection", "percent": 80, "customer": "PRIVATE-NESTED-CUSTOMER"}],
            "weekly_routine": {"items": [{"id": "monday-status", "secret": "PRIVATE-NESTED-ROUTINE"}]},
            "journey_map": {
                "server_tracks_completion": False,
                "stages": [{"id": "account", "title": "Account", "secret": "PRIVATE-NESTED-JOURNEY"}],
            },
            "seat_planner": {"active": 1, "maximum": 3, "available": 2, "device_name": "PRIVATE-DEVICE"},
            "support_readiness": {
                "ready_count": 1,
                "total": 1,
                "items": [{"id": "license", "ready": True, "note": "PRIVATE-NESTED-SUPPORT"}],
            },
            "ninety_day_plan": {
                "phases": [
                    {
                        "id": "now",
                        "items": [{"id": "update", "title": "Update", "path": "PRIVATE-NESTED-PLAN"}],
                    }
                ]
            },
            "change_digest": {"api_version": "0.41.0", "owner_note": "PRIVATE-NESTED-DIGEST"},
            "customer_glossary": [{"id": "locked-file", "term": "Locked file", "private": "PRIVATE-NESTED-GLOSSARY"}],
            "entitlement_categories": [{"category": "Recovery", "count": 2, "private": "PRIVATE-NESTED-BENEFIT"}],
            "help_center": {"items": [{"id": "update", "note": "PRIVATE-NESTED-NOTE"}]},
            "privacy_guarantees": ["No PC control."],
            "license_key": "PRIVATE-LICENSE-KEY",
            "customer_identity": "PRIVATE-CUSTOMER",
            "free_text": "PRIVATE-SUPPORT-TEXT",
        }
        report = customer_hub.customer_care_export(payload, {"update", "not-a-current-action"})
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["workspace_schema_version"], 4)
        self.assertEqual(report["completed_action_ids"], ["update"])
        self.assertEqual(report["seat_planner"]["available"], 2)
        self.assertFalse(report["journey_map"]["server_tracks_completion"])
        self.assertEqual(len(report["support_readiness"]["items"]), 1)
        self.assertEqual(len(report["ninety_day_plan"]["phases"]), 1)
        self.assertEqual(len(report["customer_glossary"]), 1)
        serialized = json.dumps(report)
        for private_value in (
            "PRIVATE-LICENSE-KEY",
            "PRIVATE-CUSTOMER",
            "PRIVATE-SUPPORT-TEXT",
            "PRIVATE-NESTED-SNAPSHOT",
            "PRIVATE-NESTED-SCORE",
            "PRIVATE-NESTED-KEY",
            "PRIVATE-NESTED-CUSTOMER",
            "PRIVATE-NESTED-ROUTINE",
            "PRIVATE-NESTED-ACTION",
            "PRIVATE-NESTED-JOURNEY",
            "PRIVATE-DEVICE",
            "PRIVATE-NESTED-SUPPORT",
            "PRIVATE-NESTED-PLAN",
            "PRIVATE-NESTED-DIGEST",
            "PRIVATE-NESTED-GLOSSARY",
            "PRIVATE-NESTED-BENEFIT",
            "PRIVATE-NESTED-NOTE",
        ):
            self.assertNotIn(private_value, serialized)

    def test_customer_progress_is_bounded_private_and_local(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            progress_path = Path(temp_dir) / "progress.json"
            saved = customer_hub.save_customer_progress(
                ["update", "backup", "update", "../private", "UPPERCASE", "a" * 81],
                progress_path,
            )
            self.assertEqual(saved["completed_action_ids"], ["backup", "update"])
            self.assertTrue(saved["updated_at_utc"])
            raw = progress_path.read_text(encoding="utf-8")
            for private_field in ("license_key", "machine_id", "path", "filename", "pin", "usb_secret"):
                self.assertNotIn(private_field, raw.lower())
            self.assertEqual(customer_hub.load_customer_progress(progress_path), saved)

    def test_next_unfinished_customer_action_respects_local_progress(self):
        workspace = {
            "action_center": {
                "items": [
                    {"id": "first", "title": "First"},
                    {"id": "second", "title": "Second"},
                ]
            },
            "next_best_action": {"id": "fallback", "title": "Fallback"},
        }
        self.assertEqual(customer_hub.next_unfinished_action(workspace, set())["id"], "first")
        self.assertEqual(customer_hub.next_unfinished_action(workspace, {"first"})["id"], "second")
        self.assertEqual(customer_hub.next_unfinished_action(workspace, {"first", "second"}), {})

    def test_customer_hub_links_to_public_guides_without_credentials(self):
        source = Path(customer_hub.__file__).read_text(encoding="utf-8")
        self.assertIn('("DECISION WIZARD", "/decision")', source)
        self.assertIn('("ANSWERS", "/QNA")', source)
        self.assertNotIn('"/decision?"', source)
        self.assertNotIn('"/QNA?"', source)

    def test_every_launcher_bootstraps_dependencies(self):
        app_dir = Path(__file__).resolve().parent
        launchers = sorted(app_dir.glob("Run *.bat"))
        self.assertEqual(len(launchers), 26)
        for launcher in launchers:
            with self.subTest(launcher=launcher.name):
                content = launcher.read_text(encoding="utf-8")
                self.assertIn('call "%~dp0Ensure Dependencies.cmd"', content)
                self.assertIn("%PYTHON_CMD%", content)
        self.assertEqual(len(build_signed_update.PACKAGE_FILES), 56)
        self.assertEqual(len(set(build_signed_update.PACKAGE_FILES)), 56)
        self.assertIn("security_maintenance_center.py", build_signed_update.PACKAGE_FILES)
        self.assertIn("Run Security Maintenance Center.bat", build_signed_update.PACKAGE_FILES)
        self.assertIn("storage_retention_center.py", build_signed_update.PACKAGE_FILES)
        self.assertIn("Run Storage & Retention Center.bat", build_signed_update.PACKAGE_FILES)
        self.assertIn("local_data_control_center.py", build_signed_update.PACKAGE_FILES)
        self.assertIn("Run Local Data Control Center.bat", build_signed_update.PACKAGE_FILES)
        self.assertIn("recovery_kit_builder.py", build_signed_update.PACKAGE_FILES)
        self.assertIn("Run Recovery Kit Builder.bat", build_signed_update.PACKAGE_FILES)
        self.assertIn("backup_verification_center.py", build_signed_update.PACKAGE_FILES)
        self.assertIn("Run Backup Verification Center.bat", build_signed_update.PACKAGE_FILES)
        self.assertIn("customer_hub.py", build_signed_update.PACKAGE_FILES)
        self.assertIn("Run Customer Hub.bat", build_signed_update.PACKAGE_FILES)
        self.assertIn("diagnostics_center.py", build_signed_update.PACKAGE_FILES)
        self.assertIn("Run Diagnostics Center.bat", build_signed_update.PACKAGE_FILES)
        self.assertIn("support_redactor.py", build_signed_update.PACKAGE_FILES)
        self.assertIn("Run Support Redactor.bat", build_signed_update.PACKAGE_FILES)
        self.assertIn("download_verification_center.py", build_signed_update.PACKAGE_FILES)
        self.assertIn("Run Download Verification Center.bat", build_signed_update.PACKAGE_FILES)
        self.assertIn("incident_response_center.py", build_signed_update.PACKAGE_FILES)
        self.assertIn("Run Incident Response Center.bat", build_signed_update.PACKAGE_FILES)
        self.assertIn("recovery_drill_center.py", build_signed_update.PACKAGE_FILES)
        self.assertIn("Run Recovery Drill Center.bat", build_signed_update.PACKAGE_FILES)
        self.assertIn("vault_health_center.py", build_signed_update.PACKAGE_FILES)
        self.assertIn("Run Vault Health Center.bat", build_signed_update.PACKAGE_FILES)
        self.assertIn("local_control_center.py", build_signed_update.PACKAGE_FILES)
        self.assertIn("Run Local Control Center.bat", build_signed_update.PACKAGE_FILES)
        self.assertIn("trust_recovery_center.py", build_signed_update.PACKAGE_FILES)
        self.assertIn("Run Trust & Recovery Center.bat", build_signed_update.PACKAGE_FILES)
        self.assertNotIn("owner_update_lab.py", build_signed_update.PACKAGE_FILES)
        self.assertNotIn("Run Owner Update Lab.bat", build_signed_update.PACKAGE_FILES)
        self.assertTrue(issubclass(customer_hub.CustomerHub, customer_hub.tk.Tk))
        self.assertTrue(issubclass(backup_verification_center.BackupVerificationCenter, backup_verification_center.tk.Tk))
        self.assertTrue(issubclass(diagnostics_center.DiagnosticsCenter, diagnostics_center.tk.Tk))
        self.assertTrue(issubclass(support_redactor.SupportRedactor, support_redactor.tk.Tk))
        self.assertTrue(
            issubclass(
                download_verification_center.DownloadVerificationCenter,
                download_verification_center.tk.Tk,
            )
        )
        self.assertTrue(issubclass(incident_response_center.IncidentResponseCenter, incident_response_center.tk.Tk))
        self.assertTrue(issubclass(recovery_drill_center.RecoveryDrillCenter, recovery_drill_center.tk.Tk))
        self.assertTrue(issubclass(recovery_kit_builder.RecoveryKitBuilder, recovery_kit_builder.tk.Tk))
        self.assertTrue(issubclass(vault_health_center.VaultHealthCenter, vault_health_center.tk.Tk))
        self.assertTrue(issubclass(local_control_center.LocalControlCenter, local_control_center.tk.Tk))
        self.assertTrue(issubclass(local_data_control_center.LocalDataControlCenter, local_data_control_center.tk.Tk))
        self.assertTrue(issubclass(security_maintenance_center.SecurityMaintenanceCenter, security_maintenance_center.tk.Tk))
        self.assertTrue(issubclass(storage_retention_center.StorageRetentionCenter, storage_retention_center.tk.Tk))
        self.assertTrue(issubclass(trust_recovery_center.TrustRecoveryCenter, trust_recovery_center.tk.Tk))
        hub_source = (app_dir / "privacy_safety_hub.py").read_text(encoding="utf-8")
        self.assertEqual(hub_source.count("self.app_card(apps,"), 34)
        self.assertEqual(len(local_control_center.CONTROL_ACTIONS), 23)
        self.assertIn("security_maintenance", local_control_center.CONTROL_ACTIONS)
        self.assertIn("storage_retention", local_control_center.CONTROL_ACTIONS)
        self.assertIn("data_control", local_control_center.CONTROL_ACTIONS)

    def test_local_control_pin_verifier_is_salted_and_never_contains_the_pin(self):
        pin = "Safe-Control-4291"
        first = local_control_center.create_pin_record(pin, b"A" * 16)
        second = local_control_center.create_pin_record(pin, b"B" * 16)
        self.assertTrue(local_control_center.verify_pin_record(pin, first))
        self.assertFalse(local_control_center.verify_pin_record("wrong-pin", first))
        self.assertNotEqual(first["digest"], second["digest"])
        self.assertNotIn(pin, json.dumps(first))
        with self.assertRaisesRegex(ValueError, "6 to 64"):
            local_control_center.create_pin_record("12345")
        with self.assertRaisesRegex(ValueError, "less repetitive"):
            local_control_center.create_pin_record("111111")

    def test_local_control_is_loopback_only_and_launches_only_allowlisted_apps(self):
        self.assertEqual(local_control_center.LOCAL_HOST, "127.0.0.1")
        self.assertEqual(local_control_center.SESSION_SECONDS, 15 * 60)
        expected_scripts = {
            None,
            "customer_hub.py",
            "diagnostics_center.py",
            "incident_response_center.py",
            "recovery_drill_center.py",
            "backup_verification_center.py",
            "recovery_kit_builder.py",
            "security_maintenance_center.py",
            "storage_retention_center.py",
            "local_data_control_center.py",
            "trust_recovery_center.py",
            "vault_health_center.py",
            "locked_file_browser.py",
            "key_inspector.py",
            "personal_vault_pad.py",
            "perm_unlock_workbench.py",
            "audit_log_viewer.py",
            "quick_lock_note.py",
            "privacy_safety_hub.py",
            "text_log_processor.py",
            "support_redactor.py",
            "download_verification_center.py",
            "global_breach_guard.py",
        }
        self.assertEqual(len(local_control_center.CONTROL_ACTIONS), 23)
        self.assertEqual(
            {action["script"] for action in local_control_center.CONTROL_ACTIONS.values()},
            expected_scripts,
        )
        for action in local_control_center.CONTROL_ACTIONS.values():
            self.assertTrue(action["label"])
            self.assertTrue(action["category"])
            self.assertTrue(action["summary"])
        with mock.patch.object(locker, "launch_main_app_process") as main_launch, mock.patch.object(
            locker, "launch_companion_script"
        ) as companion_launch:
            self.assertEqual(local_control_center.launch_control_action("main_locker"), "Main Locker")
            main_launch.assert_called_once_with()
            self.assertEqual(local_control_center.launch_control_action("key_inspector"), "Key Inspector")
            companion_launch.assert_called_once_with("key_inspector.py")
        with self.assertRaisesRegex(ValueError, "not allowed"):
            local_control_center.launch_control_action("arbitrary-command")
        state = local_control_center.ControlState("D:/private/master.key", "PRIVATE-KEY-ID")
        state.session_token = "session"
        state.session_csrf = "csrf"
        state.session_expires_at = local_control_center.time.monotonic() + 60
        with mock.patch.object(state, "usb_status", return_value=(False, "The selected USB key is missing or no longer matches.")):
            with self.assertRaises(PermissionError) as raised:
                state.run_action("session", "csrf", "main_locker")
        self.assertNotIn("D:/private", str(raised.exception))
        self.assertNotIn("PRIVATE-KEY-ID", str(raised.exception))
        self.assertEqual(state.launch_history, [])

        state.session_token = "session"
        state.session_csrf = "csrf"
        state.session_expires_at = local_control_center.time.monotonic() + 60
        with mock.patch.object(state, "usb_status", return_value=(True, "USB key verified locally.")), mock.patch.object(
            local_control_center, "launch_control_action", return_value="Main Locker"
        ):
            self.assertEqual(state.run_action("session", "csrf", "main_locker"), "Main Locker")
            state.extend_session("session", "csrf")
        self.assertEqual(len(state.launch_history), 1)
        self.assertEqual(state.launch_history[0]["action_id"], "main_locker")
        self.assertEqual(state.launch_history[0]["result"], "ok")
        self.assertNotIn("D:/private", json.dumps(state.launch_history))
        for _index in range(25):
            state.record_launch("main_locker", "ok")
        self.assertEqual(len(state.launch_history), 20)
        snapshot = state.dashboard_snapshot()
        self.assertEqual(snapshot["successful_launches"], 26)
        self.assertEqual(snapshot["failed_launches"], 0)
        self.assertEqual(sum(snapshot["category_counts"].values()), 23)
        self.assertEqual(local_control_center.normalized_category_filter("recovery"), "Recovery")
        self.assertEqual(local_control_center.normalized_category_filter("unknown-category"), "")
        state.session_token = "PRIVATE-SESSION-TOKEN-8842"
        state.session_csrf = "PRIVATE-CSRF-TOKEN-8842"
        with mock.patch.object(state, "usb_status", return_value=(True, "USB key verified locally.")):
            safe_report = state.safe_report("PRIVATE-SESSION-TOKEN-8842", "PRIVATE-CSRF-TOKEN-8842")
        self.assertEqual(safe_report["session"]["apps_total"], 23)
        self.assertEqual(safe_report["session"]["successful_launches"], 26)
        safe_report_text = json.dumps(safe_report)
        for forbidden in ("D:/private", "PRIVATE-KEY-ID", "PRIVATE-SESSION-TOKEN-8842", "PRIVATE-CSRF-TOKEN-8842"):
            self.assertNotIn(forbidden, safe_report_text)
        state.clear_history("PRIVATE-SESSION-TOKEN-8842", "PRIVATE-CSRF-TOKEN-8842")
        self.assertEqual(state.launch_history, [])
        self.assertEqual(state.dashboard_snapshot()["total_launches"], 0)
        self.assertEqual(
            local_control_center.safe_dashboard_text("D:/private/customer/file.txt"),
            "Hidden by the local control privacy rule",
        )
        self.assertEqual(
            local_control_center.safe_dashboard_text(VALID_TEST_LICENSE),
            "Hidden by the local control privacy rule",
        )

    def test_local_control_http_boundary_hides_key_data_and_sets_browser_guards(self):
        class DummyState:
            login_csrf = "LOGIN-CSRF"
            session_token = ""
            session_csrf = "SESSION-CSRF"
            extended = False
            history_cleared = False

            def usb_status(self):
                return True, "USB key verified locally."

            def is_authorized(self, token):
                return bool(self.session_token and token == self.session_token)

            def authenticate(self, pin, csrf):
                if pin == "Control-2468" and csrf == self.login_csrf:
                    self.session_token = "SESSION-TOKEN"
                    return True, "Local control session unlocked."
                return False, "The local control PIN was not accepted."

            def lock_session(self):
                self.session_token = ""

            def run_action(self, _token, _csrf, _action):
                return "Main Locker"

            def extend_session(self, _token, _csrf):
                self.extended = True

            def clear_history(self, _token, _csrf):
                self.history_cleared = True

            def safe_report(self, _token, _csrf):
                return {
                    "schema_version": 1,
                    "report_type": "VaultLink Local Control Privacy-Safe Report",
                    "session": {"apps_total": len(local_control_center.CONTROL_ACTIONS)},
                    "privacy_notice": "No keys, PINs, paths, receipts, or file contents.",
                }

            def dashboard_snapshot(self):
                apps = [
                    {**item, "successful_launches": 0, "failed_launches": 0}
                    for item in local_control_center.control_action_catalog()
                ]
                return {
                    "version": locker.DESKTOP_APP_VERSION,
                    "runtime": "Owner lab",
                    "remaining_seconds": 900,
                    "remaining_minutes": 15,
                    "server_uptime_seconds": 30,
                    "apps": apps,
                    "available_apps": len(local_control_center.CONTROL_ACTIONS),
                    "category_counts": {
                        category: sum(item["category"] == category for item in apps)
                        for category in {item["category"] for item in apps}
                    },
                    "successful_launches": 0,
                    "failed_launches": 0,
                    "total_launches": 0,
                    "customer": {
                        "license": "Active",
                        "plan": "Rank 5",
                        "desktop": locker.DESKTOP_APP_VERSION,
                        "api": "0.28.0",
                        "service": "Normal",
                        "automatic_updates": "On",
                    },
                    "history": [],
                    "history_limit": 20,
                }

        state = DummyState()
        server = local_control_center.LocalControlHTTPServer(
            (local_control_center.LOCAL_HOST, 0),
            local_control_center.LocalControlHandler,
            state,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        connection = http.client.HTTPConnection(local_control_center.LOCAL_HOST, port, timeout=5)
        try:
            connection.request("GET", "/")
            response = connection.getresponse()
            page = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)
            self.assertIn("default-src 'none'", response.getheader("Content-Security-Policy"))
            self.assertEqual(response.getheader("X-Frame-Options"), "DENY")
            self.assertEqual(response.getheader("Cross-Origin-Opener-Policy"), "same-origin")
            self.assertIn("usb=()", response.getheader("Permissions-Policy"))
            self.assertIn("Unlock Local Control", page)
            self.assertNotIn("D:/master_usb_file_locker.key", page)
            self.assertNotIn("SESSION-TOKEN", page)

            body = urllib.parse.urlencode({"pin": "Control-2468", "csrf": state.login_csrf})
            connection.request(
                "POST",
                "/login",
                body=body,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": f"http://127.0.0.1:{port}",
                },
            )
            response = connection.getresponse()
            unlocked_page = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)
            cookie = response.getheader("Set-Cookie")
            self.assertIn("HttpOnly", cookie)
            self.assertIn("SameSite=Strict", cookie)
            self.assertIn("Local Status", unlocked_page)
            self.assertIn("Recent Launches", unlocked_page)
            self.assertIn("EXTEND 15 MIN", unlocked_page)
            self.assertIn("EXPORT SAFE REPORT", unlocked_page)
            self.assertIn("Global Breach Guard", unlocked_page)
            self.assertIn("Trust &amp; Recovery Center", unlocked_page)
            self.assertIn("Diagnostics Center", unlocked_page)
            self.assertIn("Incident Response Center", unlocked_page)
            self.assertIn("Recovery Drill Center", unlocked_page)
            self.assertIn("Backup Verification Center", unlocked_page)
            self.assertIn("Recovery Kit Builder", unlocked_page)
            self.assertIn("Storage &amp; Retention Center", unlocked_page)
            self.assertIn("Security Maintenance Center", unlocked_page)
            self.assertIn("23 / 23", unlocked_page)
            self.assertNotIn("SESSION-TOKEN", unlocked_page)
            self.assertNotIn("D:/master_usb_file_locker.key", unlocked_page)

            session_cookie = cookie.split(";", 1)[0]
            body = urllib.parse.urlencode({"csrf": state.session_csrf})
            connection.request(
                "POST",
                "/extend",
                body=body,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": f"http://127.0.0.1:{port}",
                    "Cookie": session_cookie,
                },
            )
            response = connection.getresponse()
            response.read()
            self.assertEqual(response.status, 200)
            self.assertTrue(state.extended)

            connection.request(
                "POST",
                "/clear-history",
                body=body,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": f"http://127.0.0.1:{port}",
                    "Cookie": session_cookie,
                },
            )
            response = connection.getresponse()
            response.read()
            self.assertEqual(response.status, 200)
            self.assertTrue(state.history_cleared)

            connection.request(
                "GET",
                "/?category=Recovery",
                headers={"Cookie": session_cookie},
            )
            response = connection.getresponse()
            filtered_page = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)
            self.assertIn("Vault Health Center", filtered_page)
            self.assertNotIn("Personal Vault Pad", filtered_page)

            connection.request(
                "POST",
                "/export-report",
                body=body,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": f"http://127.0.0.1:{port}",
                    "Cookie": session_cookie,
                },
            )
            response = connection.getresponse()
            report = json.loads(response.read().decode("utf-8"))
            self.assertEqual(response.status, 200)
            self.assertIn("attachment", response.getheader("Content-Disposition"))
            self.assertEqual(report["session"]["apps_total"], 23)
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_trust_recovery_report_is_scored_whitelisted_and_secret_free(self):
        settings = {
            "last_key_path": "D:/PRIVATE-USB/master_usb_file_locker.key",
            "auto_install_signed_updates": True,
            "local_control_pin_verifier": "PRIVATE-PIN-VERIFIER",
        }
        state = locker.normalize_license_state(
            {
                "license_key": VALID_TEST_LICENSE,
                "receipt": "PRIVATE-RECEIPT-7701",
                "status": "active",
                "plan_id": "starter",
                "plan_name": "$5 Starter",
                "license_id": "PRIVATE-LICENSE-ID-7701",
                "customer_label": "PRIVATE-CUSTOMER-7701",
                "machine_name": "PRIVATE-PC-7701",
                "latest_desktop_version": "2026.07.14.5",
                "api_version": "0.28.0",
                "service_status": {"mode": "normal", "message": "Service normal"},
            }
        )
        defender = {
            "available": True,
            "ProtectedNow": True,
            "AntivirusEnabled": True,
            "RealTimeProtectionEnabled": True,
            "BehaviorMonitorEnabled": True,
            "IoavProtectionEnabled": True,
            "AntivirusSignatureLastUpdated": "2026-07-14T20:00:00Z",
            "QuickScanAge": 0,
            "FullScanAge": 2,
            "unexpected_secret": "PRIVATE-DEFENDER-SECRET",
        }
        records = [
            {
                "action": "recovery_self_test",
                "result": "success",
                "time_utc": "2026-07-14T20:10:00Z",
                "path": "C:/PRIVATE/recovery.txt",
            },
            {
                "action": "backup_app_data",
                "result": "success",
                "time_utc": "2026-07-14T20:20:00Z",
                "file_contents": "PRIVATE-BACKUP-CONTENTS",
            },
        ]
        online = {
            "ok": True,
            "trust_schema_version": 1,
            "api_version": "0.28.0",
            "score": {"value": 100, "maximum": 100, "label": "ready", "attention_count": 0},
            "checks": [
                {
                    "id": "api-online",
                    "category": "Service",
                    "title": "API online",
                    "state": "good",
                    "passed": True,
                    "weight": 10,
                    "detail": "D:/PRIVATE/customer/path.txt",
                    "unexpected": "PRIVATE-ONLINE-CHECK-SECRET",
                }
            ],
            "service_status": {"mode": "normal", "message": "Service normal"},
            "signed_release": {
                "ready": True,
                "version": "2026.07.14.5",
                "minimum_supported_version": "2026.07.12.9",
                "published_at_utc": "2026-07-14T20:30:00Z",
                "package_filename": "VaultLink-Windows-2026.07.14.5.zip",
                "size_bytes": 123456,
                "sha256": "a" * 64,
                "signing_key_id": "safe-key-id",
                "checks": {
                    "manifest_schema": "passed",
                    "ed25519_signature": "passed",
                    "package_size": "passed",
                    "package_sha256": "passed",
                    "app_data_preservation": "passed",
                },
            },
            "storage": {
                "license_state": "persistent_configured",
                "audit_exports": "persistent_configured",
                "private_license_fields_encrypted": True,
                "support_private_fields_encrypted": True,
            },
            "cryptography": [{"purpose": "Updates", "control": "Ed25519 and SHA-256"}],
            "data_boundaries": {
                "stays_on_customer_pc": ["USB key bytes"],
                "may_reach_api_after_explicit_action": ["Approved safe fields"],
                "never_requested_by_api": ["PINs and file contents"],
            },
            "recovery_steps": ["Use a disposable test file"],
            "limitations": ["Not certification"],
            "safe_to_export": True,
            "server_time_utc": "2026-07-14T20:31:00Z",
            "unexpected_private_customer_record": "PRIVATE-ONLINE-CUSTOMER-7701",
        }
        with mock.patch.object(locker, "load_owner_policy", return_value={"version": 1}), mock.patch.object(
            trust_recovery_center, "selected_key_ready", return_value=True
        ), mock.patch.object(
            trust_recovery_center, "local_control_pin_ready", return_value=True
        ), mock.patch.object(locker, "license_is_active", return_value=True):
            report = trust_recovery_center.build_local_trust_report(
                settings,
                state,
                defender,
                (True, 2, "Hash chain and event signatures are valid."),
                records,
                online,
            )
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["score"]["maximum"], 100)
        self.assertEqual(report["score"]["value"], 100)
        self.assertEqual(report["score"]["passed"], 11)
        self.assertEqual(report["online_trust"]["score"]["value"], 100)
        self.assertNotIn("unexpected_private_customer_record", report["online_trust"])
        self.assertEqual(report["online_trust"]["checks"][0]["detail"], "No public detail is available.")
        report_text = json.dumps(report)
        rendered_text = trust_recovery_center.safe_report_text(report)
        for private_value in (
            "D:/PRIVATE-USB",
            "C:/PRIVATE",
            VALID_TEST_LICENSE,
            "PRIVATE-RECEIPT-7701",
            "PRIVATE-LICENSE-ID-7701",
            "PRIVATE-CUSTOMER-7701",
            "PRIVATE-PC-7701",
            "PRIVATE-PIN-VERIFIER",
            "PRIVATE-DEFENDER-SECRET",
            "PRIVATE-BACKUP-CONTENTS",
            "PRIVATE-ONLINE-CHECK-SECRET",
            "PRIVATE-ONLINE-CUSTOMER-7701",
        ):
            self.assertNotIn(private_value, report_text)
            self.assertNotIn(private_value, rendered_text)

    def test_diagnostics_report_has_eighteen_checks_and_no_private_values(self):
        now = datetime(2026, 7, 14, 20, 30, tzinfo=timezone.utc)
        settings = {
            "last_key_path": "D:/PRIVATE-DIAGNOSTIC-USB/master_usb_file_locker.key",
            "owner_usb_policy": "PRIVATE-OWNER-POLICY",
            "local_control_pin_verifier": "PRIVATE-DIAGNOSTIC-PIN",
        }
        state = locker.normalize_license_state(
            {
                "license_key": VALID_TEST_LICENSE,
                "receipt": "PRIVATE-DIAGNOSTIC-RECEIPT",
                "license_id": "PRIVATE-DIAGNOSTIC-LICENSE-ID",
                "customer_label": "PRIVATE-DIAGNOSTIC-CUSTOMER",
                "machine_name": "PRIVATE-DIAGNOSTIC-PC",
                "status": "active",
                "plan_id": "starter",
                "plan_name": "$5 Starter",
            }
        )
        defender = {
            "available": True,
            "ProtectedNow": True,
            "AntivirusEnabled": True,
            "RealTimeProtectionEnabled": True,
            "BehaviorMonitorEnabled": True,
            "IoavProtectionEnabled": True,
            "AntivirusSignatureLastUpdated": "2026-07-14T20:00:00Z",
            "unexpected_secret": "PRIVATE-DIAGNOSTIC-DEFENDER",
        }
        audit_records = [
            {"action": "recovery_self_test", "result": "success", "time_utc": "2026-07-14T20:10:00Z", "path": "C:/PRIVATE/recovery.txt"},
            {"action": "backup_app_data", "result": "success", "time_utc": "2026-07-14T20:20:00Z", "contents": "PRIVATE-DIAGNOSTIC-CONTENTS"},
        ]
        guide = {
            "ok": True,
            "diagnostics_schema_version": 1,
            "api_version": "0.28.0",
            "service_status": {"mode": "normal", "message": "All services normal."},
            "signed_release": {
                "ready": True,
                "version": "2026.07.14.5",
                "minimum_supported_version": "2026.07.12.9",
                "published_at_utc": "2026-07-14T20:15:00Z",
            },
            "categories": [
                {
                    "id": "app-start",
                    "title": "App will not open",
                    "summary": "Use fixed safe steps.",
                    "steps": [
                        {
                            "id": "step-one",
                            "title": "Run diagnostics",
                            "action": "C:/PRIVATE/customer-file.txt",
                            "expected": "A privacy-safe result.",
                            "unexpected": "PRIVATE-DIAGNOSTIC-STEP",
                        }
                    ],
                    "escalation": "Send only reviewed safe fields.",
                }
            ],
            "privacy_boundaries": ["No files or secrets"],
            "limitations": ["Not certification"],
            "server_time_utc": "2026-07-14T20:30:00Z",
            "unexpected_customer": "PRIVATE-DIAGNOSTIC-ONLINE-CUSTOMER",
        }
        runtime = {
            "python_version": "3.14.0",
            "python_supported": True,
            "cryptography_version": "49.0.0",
            "cryptography_ready": True,
            "required_app_files": 4,
            "available_app_files": 4,
            "package_ready": True,
            "app_data_writable": True,
            "free_disk_bytes": 2 * 1024 ** 3,
            "settings_readable": True,
            "unexpected_path": "C:/PRIVATE/app-data",
        }
        with mock.patch.object(locker, "load_owner_policy", return_value={"version": 1}), mock.patch.object(
            trust_recovery_center, "selected_key_ready", return_value=True
        ), mock.patch.object(
            trust_recovery_center, "local_control_pin_ready", return_value=True
        ), mock.patch.object(locker, "license_is_active", return_value=True):
            report = diagnostics_center.build_diagnostics_report(
                settings,
                state,
                defender,
                (True, 2, "Hash chain is valid."),
                audit_records,
                guide,
                runtime,
                now_utc=now,
            )
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["score"]["maximum"], 100)
        self.assertEqual(report["score"]["value"], 100)
        self.assertEqual(report["score"]["passed"], 18)
        self.assertEqual(report["score"]["total"], 18)
        self.assertEqual(sum(item["weight"] for item in report["checks"]), 100)
        self.assertEqual(report["environment"]["diagnostics_api_version"], "0.28.0")
        self.assertEqual(report["online_guide"]["categories"][0]["steps"][0]["action"], "Review this check in the desktop app.")
        self.assertNotIn("unexpected_customer", report["online_guide"])
        malformed = dict(guide)
        malformed["diagnostics_schema_version"] = "not-an-integer"
        self.assertEqual(diagnostics_center.safe_diagnostics_guide(malformed)["diagnostics_schema_version"], 1)
        report_text = json.dumps(report)
        rendered_text = diagnostics_center.safe_diagnostics_text(report)
        summary_text = diagnostics_center.safe_summary_text(report)
        for private_value in (
            "D:/PRIVATE-DIAGNOSTIC-USB",
            "C:/PRIVATE",
            VALID_TEST_LICENSE,
            "PRIVATE-DIAGNOSTIC-RECEIPT",
            "PRIVATE-DIAGNOSTIC-LICENSE-ID",
            "PRIVATE-DIAGNOSTIC-CUSTOMER",
            "PRIVATE-DIAGNOSTIC-PC",
            "PRIVATE-DIAGNOSTIC-PIN",
            "PRIVATE-DIAGNOSTIC-DEFENDER",
            "PRIVATE-DIAGNOSTIC-CONTENTS",
            "PRIVATE-DIAGNOSTIC-STEP",
            "PRIVATE-DIAGNOSTIC-ONLINE-CUSTOMER",
        ):
            self.assertNotIn(private_value, report_text)
            self.assertNotIn(private_value, rendered_text)
            self.assertNotIn(private_value, summary_text)

    def test_incident_report_has_fixed_playbook_and_no_private_values(self):
        diagnostic_checks = []
        for identifier, _category, title, _weight in incident_response_center.READINESS_CHECKS:
            diagnostic_checks.append(
                {
                    "id": identifier,
                    "title": title,
                    "passed": True,
                    "detail": "Coarse readiness result is available.",
                    "action": "Use the trusted local recovery tool.",
                    "private_path": "C:/PRIVATE-INCIDENT/customer.txt",
                }
            )
        diagnostic_report = {
            "checks": diagnostic_checks,
            "license_key": VALID_TEST_LICENSE,
            "machine_name": "PRIVATE-INCIDENT-PC",
            "contents": "PRIVATE-INCIDENT-CONTENTS",
        }
        guide = {
            "ok": True,
            "incident_schema_version": 1,
            "api_version": "0.29.0",
            "service_status": {"mode": "normal", "message": "All services normal.", "secret": "PRIVATE-SERVICE"},
            "signed_release": {"ready": True, "version": "2026.07.14.6", "minimum_supported_version": "2026.07.12.9"},
            "playbooks": [
                {
                    "id": "defender-alert",
                    "title": "Microsoft Defender alert",
                    "summary": "Use fixed safe response steps.",
                    "steps": [
                        {
                            "id": "alert-safe-step",
                            "title": "Review the alert",
                            "action": "C:/PRIVATE-INCIDENT/customer.txt",
                            "expected": "A reviewed safe result.",
                            "unexpected_secret": "PRIVATE-STEP-SECRET",
                        }
                    ],
                    "escalation": "Seek qualified help when unresolved.",
                    "private_customer": "PRIVATE-INCIDENT-CUSTOMER",
                }
            ],
            "privacy_boundaries": ["No files or secrets"],
            "limitations": ["Not malware removal or certification"],
            "customer_records": ["PRIVATE-CUSTOMER-RECORD"],
            "server_time_utc": "2026-07-14T21:00:00Z",
        }
        report = incident_response_center.build_incident_report(
            diagnostic_report,
            guide,
            "defender-alert",
            {"alert-safe-step", "PRIVATE-INVALID-STEP"},
            "2026-07-14T21:01:00Z",
        )
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["readiness"]["value"], 100)
        self.assertEqual(report["readiness"]["maximum"], 100)
        self.assertEqual(report["readiness"]["passed"], 8)
        self.assertEqual(report["readiness"]["total"], 8)
        self.assertEqual(sum(item["weight"] for item in report["checks"]), 100)
        self.assertEqual(report["selected_playbook"]["completed_step_ids"], ["alert-safe-step"])
        self.assertEqual(report["selected_playbook"]["steps"][0]["action"], "Review this step locally.")
        self.assertEqual(report["online_guide"]["api_version"], "0.29.0")
        self.assertEqual(report["online_guide"]["playbook_count"], 1)
        fallback = incident_response_center.safe_incident_guide({})
        self.assertEqual(len(fallback["playbooks"]), 12)
        self.assertEqual(sum(len(item["steps"]) for item in fallback["playbooks"]), 72)
        report_text = json.dumps(report)
        rendered_text = incident_response_center.safe_incident_text(report)
        summary_text = incident_response_center.safe_incident_summary(report)
        for private_value in (
            "C:/PRIVATE-INCIDENT",
            VALID_TEST_LICENSE,
            "PRIVATE-INCIDENT-PC",
            "PRIVATE-INCIDENT-CONTENTS",
            "PRIVATE-SERVICE",
            "PRIVATE-STEP-SECRET",
            "PRIVATE-INCIDENT-CUSTOMER",
            "PRIVATE-CUSTOMER-RECORD",
            "PRIVATE-INVALID-STEP",
        ):
            self.assertNotIn(private_value, report_text)
            self.assertNotIn(private_value, rendered_text)
            self.assertNotIn(private_value, summary_text)

    def test_recovery_drills_are_fixed_hash_chained_and_privacy_safe(self):
        self.assertEqual(len(recovery_drill_center.LOCAL_DRILLS), 16)
        self.assertEqual(sum(len(item["steps"]) for item in recovery_drill_center.LOCAL_DRILLS), 80)
        self.assertEqual(sum(item[3] for item in recovery_drill_center.READINESS_CHECKS), 100)
        fallback = recovery_drill_center.safe_recovery_guide({})
        self.assertEqual(len(fallback["drills"]), 16)
        self.assertEqual(sum(len(item["steps"]) for item in fallback["drills"]), 80)

        diagnostic_checks = []
        for identifier, _category, title, _weight in recovery_drill_center.READINESS_CHECKS:
            diagnostic_checks.append(
                {
                    "id": identifier,
                    "title": title,
                    "passed": True,
                    "detail": "C:/PRIVATE-RECOVERY/customer-name.txt",
                    "action": "Open D:/PRIVATE-RECOVERY/master.key",
                }
            )
        guide = {
            "ok": True,
            "recovery_drill_schema_version": 1,
            "api_version": "0.30.0",
            "service_status": {"mode": "normal", "message": "Normal", "private": "PRIVATE-SERVICE"},
            "signed_release": {"ready": True, "version": "2026.07.14.7", "minimum_supported_version": "2026.07.12.9"},
            "drills": [
                {
                    "id": "key-recovery",
                    "category": "Recovery",
                    "title": "Recover with a backup key",
                    "summary": "Fixed safe drill",
                    "steps": [
                        {
                            "id": "key-preserve",
                            "title": "Preserve the original",
                            "action": "C:/PRIVATE-RECOVERY/customer-name.txt",
                            "expected": "The original stays unchanged.",
                            "private": "PRIVATE-STEP",
                        }
                    ],
                    "success": "A safe result exists.",
                    "private": "PRIVATE-CUSTOMER",
                }
            ],
            "privacy_boundaries": ["No secrets"],
            "limitations": ["Not a guarantee"],
            "customer_records": ["PRIVATE-RECORD"],
        }
        with tempfile.TemporaryDirectory(prefix="vaultlink_recovery_drill_") as folder:
            history_path = Path(folder) / "history.jsonl"
            settings_path = Path(folder) / "settings.json"
            first = recovery_drill_center.append_drill_history(
                "key-recovery", 5, 5, 100, path=history_path, time_utc="2026-07-15T02:00:00Z"
            )
            second = recovery_drill_center.append_drill_history(
                "phishing-response", 2, 5, 80, path=history_path, time_utc="2026-07-15T02:01:00Z"
            )
            history, integrity = recovery_drill_center.load_drill_history(history_path)
            self.assertTrue(integrity["valid"])
            self.assertEqual([first["result"], second["result"]], ["complete", "partial"])
            self.assertEqual(len(history), 2)
            recovery_drill_center.save_drill_settings(60, settings_path)
            self.assertEqual(recovery_drill_center.load_drill_settings(settings_path)["interval_days"], 60)

            report = recovery_drill_center.build_recovery_report(
                {"checks": diagnostic_checks, "license_key": VALID_TEST_LICENSE, "private": "PRIVATE-DIAGNOSTIC"},
                guide,
                "key-recovery",
                {"key-preserve", "PRIVATE-INVALID-STEP"},
                history,
                integrity,
                60,
                "2026-07-15T02:02:00Z",
            )
            self.assertEqual(report["readiness"]["value"], 100)
            self.assertEqual(report["readiness"]["total"], 10)
            self.assertEqual(report["selected_drill"]["completed_step_ids"], ["key-preserve"])
            self.assertEqual(report["selected_drill"]["steps"][0]["action"], "Review this fixed step locally.")
            self.assertEqual(report["history"]["record_count"], 2)
            self.assertTrue(report["history"]["integrity_valid"])
            self.assertEqual(report["history"]["interval_days"], 60)
            self.assertEqual(report["online_catalog"]["api_version"], "0.30.0")
            self.assertTrue(all(item["detail"] == "This readiness result is unavailable." for item in report["checks"]))

            report_text = json.dumps(report)
            rendered_text = recovery_drill_center.safe_recovery_text(report)
            summary_text = recovery_drill_center.safe_recovery_summary(report)
            for private_value in (
                "C:/PRIVATE-RECOVERY",
                "D:/PRIVATE-RECOVERY",
                VALID_TEST_LICENSE,
                "PRIVATE-SERVICE",
                "PRIVATE-STEP",
                "PRIVATE-CUSTOMER",
                "PRIVATE-RECORD",
                "PRIVATE-DIAGNOSTIC",
                "PRIVATE-INVALID-STEP",
            ):
                self.assertNotIn(private_value, report_text)
                self.assertNotIn(private_value, rendered_text)
                self.assertNotIn(private_value, summary_text)

            lines = history_path.read_text(encoding="utf-8").splitlines()
            damaged = json.loads(lines[0])
            damaged["readiness_score"] = 1
            lines[0] = json.dumps(damaged, sort_keys=True, separators=(",", ":"))
            history_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            _records, damaged_integrity = recovery_drill_center.load_drill_history(history_path)
            self.assertFalse(damaged_integrity["valid"])
            with self.assertRaisesRegex(ValueError, "integrity failed"):
                recovery_drill_center.append_drill_history("key-recovery", 1, 5, 10, path=history_path)

    def test_backup_verification_is_fixed_hash_chained_comparable_and_private(self):
        self.assertEqual(len(backup_verification_center.LOCAL_PLANS), 12)
        self.assertEqual(sum(len(item["steps"]) for item in backup_verification_center.LOCAL_PLANS), 60)
        self.assertEqual(len({item["category"] for item in backup_verification_center.LOCAL_PLANS}), 9)
        self.assertEqual(sum(item[3] for item in backup_verification_center.READINESS_CHECKS), 100)
        self.assertEqual(len(backup_verification_center.RESTORE_OBJECTIVES), 5)
        fallback = backup_verification_center.safe_backup_guide({})
        self.assertEqual(len(fallback["plans"]), 12)
        self.assertEqual(sum(len(item["steps"]) for item in fallback["plans"]), 60)

        diagnostic_checks = []
        for identifier, _category, title, _weight in backup_verification_center.READINESS_CHECKS:
            diagnostic_checks.append(
                {
                    "id": identifier,
                    "title": title,
                    "passed": True,
                    "detail": "C:/PRIVATE-BACKUP/customer-name.txt",
                    "action": "Open D:/PRIVATE-BACKUP/master.key",
                }
            )
        guide = {
            "ok": True,
            "backup_verification_schema_version": 1,
            "api_version": "0.31.0",
            "service_status": {"mode": "normal", "message": "Normal", "private": "PRIVATE-SERVICE"},
            "signed_release": {"ready": True, "version": "2026.07.15.2", "minimum_supported_version": "2026.07.12.9"},
            "restore_objectives": list(backup_verification_center.RESTORE_OBJECTIVES),
            "plans": [
                {
                    "id": "master-key-copies",
                    "category": "Keys",
                    "title": "Master-key copy verification",
                    "summary": "Fixed backup plan",
                    "steps": [
                        {
                            "id": "master-key-copies-inventory",
                            "title": "Inventory the pieces",
                            "action": "C:/PRIVATE-BACKUP/customer-name.txt",
                            "expected": "The scope is known.",
                            "private": "PRIVATE-STEP",
                        }
                    ],
                    "success": "A safe result exists.",
                    "private": "PRIVATE-CUSTOMER",
                }
            ],
            "privacy_boundaries": ["No secrets"],
            "limitations": ["Not a guarantee"],
            "customer_records": ["PRIVATE-RECORD"],
        }
        with tempfile.TemporaryDirectory(prefix="vaultlink_backup_verification_") as folder:
            history_path = Path(folder) / "history.jsonl"
            settings_path = Path(folder) / "settings.json"
            first = backup_verification_center.append_checkpoint(
                "master-key-copies", 1, 5, 70, ["audit-chain"], "4-hours", 2,
                path=history_path, time_utc="2026-07-15T03:00:00Z",
            )
            second = backup_verification_center.append_checkpoint(
                "master-key-copies", 5, 5, 90, ["audit-chain", "selected-key"], "1-day", 3,
                path=history_path, time_utc="2026-07-15T03:01:00Z",
            )
            history, integrity = backup_verification_center.load_checkpoint_history(history_path)
            self.assertTrue(integrity["valid"])
            self.assertEqual([first["result"], second["result"]], ["partial", "complete"])
            self.assertEqual(len(history), 2)
            backup_verification_center.save_center_settings(60, "1-day", 3, settings_path)
            saved = backup_verification_center.load_center_settings(settings_path)
            self.assertEqual(saved, {"interval_days": 60, "copy_target": 3, "objective_id": "1-day"})

            report = backup_verification_center.build_backup_report(
                {"checks": diagnostic_checks, "license_key": VALID_TEST_LICENSE, "private": "PRIVATE-DIAGNOSTIC"},
                guide,
                "master-key-copies",
                {"master-key-copies-inventory", "PRIVATE-INVALID-STEP"},
                history,
                integrity,
                saved,
                True,
                4,
                "2026-07-15T03:02:00Z",
            )
            self.assertEqual(report["readiness"]["value"], 100)
            self.assertEqual(report["readiness"]["total"], 12)
            self.assertEqual(report["selected_plan"]["completed_step_ids"], ["master-key-copies-inventory"])
            self.assertEqual(report["selected_plan"]["steps"][0]["action"], "Review this fixed step locally.")
            self.assertEqual(report["restore_target"]["objective_id"], "1-day")
            self.assertEqual(report["restore_target"]["copy_target"], 3)
            self.assertTrue(report["session_backup_verification"]["verified"])
            self.assertEqual(report["session_backup_verification"]["restorable_file_count"], 4)
            self.assertEqual(report["history"]["comparison"]["score_delta"], 20)
            self.assertEqual(report["history"]["comparison"]["gained_check_ids"], ["selected-key"])
            self.assertEqual(report["online_catalog"]["api_version"], "0.31.0")
            self.assertTrue(all("PRIVATE-BACKUP" not in item["detail"] for item in report["checks"]))

            report_text = json.dumps(report)
            rendered_text = backup_verification_center.safe_backup_text(report)
            summary_text = backup_verification_center.safe_backup_summary(report)
            for private_value in (
                "C:/PRIVATE-BACKUP",
                "D:/PRIVATE-BACKUP",
                VALID_TEST_LICENSE,
                "PRIVATE-SERVICE",
                "PRIVATE-STEP",
                "PRIVATE-CUSTOMER",
                "PRIVATE-RECORD",
                "PRIVATE-DIAGNOSTIC",
                "PRIVATE-INVALID-STEP",
            ):
                self.assertNotIn(private_value, report_text)
                self.assertNotIn(private_value, rendered_text)
                self.assertNotIn(private_value, summary_text)

            unexpected_path = Path(folder) / "unexpected-field-history.jsonl"
            unexpected = dict(first)
            unexpected["private_path"] = "C:/PRIVATE-BACKUP/customer-name.txt"
            unexpected["hash"] = hashlib.sha256(
                backup_verification_center._canonical_record(unexpected)
            ).hexdigest()
            unexpected_path.write_text(
                json.dumps(unexpected, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            unexpected_records, unexpected_integrity = backup_verification_center.load_checkpoint_history(unexpected_path)
            self.assertEqual(unexpected_records, [])
            self.assertFalse(unexpected_integrity["valid"])
            self.assertIn("fixed schema", unexpected_integrity["message"])

            lines = history_path.read_text(encoding="utf-8").splitlines()
            damaged = json.loads(lines[0])
            damaged["copy_target"] = 5
            lines[0] = json.dumps(damaged, sort_keys=True, separators=(",", ":"))
            history_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            _records, damaged_integrity = backup_verification_center.load_checkpoint_history(history_path)
            self.assertFalse(damaged_integrity["valid"])
            with self.assertRaisesRegex(ValueError, "integrity failed"):
                backup_verification_center.append_checkpoint(
                    "master-key-copies", 1, 5, 10, [], "4-hours", 2, path=history_path
                )

    def test_recovery_kit_is_fixed_hash_chained_exportable_and_private(self):
        tree = ast.parse(Path(recovery_kit_builder.__file__).read_text(encoding="utf-8"))
        locker_attributes = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "locker"
        }
        self.assertEqual(sorted(name for name in locker_attributes if not hasattr(locker, name)), [])
        self.assertEqual(len(recovery_kit_builder.LOCAL_PROFILES), 5)
        self.assertEqual(len(recovery_kit_builder.LOCAL_SECTIONS), 10)
        self.assertEqual(sum(len(item["items"]) for item in recovery_kit_builder.LOCAL_SECTIONS), 50)
        self.assertEqual(len({item["category"] for item in recovery_kit_builder.LOCAL_SECTIONS}), 8)
        self.assertEqual(len(recovery_kit_builder.LOCAL_RUNBOOKS), 5)
        self.assertEqual(sum(len(item["steps"]) for item in recovery_kit_builder.LOCAL_RUNBOOKS), 30)
        self.assertEqual(sum(item[3] for item in recovery_kit_builder.KIT_READINESS_CHECKS), 100)
        fallback = recovery_kit_builder.safe_recovery_kit_guide({})
        self.assertEqual(len(fallback["profiles"]), 5)
        self.assertEqual(len(fallback["sections"]), 10)
        self.assertEqual(sum(len(item["items"]) for item in fallback["sections"]), 50)

        diagnostic_checks = [
            {
                "id": identifier,
                "title": title,
                "passed": True,
                "detail": "C:/PRIVATE-KIT/customer-name.txt",
                "action": "Open D:/PRIVATE-KIT/master.key",
            }
            for identifier, _category, title, _weight in recovery_kit_builder.KIT_READINESS_CHECKS
        ]
        guide = {
            "ok": True,
            "recovery_kit_schema_version": 1,
            "api_version": "0.32.0",
            "service_status": {"mode": "normal", "message": "Normal", "private": "PRIVATE-SERVICE"},
            "signed_release": {"ready": True, "version": "2026.07.15.2", "minimum_supported_version": "2026.07.12.9"},
            "profiles": [
                {
                    "id": "personal-pc",
                    "label": "C:/PRIVATE-KIT/profile.txt",
                    "summary": "C:/PRIVATE-KIT/profile-summary.txt",
                    "section_ids": ["PRIVATE-SECTION"],
                    "private": "PRIVATE-PROFILE-FIELD",
                }
            ],
            "sections": [
                {
                    "id": "signed-software",
                    "category": "PRIVATE-CATEGORY",
                    "title": "Signed software kit",
                    "summary": "Fixed kit section",
                    "items": [
                        {
                            "id": "software-official-source",
                            "title": "Official source",
                            "action": "C:/PRIVATE-KIT/customer-name.txt",
                            "expected": "Fixed expected state",
                            "private": "PRIVATE-ITEM",
                        }
                    ],
                    "private": "PRIVATE-SECTION-FIELD",
                }
            ],
            "runbooks": [
                {
                    "id": "replacement-pc",
                    "label": "Replacement PC",
                    "summary": "Fixed emergency order",
                    "steps": ["C:/PRIVATE-KIT/step.txt"] * 6,
                    "private": "PRIVATE-RUNBOOK",
                }
            ],
            "privacy_boundaries": ["C:/PRIVATE-KIT/boundary.txt"],
            "limitations": ["Not a guarantee"],
            "customer_records": ["PRIVATE-RECORD"],
        }
        with tempfile.TemporaryDirectory(prefix="vaultlink_recovery_kit_") as folder:
            history_path = Path(folder) / "history.jsonl"
            settings_path = Path(folder) / "settings.json"
            personal_items = sorted(recovery_kit_builder._profile_item_ids("personal-pc"))
            first = recovery_kit_builder.append_snapshot(
                "personal-pc",
                "replacement-pc",
                personal_items[:2],
                70,
                30,
                path=history_path,
                time_utc="2026-07-15T12:00:00Z",
            )
            second = recovery_kit_builder.append_snapshot(
                "personal-pc",
                "replacement-pc",
                personal_items[:3],
                90,
                60,
                path=history_path,
                time_utc="2026-07-15T12:01:00Z",
            )
            history, integrity = recovery_kit_builder.load_snapshot_history(history_path)
            self.assertTrue(integrity["valid"])
            self.assertEqual(len(history), 2)
            self.assertEqual(first["total_items"], 45)
            self.assertEqual(second["completed_count"], 3)
            recovery_kit_builder.save_settings("personal-pc", "replacement-pc", 60, settings_path)
            saved = recovery_kit_builder.load_settings(settings_path)
            self.assertEqual(saved, {"profile_id": "personal-pc", "runbook_id": "replacement-pc", "interval_days": 60})

            report = recovery_kit_builder.build_recovery_kit_report(
                {"checks": diagnostic_checks, "license_key": VALID_TEST_LICENSE, "private": "PRIVATE-DIAGNOSTIC"},
                guide,
                "personal-pc",
                "replacement-pc",
                set(personal_items[:3]) | {"PRIVATE-INVALID-ITEM"},
                60,
                history,
                integrity,
                "2026-07-15T12:02:00Z",
            )
            self.assertEqual(report["readiness"]["value"], 100)
            self.assertEqual(report["readiness"]["total"], 10)
            self.assertEqual(report["profile"]["item_count"], 45)
            self.assertEqual(report["profile"]["completed_item_ids"], personal_items[:3])
            self.assertEqual(report["history"]["comparison"]["coverage_delta"], 1)
            self.assertEqual(report["history"]["comparison"]["readiness_delta"], 20)
            self.assertEqual(report["history"]["comparison"]["gained_item_ids"], [personal_items[2]])
            self.assertEqual(report["online_catalog"]["api_version"], "0.32.0")
            self.assertEqual(len(report["runbook"]["steps"]), 6)
            self.assertTrue(all("PRIVATE-KIT" not in item["detail"] for item in report["checks"]))

            calendar = recovery_kit_builder.build_calendar_text(
                30,
                datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc),
                "0123456789abcdef",
            )
            self.assertIn("DTSTART:20260814T120000Z", calendar)
            self.assertIn("UID:0123456789abcdef@vaultlink.local", calendar)
            self.assertIn("VaultLink Recovery Kit Review", calendar)

            report_text = json.dumps(report)
            rendered_text = recovery_kit_builder.safe_report_text(report)
            summary_text = recovery_kit_builder.safe_summary(report)
            for private_value in (
                "C:/PRIVATE-KIT",
                "D:/PRIVATE-KIT",
                VALID_TEST_LICENSE,
                "PRIVATE-SERVICE",
                "PRIVATE-PROFILE-FIELD",
                "PRIVATE-ITEM",
                "PRIVATE-SECTION-FIELD",
                "PRIVATE-RUNBOOK",
                "PRIVATE-RECORD",
                "PRIVATE-DIAGNOSTIC",
                "PRIVATE-INVALID-ITEM",
            ):
                self.assertNotIn(private_value, report_text)
                self.assertNotIn(private_value, rendered_text)
                self.assertNotIn(private_value, summary_text)
                self.assertNotIn(private_value, calendar)

            unexpected_path = Path(folder) / "unexpected-field-history.jsonl"
            unexpected = dict(first)
            unexpected["private_contact"] = "PRIVATE-CONTACT"
            unexpected["hash"] = hashlib.sha256(
                recovery_kit_builder._canonical_record(unexpected)
            ).hexdigest()
            unexpected_path.write_text(
                json.dumps(unexpected, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            unexpected_records, unexpected_integrity = recovery_kit_builder.load_snapshot_history(unexpected_path)
            self.assertEqual(unexpected_records, [])
            self.assertFalse(unexpected_integrity["valid"])
            self.assertIn("fixed schema", unexpected_integrity["message"])

            lines = history_path.read_text(encoding="utf-8").splitlines()
            damaged = json.loads(lines[0])
            damaged["interval_days"] = 90
            lines[0] = json.dumps(damaged, sort_keys=True, separators=(",", ":"))
            history_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            _records, damaged_integrity = recovery_kit_builder.load_snapshot_history(history_path)
            self.assertFalse(damaged_integrity["valid"])
            with self.assertRaisesRegex(ValueError, "integrity failed"):
                recovery_kit_builder.append_snapshot(
                    "personal-pc", "replacement-pc", [], 10, 30, path=history_path
                )

    def test_local_data_control_is_fixed_hash_chained_bounded_and_private(self):
        tree = ast.parse(Path(local_data_control_center.__file__).read_text(encoding="utf-8"))
        locker_attributes = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "locker"
        }
        self.assertEqual(sorted(name for name in locker_attributes if not hasattr(locker, name)), [])
        self.assertEqual(len(local_data_control_center.SCOPE_SPECS), 5)
        self.assertEqual(len(local_data_control_center.DATA_CLASS_SPECS), 14)
        self.assertEqual(len({item["id"] for item in local_data_control_center.DATA_CLASS_SPECS}), 14)
        self.assertEqual(len(local_data_control_center.CONTROL_CHECKS), 11)
        self.assertEqual(sum(item[3] for item in local_data_control_center.CONTROL_CHECKS), 100)
        self.assertEqual(local_data_control_center.MAX_INVENTORY_FILES, 5000)

        source_map = local_data_control_center._class_sources()
        source_text = "\n".join(str(path) for paths in source_map.values() for path in paths)
        self.assertNotIn("Downloads", source_text)
        self.assertNotIn("Documents", source_text)
        for paths in source_map.values():
            for path in paths:
                self.assertTrue(local_data_control_center._inside_app_dir(path))

        rows = []
        for index, spec in enumerate(local_data_control_center.DATA_CLASS_SPECS):
            rows.append(
                {
                    "id": spec["id"],
                    "state": "present" if index < 4 else "not-configured",
                    "count_band": "2-10" if index < 4 else "none",
                    "size_band": "under-64-kib" if index < 4 else "none",
                    "age_band": "today" if index < 4 else "none",
                    "private_path": "C:/PRIVATE-DATA/customer-name.txt",
                }
            )
        checks = [
            {
                "id": identifier,
                "passed": True,
                "detail": "C:/PRIVATE-DATA/customer-name.txt",
                "action": "Open D:/PRIVATE-DATA/master.key",
            }
            for identifier, _category, _title, _weight in local_data_control_center.CONTROL_CHECKS
        ]
        report = local_data_control_center.build_data_control_report(
            rows,
            checks,
            {
                "ok": True,
                "api_version": "0.33.0",
                "service_status": {"mode": "normal", "message": "C:/PRIVATE-DATA/customer-name.txt"},
                "signed_release": {"version": "2026.07.15.3", "private": "PRIVATE-RELEASE"},
                "customer_records": ["PRIVATE-CUSTOMER"],
            },
            history=[{"private": "PRIVATE-HISTORY"}],
            integrity={"valid": True, "message": "C:/PRIVATE-DATA/receipt.txt"},
            generated_at_utc="2026-07-15T15:00:00Z",
        )
        self.assertEqual(report["class_count"], 14)
        self.assertEqual(report["scope_count"], 5)
        self.assertEqual(report["summary"]["present_class_count"], 4)
        self.assertEqual(report["posture"], {"score": 100, "maximum": 100, "label": "ready", "passed": 11, "total": 11})
        self.assertEqual(report["online"]["api_version"], "0.33.0")
        self.assertEqual(report["online"]["signed_desktop_version"], "2026.07.15.3")
        self.assertEqual(report["online"]["service_mode"], "normal")
        self.assertEqual(report["receipts"]["record_count"], 1)
        self.assertTrue(all("PRIVATE-DATA" not in item["detail"] for item in report["checks"]))

        report_text = json.dumps(report)
        safe_text = local_data_control_center.safe_report_text(report)
        safe_summary = local_data_control_center.safe_summary(report)
        for private_value in (
            "C:/PRIVATE-DATA",
            "D:/PRIVATE-DATA",
            "PRIVATE-RELEASE",
            "PRIVATE-CUSTOMER",
            "PRIVATE-HISTORY",
        ):
            self.assertNotIn(private_value, report_text)
            self.assertNotIn(private_value, safe_text)
            self.assertNotIn(private_value, safe_summary)

        with tempfile.TemporaryDirectory(prefix="vaultlink_data_control_") as folder:
            history_path = Path(folder) / "data-control.jsonl"
            first = local_data_control_center.append_receipt(
                report, path=history_path, time_utc="2026-07-15T15:01:00Z"
            )
            second = local_data_control_center.append_receipt(
                report, path=history_path, time_utc="2026-07-15T15:02:00Z"
            )
            history, integrity = local_data_control_center.load_receipt_history(history_path)
            self.assertTrue(integrity["valid"])
            self.assertEqual(len(history), 2)
            self.assertEqual(first["sequence"], 1)
            self.assertEqual(second["previous_hash"], first["hash"])
            self.assertEqual(first["posture_score"], 100)
            self.assertEqual(first["present_class_count"], 4)
            receipt_text = history_path.read_text(encoding="utf-8")
            for private_value in ("PRIVATE-DATA", "PRIVATE-CUSTOMER", "master.key"):
                self.assertNotIn(private_value, receipt_text)

            concurrent_path = Path(folder) / "concurrent-data-control.jsonl"
            concurrent_errors = []
            threads = [
                threading.Thread(
                    target=lambda: local_data_control_center.append_receipt(report, path=concurrent_path),
                    daemon=True,
                )
                for _index in range(10)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
                if thread.is_alive():
                    concurrent_errors.append("thread did not finish")
            concurrent_history, concurrent_integrity = local_data_control_center.load_receipt_history(concurrent_path)
            self.assertEqual(concurrent_errors, [])
            self.assertTrue(concurrent_integrity["valid"])
            self.assertEqual(len(concurrent_history), 10)

            with mock.patch.object(local_data_control_center, "_linklike", return_value=True):
                _linked_history, linked_integrity = local_data_control_center.load_receipt_history(history_path)
                self.assertFalse(linked_integrity["valid"])
                with self.assertRaisesRegex(ValueError, "link or junction"):
                    local_data_control_center.append_receipt(report, path=history_path)

            invalid_report = json.loads(json.dumps(report))
            invalid_report["data_classes"][0]["state"] = "C:/PRIVATE-DATA/customer-name.txt"
            with self.assertRaisesRegex(ValueError, "invalid fixed class value"):
                local_data_control_center.append_receipt(
                    invalid_report,
                    path=Path(folder) / "invalid.jsonl",
                    time_utc="2026-07-15T15:03:00Z",
                )

            lines = history_path.read_text(encoding="utf-8").splitlines()
            damaged = json.loads(lines[0])
            damaged["posture_score"] = 1
            lines[0] = json.dumps(damaged, sort_keys=True, separators=(",", ":"))
            history_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            _records, damaged_integrity = local_data_control_center.load_receipt_history(history_path)
            self.assertFalse(damaged_integrity["valid"])
            with self.assertRaisesRegex(ValueError, "integrity failed"):
                local_data_control_center.append_receipt(report, path=history_path)

        with self.assertRaisesRegex(ValueError, "valid UTC"):
            local_data_control_center.build_data_control_report(
                rows,
                checks,
                generated_at_utc="C:/PRIVATE-DATA/customer-name.txt",
            )

    def test_security_maintenance_is_fixed_hash_chained_private_and_allowlisted(self):
        tree = ast.parse(Path(security_maintenance_center.__file__).read_text(encoding="utf-8"))
        locker_attributes = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "locker"
        }
        self.assertEqual(sorted(name for name in locker_attributes if not hasattr(locker, name)), [])
        self.assertEqual(len(security_maintenance_center.LOCAL_CATEGORIES), 8)
        self.assertEqual(len(security_maintenance_center.LOCAL_TASKS), 32)
        self.assertEqual(len(security_maintenance_center.LOCAL_ROUTINES), 6)
        self.assertEqual(len(security_maintenance_center.HISTORY_FIELDS), 10)
        self.assertEqual(len(security_maintenance_center.SNAPSHOT_FIELDS), 13)
        self.assertEqual(len(security_maintenance_center.PLANNING_WINDOWS), 5)
        self.assertEqual(set(security_maintenance_center.ALLOWED_CADENCE_DAYS), {7, 14, 30, 60, 90})
        self.assertEqual(
            set(security_maintenance_center.SCHEDULE_SCORE_WEIGHTS),
            {"current", "due-soon", "overdue", "not-started"},
        )
        self.assertEqual(set(security_maintenance_center.TRUSTED_TOOL_TARGETS), set(security_maintenance_center.TASK_BY_ID))
        for category in security_maintenance_center.LOCAL_CATEGORIES:
            self.assertEqual(
                sum(task["category_id"] == category["id"] for task in security_maintenance_center.LOCAL_TASKS),
                4,
            )
        self.assertEqual(
            set(security_maintenance_center.ROUTINE_BY_ID["full-maintenance"]["task_ids"]),
            set(security_maintenance_center.TASK_BY_ID),
        )

        private_values = (
            "PRIVATE-CUSTOMER-9812",
            "C:/PRIVATE-DATA/customer-name.txt",
            "PRIVATE-MASTER-KEY",
            "PRIVATE-PIN-9812",
        )
        guide = security_maintenance_center.safe_maintenance_guide(
            {
                "ok": True,
                "api_version": "0.36.0",
                "service_status": {"mode": "normal", "message": private_values[0]},
                "signed_release": {"ready": True, "version": "2026.07.16.2"},
                "categories": [{"id": private_values[1], "title": private_values[0]}],
                "tasks": [{"id": private_values[2], "title": private_values[3]}],
                "routines": [{"id": private_values[0], "task_ids": [private_values[1]]}],
            }
        )
        self.assertEqual(len(guide["categories"]), 8)
        self.assertEqual(len(guide["tasks"]), 32)
        self.assertEqual(len(guide["routines"]), 6)
        self.assertNotIn(private_values[1], json.dumps(guide["tasks"]))

        with tempfile.TemporaryDirectory(prefix="vaultlink_maintenance_") as folder:
            history_path = Path(folder) / "maintenance.jsonl"
            first = security_maintenance_center.append_maintenance_event(
                "defender-protection",
                "completed",
                path=history_path,
                time_utc="2026-07-01T12:00:00Z",
            )
            history, integrity = security_maintenance_center.load_maintenance_history(history_path)
            self.assertTrue(integrity["valid"])
            self.assertEqual(len(history), 1)
            self.assertEqual(first["sequence"], 1)
            self.assertEqual(first["previous_hash"], "0" * 64)
            self.assertEqual(first["cadence_days"], 7)

            report = security_maintenance_center.build_maintenance_report(
                guide,
                history,
                integrity,
                "windows-security",
                "weekly-security",
                "2026-07-16T12:00:00Z",
            )
            self.assertEqual(report["catalog"]["category_count"], 8)
            self.assertEqual(report["catalog"]["task_count"], 32)
            self.assertEqual(report["catalog"]["routine_count"], 6)
            self.assertEqual(report["summary"]["overdue"], 1)
            self.assertEqual(report["summary"]["not_started"], 31)
            self.assertEqual(report["summary"]["scheduled_tasks"], 1)
            self.assertEqual(report["summary"]["ever_completed_tasks"], 1)
            self.assertGreaterEqual(report["summary"]["schedule_score"], 0)
            self.assertLessEqual(report["summary"]["schedule_score"], 100)
            self.assertEqual(report["planning"]["next_7_days"], 3)
            self.assertEqual(report["planning"]["next_90_days"], 32)
            self.assertEqual(len(report["category_coverage"]), 8)
            self.assertEqual(len(report["routine_coverage"]), 6)
            self.assertEqual(len(report["priority_task_ids"]), 8)
            self.assertEqual(report["priority_task_ids"][0], "defender-protection")
            self.assertEqual(report["history"]["activity"]["completed_events"], 1)
            self.assertEqual(report["history"]["activity"]["reopened_events"], 0)
            self.assertTrue(report["history"]["integrity_valid"])
            self.assertEqual(report["online"]["api_version"], "0.36.0")
            self.assertEqual(report["online"]["signed_desktop_version"], "2026.07.16.2")
            serialized_report = json.dumps(report)
            dashboard = security_maintenance_center.dashboard_text(report)
            safe_summary = security_maintenance_center.safe_summary(report)
            safe_report = security_maintenance_center.safe_report_text(report)
            for private_value in private_values:
                self.assertNotIn(private_value, serialized_report)
                self.assertNotIn(private_value, dashboard)
                self.assertNotIn(private_value, safe_summary)
                self.assertNotIn(private_value, safe_report)
            self.assertNotIn("service_message", report["online"])
            self.assertNotIn("<textarea", Path(security_maintenance_center.__file__).read_text(encoding="utf-8").lower())

            snapshot_path = Path(folder) / "maintenance-snapshots.jsonl"
            first_snapshot = security_maintenance_center.append_maintenance_snapshot(
                report,
                path=snapshot_path,
                time_utc="2026-07-16T12:00:30Z",
            )
            invalid_snapshot_report = json.loads(json.dumps(report))
            invalid_snapshot_report["history"]["record_count"] = True
            with self.assertRaisesRegex(ValueError, "invalid history count"):
                security_maintenance_center.append_maintenance_snapshot(
                    invalid_snapshot_report,
                    path=Path(folder) / "invalid-snapshot.jsonl",
                )
            snapshots, snapshot_integrity = security_maintenance_center.load_snapshot_history(snapshot_path)
            self.assertTrue(snapshot_integrity["valid"])
            self.assertEqual(len(snapshots), 1)
            self.assertEqual(first_snapshot["sequence"], 1)
            self.assertEqual(first_snapshot["previous_hash"], "0" * 64)
            self.assertEqual(first_snapshot["scheduled_task_count"], 1)

            reopened = security_maintenance_center.append_maintenance_event(
                "defender-protection",
                "reopened",
                path=history_path,
                time_utc="2026-07-16T12:01:00Z",
            )
            self.assertEqual(reopened["previous_hash"], first["hash"])
            history, integrity = security_maintenance_center.load_maintenance_history(history_path)
            state = security_maintenance_center.maintenance_task_state(
                "defender-protection",
                history,
                "2026-07-16T12:02:00Z",
            )
            self.assertEqual(state["state"], "not-started")
            self.assertEqual(state["next_due_utc"], "")
            reopened_report = security_maintenance_center.build_maintenance_report(
                guide,
                history,
                integrity,
                "all",
                "all",
                "2026-07-16T12:02:00Z",
            )
            second_snapshot = security_maintenance_center.append_maintenance_snapshot(
                reopened_report,
                path=snapshot_path,
                time_utc="2026-07-16T12:02:30Z",
            )
            snapshots, snapshot_integrity = security_maintenance_center.load_snapshot_history(snapshot_path)
            self.assertTrue(snapshot_integrity["valid"])
            self.assertEqual(len(snapshots), 2)
            self.assertEqual(second_snapshot["previous_hash"], first_snapshot["hash"])
            comparison = security_maintenance_center.compare_maintenance_snapshots(
                snapshots[0],
                snapshots[1],
            )
            self.assertEqual(comparison["scheduled_task_count_change"], -1)
            self.assertEqual(comparison["history_record_count_change"], 1)
            self.assertFalse(comparison["customer_records_included"])
            comparison_text = security_maintenance_center.snapshot_comparison_text(comparison)
            self.assertIn("REMINDER COVERAGE", comparison_text.upper())
            archive = security_maintenance_center.build_maintenance_archive(
                history,
                integrity,
                snapshots,
                snapshot_integrity,
                "2026-07-16T12:03:00Z",
            )
            self.assertEqual(archive["event_record_count"], 2)
            self.assertEqual(archive["snapshot_record_count"], 2)
            self.assertFalse(archive["customer_records_included"])
            for private_value in private_values:
                self.assertNotIn(private_value, json.dumps(archive))

            calendar_text = security_maintenance_center.build_calendar_text(
                ["defender-protection", "windows-update"],
                history,
                datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc),
                event_id="a" * 16,
            )
            self.assertEqual(calendar_text.count("BEGIN:VEVENT"), 2)
            self.assertIn("VaultLink: Review Defender protection", calendar_text)
            for private_value in private_values:
                self.assertNotIn(private_value, calendar_text)

            concurrent_path = Path(folder) / "concurrent-maintenance.jsonl"
            concurrent_errors = []

            def append_concurrently():
                try:
                    security_maintenance_center.append_maintenance_event(
                        "audit-chain-verify",
                        "completed",
                        path=concurrent_path,
                    )
                except Exception as exc:
                    concurrent_errors.append(str(exc))

            threads = [threading.Thread(target=append_concurrently, daemon=True) for _index in range(12)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
                if thread.is_alive():
                    concurrent_errors.append("thread did not finish")
            concurrent_history, concurrent_integrity = security_maintenance_center.load_maintenance_history(concurrent_path)
            self.assertEqual(concurrent_errors, [])
            self.assertTrue(concurrent_integrity["valid"])
            self.assertEqual(len(concurrent_history), 12)

            concurrent_snapshot_path = Path(folder) / "concurrent-maintenance-snapshots.jsonl"
            snapshot_errors = []

            def snapshot_concurrently():
                try:
                    security_maintenance_center.append_maintenance_snapshot(
                        reopened_report,
                        path=concurrent_snapshot_path,
                    )
                except Exception as exc:
                    snapshot_errors.append(str(exc))

            snapshot_threads = [threading.Thread(target=snapshot_concurrently, daemon=True) for _index in range(10)]
            for thread in snapshot_threads:
                thread.start()
            for thread in snapshot_threads:
                thread.join(timeout=5)
                if thread.is_alive():
                    snapshot_errors.append("thread did not finish")
            concurrent_snapshots, concurrent_snapshot_integrity = security_maintenance_center.load_snapshot_history(
                concurrent_snapshot_path
            )
            self.assertEqual(snapshot_errors, [])
            self.assertTrue(concurrent_snapshot_integrity["valid"])
            self.assertEqual(len(concurrent_snapshots), 10)

            with mock.patch.object(security_maintenance_center, "_linklike", return_value=True):
                _linked_history, linked_integrity = security_maintenance_center.load_maintenance_history(history_path)
                self.assertFalse(linked_integrity["valid"])
                with self.assertRaisesRegex(ValueError, "link or junction"):
                    security_maintenance_center.append_maintenance_event(
                        "defender-protection",
                        "completed",
                        path=history_path,
                    )
                _linked_snapshots, linked_snapshot_integrity = security_maintenance_center.load_snapshot_history(
                    snapshot_path
                )
                self.assertFalse(linked_snapshot_integrity["valid"])
                with self.assertRaisesRegex(ValueError, "link or junction"):
                    security_maintenance_center.append_maintenance_snapshot(
                        reopened_report,
                        path=snapshot_path,
                    )

            directory_history = Path(folder) / "maintenance-history-directory"
            directory_history.mkdir()
            _directory_records, directory_integrity = security_maintenance_center.load_maintenance_history(
                directory_history
            )
            self.assertFalse(directory_integrity["valid"])
            self.assertIn("regular file", directory_integrity["message"])
            directory_snapshots = Path(folder) / "maintenance-snapshot-directory"
            directory_snapshots.mkdir()
            _directory_snapshot_records, directory_snapshot_integrity = security_maintenance_center.load_snapshot_history(
                directory_snapshots
            )
            self.assertFalse(directory_snapshot_integrity["valid"])
            self.assertIn("regular file", directory_snapshot_integrity["message"])

            lines = history_path.read_text(encoding="utf-8").splitlines()
            damaged = json.loads(lines[0])
            damaged["state"] = "PRIVATE-CUSTOMER-9812"
            lines[0] = json.dumps(damaged, sort_keys=True, separators=(",", ":"))
            history_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            _damaged_history, damaged_integrity = security_maintenance_center.load_maintenance_history(history_path)
            self.assertFalse(damaged_integrity["valid"])
            with self.assertRaisesRegex(ValueError, "integrity failed"):
                security_maintenance_center.append_maintenance_event(
                    "windows-update",
                    "completed",
                    path=history_path,
                )

            snapshot_lines = snapshot_path.read_text(encoding="utf-8").splitlines()
            damaged_snapshot = json.loads(snapshot_lines[0])
            damaged_snapshot["schedule_score"] = 99
            snapshot_lines[0] = json.dumps(damaged_snapshot, sort_keys=True, separators=(",", ":"))
            snapshot_path.write_text("\n".join(snapshot_lines) + "\n", encoding="utf-8")
            _damaged_snapshots, damaged_snapshot_integrity = security_maintenance_center.load_snapshot_history(
                snapshot_path
            )
            self.assertFalse(damaged_snapshot_integrity["valid"])
            with self.assertRaisesRegex(ValueError, "snapshot integrity failed"):
                security_maintenance_center.append_maintenance_snapshot(
                    reopened_report,
                    path=snapshot_path,
                )
            with self.assertRaisesRegex(ValueError, "verified snapshots"):
                security_maintenance_center.compare_maintenance_snapshots(
                    damaged_snapshot,
                    second_snapshot,
                )

        with self.assertRaisesRegex(ValueError, "fixed maintenance tasks"):
            security_maintenance_center.append_maintenance_event("C:/PRIVATE-DATA/file.txt", "completed")
        with self.assertRaisesRegex(ValueError, "valid UTC"):
            security_maintenance_center.build_maintenance_report(now_utc="C:/PRIVATE-DATA/file.txt")
        with self.assertRaisesRegex(ValueError, "not recognized"):
            security_maintenance_center.maintenance_task_state("arbitrary-task")
        with self.assertRaisesRegex(ValueError, "No trusted tool"):
            security_maintenance_center.launch_trusted_task_tool("arbitrary-task")
        with mock.patch.object(security_maintenance_center.locker, "launch_companion_script") as launch:
            self.assertEqual(
                security_maintenance_center.launch_trusted_task_tool("audit-chain-verify"),
                "Audit Log Viewer",
            )
            launch.assert_called_once_with("audit_log_viewer.py")

    def test_storage_retention_is_exact_bounded_hash_chained_and_private(self):
        tree = ast.parse(Path(storage_retention_center.__file__).read_text(encoding="utf-8"))
        locker_attributes = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "locker"
        }
        self.assertEqual(sorted(name for name in locker_attributes if not hasattr(locker, name)), [])
        self.assertEqual(len(storage_retention_center.AREA_SPECS), 8)
        self.assertEqual(len({item["id"] for item in storage_retention_center.AREA_SPECS}), 8)
        self.assertEqual(len(storage_retention_center.CONTROL_CHECKS), 10)
        self.assertEqual(sum(item[3] for item in storage_retention_center.CONTROL_CHECKS), 100)
        self.assertEqual(storage_retention_center.MAX_TEMP_ENTRIES, 5000)
        self.assertEqual(storage_retention_center.MAX_METADATA_ENTRIES, 5000)
        self.assertEqual(len(storage_retention_center.RECEIPT_FIELDS), 13)

        rows = [
            {
                "id": item["id"],
                "state": "not-inventoried" if item["id"] == "external-customer-data" else "present",
                "count_band": "2-10",
                "size_band": "under-64-kib",
                "age_band": "today",
                "metadata_attention": False,
                "private_path": "C:/PRIVATE-RETENTION/customer-name.txt",
            }
            for item in storage_retention_center.AREA_SPECS
        ]
        checks = [
            {
                "id": identifier,
                "passed": True,
                "detail": "C:/PRIVATE-RETENTION/customer-name.txt",
                "action": "Open D:/PRIVATE-RETENTION/master.key",
            }
            for identifier, _category, _title, _weight in storage_retention_center.CONTROL_CHECKS
        ]
        temp_scan = {
            "boundary_valid": True,
            "blocked": False,
            "capped": False,
            "errors": False,
            "total_entries": 4,
            "eligible_entries": 3,
            "eligible_candidates": 2,
            "total_bytes": 8192,
            "eligible_bytes": 4096,
            "newest": 0,
            "candidate_paths": [Path("C:/PRIVATE-RETENTION/customer-name.txt")],
        }
        report = storage_retention_center.build_retention_report(
            rows,
            checks,
            temp_scan,
            {
                "ok": True,
                "api_version": "0.34.0",
                "service_status": {"mode": "normal", "message": "PRIVATE-SERVICE"},
                "signed_release": {"version": "2026.07.15.4", "private": "PRIVATE-RELEASE"},
                "customer_records": ["PRIVATE-CUSTOMER"],
            },
            history=[{"private": "PRIVATE-HISTORY"}],
            integrity={"valid": True, "message": "C:/PRIVATE-RETENTION/receipt.txt"},
            generated_at_utc="2026-07-15T17:00:00Z",
        )
        self.assertEqual(report["area_count"], 8)
        self.assertEqual(report["summary"]["cleanup_area_count"], 1)
        self.assertEqual(report["summary"]["external_boundary_count"], 1)
        self.assertEqual(report["posture"], {"score": 100, "maximum": 100, "label": "ready", "passed": 10, "total": 10})
        self.assertEqual(report["temporary_workspace"]["eligible_band"], "2-10")
        self.assertEqual(report["online"]["api_version"], "0.34.0")
        self.assertEqual(report["online"]["signed_desktop_version"], "2026.07.15.4")
        self.assertEqual(report["online"]["service_mode"], "normal")
        self.assertEqual(report["receipts"]["record_count"], 1)

        report_text = json.dumps(report)
        safe_text = storage_retention_center.safe_report_text(report)
        safe_summary = storage_retention_center.safe_summary(report)
        for private_value in (
            "C:/PRIVATE-RETENTION",
            "D:/PRIVATE-RETENTION",
            "PRIVATE-SERVICE",
            "PRIVATE-RELEASE",
            "PRIVATE-CUSTOMER",
            "PRIVATE-HISTORY",
            "customer-name.txt",
            "master.key",
        ):
            self.assertNotIn(private_value, report_text)
            self.assertNotIn(private_value, safe_text)
            self.assertNotIn(private_value, safe_summary)

        with tempfile.TemporaryDirectory(prefix="vaultlink_retention_receipts_") as folder:
            history_path = Path(folder) / "retention.jsonl"
            first = storage_retention_center.append_receipt(
                report, "review", "attention", path=history_path, time_utc="2026-07-15T17:01:00Z"
            )
            second = storage_retention_center.append_receipt(
                report, "cleanup", "ok", 3, 4096, path=history_path, time_utc="2026-07-15T17:02:00Z"
            )
            history, integrity = storage_retention_center.load_receipt_history(history_path)
            self.assertTrue(integrity["valid"])
            self.assertEqual(len(history), 2)
            self.assertEqual(first["sequence"], 1)
            self.assertEqual(second["previous_hash"], first["hash"])
            self.assertEqual(second["removed_band"], "2-10")
            self.assertEqual(second["bytes_band"], "under-64-kib")
            receipt_text = history_path.read_text(encoding="utf-8")
            self.assertNotIn("PRIVATE-RETENTION", receipt_text)
            self.assertNotIn("customer-name.txt", receipt_text)

            concurrent_path = Path(folder) / "concurrent-retention.jsonl"
            threads = [
                threading.Thread(
                    target=lambda: storage_retention_center.append_receipt(report, path=concurrent_path),
                    daemon=True,
                )
                for _index in range(10)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
            concurrent_history, concurrent_integrity = storage_retention_center.load_receipt_history(concurrent_path)
            self.assertTrue(concurrent_integrity["valid"])
            self.assertEqual(len(concurrent_history), 10)

            with mock.patch.object(storage_retention_center, "_linklike", return_value=True):
                _linked_history, linked_integrity = storage_retention_center.load_receipt_history(history_path)
                self.assertFalse(linked_integrity["valid"])
                with self.assertRaisesRegex(ValueError, "link or junction"):
                    storage_retention_center.append_receipt(report, path=history_path)

            invalid_path = Path(folder) / "unexpected-field.jsonl"
            unexpected = dict(first)
            unexpected["private_contact"] = "PRIVATE-CONTACT"
            unexpected["hash"] = hashlib.sha256(
                storage_retention_center._canonical_receipt(unexpected)
            ).hexdigest()
            invalid_path.write_text(
                json.dumps(unexpected, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            unexpected_records, unexpected_integrity = storage_retention_center.load_receipt_history(invalid_path)
            self.assertEqual(unexpected_records, [])
            self.assertFalse(unexpected_integrity["valid"])
            self.assertIn("fixed schema", unexpected_integrity["message"])

            lines = history_path.read_text(encoding="utf-8").splitlines()
            damaged = json.loads(lines[0])
            damaged["posture_score"] = 1
            lines[0] = json.dumps(damaged, sort_keys=True, separators=(",", ":"))
            history_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            _records, damaged_integrity = storage_retention_center.load_receipt_history(history_path)
            self.assertFalse(damaged_integrity["valid"])
            with self.assertRaisesRegex(ValueError, "integrity failed"):
                storage_retention_center.append_receipt(report, path=history_path)

        with tempfile.TemporaryDirectory(prefix="vaultlink_retention_cleanup_") as folder:
            root = Path(folder)
            app_dir = root / "USBFileLocker"
            temp_dir = app_dir / "temp"
            temp_dir.mkdir(parents=True)
            old_file = temp_dir / "old-copy.bin"
            recent_file = temp_dir / "recent-copy.bin"
            old_folder = temp_dir / "old-folder"
            nested = old_folder / "nested.bin"
            old_folder.mkdir()
            old_file.write_bytes(b"old")
            recent_file.write_bytes(b"recent")
            nested.write_bytes(b"nested")
            outside = root / "outside-private.txt"
            outside.write_text("must remain", encoding="utf-8")
            now_value = 2_000_000_000.0
            old_time = now_value - storage_retention_center.EXPIRED_SECONDS - 60
            recent_time = now_value - 30
            for path in (old_file, nested, old_folder):
                os.utime(path, (old_time, old_time))
            os.utime(recent_file, (recent_time, recent_time))

            with mock.patch.object(locker, "APP_DIR", app_dir), mock.patch.object(
                locker, "TEMP_DIR", temp_dir
            ), mock.patch.object(locker, "log_event") as log_event:
                preview = storage_retention_center.scan_temp_workspace(now_value)
                self.assertTrue(preview["boundary_valid"])
                self.assertFalse(preview["blocked"])
                self.assertEqual(preview["eligible_candidates"], 2)
                self.assertEqual(preview["eligible_entries"], 3)
                with self.assertRaisesRegex(ValueError, "CLEAN TEMP"):
                    storage_retention_center.cleanup_expired_temp("clean temp", now_value)

                original_linklike = storage_retention_center._linklike
                with mock.patch.object(
                    storage_retention_center,
                    "_linklike",
                    side_effect=lambda path: Path(path).name == old_file.name or original_linklike(path),
                ):
                    linked_preview = storage_retention_center.scan_temp_workspace(now_value)
                self.assertTrue(linked_preview["blocked"])
                self.assertTrue(old_file.exists())

                result = storage_retention_center.cleanup_expired_temp("CLEAN TEMP", now_value)
                self.assertEqual(result["removed_candidates"], 2)
                self.assertEqual(result["removed_entries"], 3)
                self.assertFalse(old_file.exists())
                self.assertFalse(old_folder.exists())
                self.assertTrue(recent_file.exists())
                self.assertTrue(outside.exists())
                self.assertEqual(outside.read_text(encoding="utf-8"), "must remain")
                log_event.assert_called_once()

                with mock.patch.object(locker, "TEMP_DIR", root / "wrong-temp"):
                    blocked = storage_retention_center.scan_temp_workspace(now_value)
                    self.assertFalse(blocked["boundary_valid"])
                    self.assertTrue(blocked["blocked"])
                    with self.assertRaisesRegex(ValueError, "blocked"):
                        storage_retention_center.cleanup_expired_temp("CLEAN TEMP", now_value)

        with self.assertRaisesRegex(ValueError, "valid UTC"):
            storage_retention_center.build_retention_report(
                rows,
                checks,
                temp_scan,
                generated_at_utc="C:/PRIVATE-RETENTION/customer-name.txt",
            )

    def test_vault_health_checks_headers_and_exports_aggregate_data_only(self):
        with tempfile.TemporaryDirectory(prefix="vaultlink_health_") as folder:
            root = Path(folder)
            source = root / "private-client-name.txt"
            source.write_text("private contents", encoding="utf-8")
            key = {"key_id": "0123456789abcdef", "secret": b"K" * 32}
            header = locker.portable_lock_header(source.name, source.stat().st_size, key)
            locked_path = root / "private-client-name.txt.locked"
            locker.write_portable_locked(source, locked_path, header, key, "")

            healthy = vault_health_center.inspect_locked_file(locked_path, key["key_id"])
            self.assertEqual(healthy["health"], "Healthy")
            self.assertEqual(healthy["key_match"], "match")
            self.assertEqual(healthy["format"], "Portable")
            self.assertEqual(healthy["recovery"], "Key ID covered")

            multi_key = vault_health_center.inspect_locked_file(
                locked_path,
                {"1111111111111111", key["key_id"]},
            )
            self.assertEqual(multi_key["key_match"], "match")

            wrong_key = vault_health_center.inspect_locked_file(locked_path, "fedcba9876543210")
            self.assertEqual(wrong_key["key_match"], "mismatch")
            self.assertEqual(wrong_key["health"], "Healthy")
            self.assertEqual(wrong_key["recovery"], "Matching key needed")
            self.assertTrue(vault_health_center.row_needs_attention(wrong_key))
            self.assertFalse(vault_health_center.row_needs_attention(healthy))

            damaged_path = root / "damaged.locked"
            damaged_path.write_bytes(b"not-a-vaultlink-lock")
            damaged = vault_health_center.inspect_locked_file(damaged_path, key["key_id"])
            self.assertEqual(damaged["health"], "Unreadable")

            report = vault_health_center.build_privacy_safe_health_report(
                [healthy, wrong_key, damaged],
                scope="selected-folder",
                loaded_key=2,
            )
            self.assertEqual(report["locked_file_count"], 3)
            self.assertEqual(report["loaded_key_count"], 2)
            self.assertEqual(report["key_match_counts"]["match"], 1)
            self.assertEqual(report["key_match_counts"]["mismatch"], 1)
            self.assertEqual(report["recovery_counts"]["matching key needed"], 1)
            self.assertEqual(report["key_coverage_percent"], 33.3)
            serialized = json.dumps(report).lower()
            for forbidden in (
                "private-client-name",
                str(root).lower(),
                key["key_id"],
                "private contents",
            ):
                self.assertNotIn(forbidden, serialized)

            baseline_path = root / "health-baseline.json"
            report["unexpected_private_path"] = str(root)
            baseline = vault_health_center.save_health_baseline(report, baseline_path)
            loaded_baseline = vault_health_center.load_health_baseline(baseline_path)
            self.assertEqual(loaded_baseline["baseline_type"], "vaultlink-vault-health-aggregate")
            self.assertEqual(loaded_baseline["locked_file_count"], 3)
            self.assertEqual(loaded_baseline["loaded_key_count"], 2)
            self.assertEqual(baseline["health_counts"]["healthy"], 2)
            baseline_text = baseline_path.read_text(encoding="utf-8").lower()
            self.assertNotIn("unexpected_private_path", baseline_text)
            for forbidden in ("private-client-name", str(root).lower(), key["key_id"], "private contents"):
                self.assertNotIn(forbidden, baseline_text)

            safe_summary = vault_health_center.build_safe_summary_text(report).lower()
            self.assertIn("locked items: 3", safe_summary)
            self.assertNotIn("private-client-name", safe_summary)
            self.assertNotIn(str(root).lower(), safe_summary)
            self.assertNotIn(key["key_id"], safe_summary)

            previous = dict(report)
            previous["health_counts"] = {"healthy": 1, "review": 1, "unreadable": 1}
            previous["recovery_counts"] = {"review": 2, "unreadable": 1}
            comparison = vault_health_center.compare_health_reports(previous, report)
            self.assertEqual(comparison["comparison_type"], "vaultlink-vault-health-aggregate")
            self.assertEqual(comparison["trend"], "improved")
            baseline_comparison = vault_health_center.compare_health_reports(
                vault_health_center.baseline_as_health_report(loaded_baseline),
                report,
            )
            self.assertEqual(baseline_comparison["trend"], "unchanged")
            comparison_text = json.dumps(comparison).lower()
            self.assertNotIn("private-client-name", comparison_text)
            self.assertNotIn(str(root).lower(), comparison_text)

    def test_locked_file_search_honors_stop_event_before_walking(self):
        stop_event = mock.Mock()
        stop_event.is_set.return_value = True
        with tempfile.TemporaryDirectory(prefix="vaultlink_cancelled_scan_") as folder:
            (Path(folder) / "sample.locked").write_bytes(b"not-read")
            results = locker.find_locked_files_in_roots([folder], stop_event=stop_event)
        self.assertEqual(results, [])

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
        self.assertTrue(callable(owner_update_lab.launch_verified_lab_runtime))

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

    def test_owner_lab_runtime_extracts_verified_candidate_into_private_runtime(self):
        with tempfile.TemporaryDirectory(prefix="vaultlink_owner_lab_runtime_") as temp_dir:
            root = Path(temp_dir)
            lab_dir = root / "owner_update_lab"
            candidate_dir = lab_dir / "candidate"
            runtime_root = lab_dir / "runtime"
            candidate_dir.mkdir(parents=True)
            manifest_path = candidate_dir / "windows-manifest.json"
            package_path = candidate_dir / "VaultLink-Windows-test.zip"
            manifest = {"version": "9999.2", "preserves_local_app_data": True}
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with zipfile.ZipFile(package_path, "w") as archive:
                archive.writestr("usb_file_locker.py", "print('verified lab runtime')")
                archive.writestr("README.txt", "safe package")
            digest = hashlib.sha256(package_path.read_bytes()).hexdigest()
            report = {
                "manifest_filename": manifest_path.name,
                "package_filename": package_path.name,
                "sha256": digest,
            }
            with mock.patch.object(owner_update_lab, "LAB_DIR", lab_dir), \
                    mock.patch.object(owner_update_lab, "CANDIDATE_DIR", candidate_dir), \
                    mock.patch.object(owner_update_lab, "LAB_RUNTIME_DIR", runtime_root), \
                    mock.patch.object(owner_update_lab, "verify_candidate_files", return_value=manifest):
                runtime = owner_update_lab.prepare_verified_lab_runtime(report)
            self.assertEqual(runtime["version"], "9999.2")
            self.assertEqual(runtime["sha256"], digest)
            self.assertEqual(runtime["extracted_files"], 2)
            self.assertTrue(runtime["entrypoint"].is_file())
            marker = json.loads((runtime["runtime_dir"] / ".vaultlink-lab-runtime.json").read_text(encoding="utf-8"))
            self.assertEqual(marker["runtime_type"], "vaultlink-owner-lab")
            self.assertFalse(marker["published"])
            self.assertNotIn(str(root).lower(), json.dumps(marker).lower())

    def test_owner_lab_launch_sets_private_mode_without_publishing(self):
        runtime_dir = Path("C:/safe-owner-lab/runtime")
        runtime = {
            "version": "9999.2",
            "sha256": "a" * 64,
            "runtime_dir": runtime_dir,
            "entrypoint": runtime_dir / "usb_file_locker.py",
            "extracted_files": 32,
        }
        process = SimpleNamespace(pid=4242)
        with mock.patch.object(owner_update_lab.release_builder, "authorize_owner_release"), \
                mock.patch.object(owner_update_lab, "validate_repo", side_effect=lambda path, _marker: Path(path)), \
                mock.patch.object(owner_update_lab, "load_candidate_report", return_value={"status": "verified"}), \
                mock.patch.object(owner_update_lab, "candidate_is_current", return_value=(True, "ready")), \
                mock.patch.object(owner_update_lab, "prepare_verified_lab_runtime", return_value=runtime), \
                mock.patch.object(owner_update_lab.locker, "pythonw_path", return_value=Path("C:/Python/pythonw.exe")), \
                mock.patch.object(owner_update_lab.subprocess, "Popen", return_value=process) as popen, \
                mock.patch.object(owner_update_lab, "append_lab_history") as history:
            result = owner_update_lab.launch_verified_lab_runtime(
                "C:/app",
                "C:/api",
                "D:/owner.key",
                "2026.07.12.9",
                "notes",
            )
        self.assertEqual(result["process_id"], 4242)
        environment = popen.call_args.kwargs["env"]
        self.assertEqual(environment["VAULTLINK_LAB_MODE"], "1")
        self.assertEqual(environment["VAULTLINK_LAB_RUNTIME_VERSION"], "9999.2")
        self.assertEqual(popen.call_args.kwargs["cwd"], str(runtime_dir))
        history.assert_called_once_with("lab_runtime_launch", "ok", {"version": "9999.2", "sha256": "a" * 64})

    def test_owner_release_history_is_hash_chained_and_privacy_safe(self):
        with tempfile.TemporaryDirectory(prefix="vaultlink_owner_history_") as temp_dir:
            history_path = Path(temp_dir) / "release_history.jsonl"
            with mock.patch.object(owner_update_lab, "HISTORY_FILE", history_path):
                owner_update_lab.append_lab_history(
                    "candidate_verified",
                    "ok",
                    {
                        "version": "9999.1",
                        "sha256": "a" * 64,
                        "test_count": 48,
                        "owner_key_path": "D:/master_usb_file_locker.key",
                        "secret": "DO-NOT-STORE",
                    },
                )
                entries, integrity = owner_update_lab.load_lab_history()
                self.assertTrue(integrity["valid"])
                self.assertEqual(len(entries), 1)
                self.assertEqual(entries[0]["details"]["version"], "9999.1")
                serialized = history_path.read_text(encoding="utf-8")
                self.assertNotIn("master_usb_file_locker.key", serialized)
                self.assertNotIn("DO-NOT-STORE", serialized)

                damaged = json.loads(serialized)
                damaged["details"]["version"] = "tampered"
                history_path.write_text(json.dumps(damaged) + "\n", encoding="utf-8")
                _entries, damaged_integrity = owner_update_lab.load_lab_history()
                self.assertFalse(damaged_integrity["valid"])

    def test_owner_package_inspector_reports_only_signed_zip_entries(self):
        with tempfile.TemporaryDirectory(prefix="vaultlink_package_info_") as temp_dir:
            candidate_dir = Path(temp_dir)
            manifest_path = candidate_dir / "windows-manifest.json"
            package_path = candidate_dir / "VaultLink-Windows-test.zip"
            manifest = {"version": "9999.1", "preserves_local_app_data": True}
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with zipfile.ZipFile(package_path, "w") as archive:
                archive.writestr("usb_file_locker.py", "print('safe')")
                archive.writestr("Run USB File Locker.bat", "@echo off")
                archive.writestr("README.txt", "safe")
            report = {
                "manifest_filename": manifest_path.name,
                "package_filename": package_path.name,
            }
            with mock.patch.object(owner_update_lab, "CANDIDATE_DIR", candidate_dir), \
                    mock.patch.object(owner_update_lab, "verify_candidate_files", return_value=manifest):
                info = owner_update_lab.candidate_package_info(report)
            self.assertEqual(info["entry_count"], 3)
            self.assertEqual(info["python_files"], 1)
            self.assertEqual(info["launchers"], 1)
            self.assertEqual(info["entries"], ["README.txt", "Run USB File Locker.bat", "usb_file_locker.py"])

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

    def test_update_verification_receipt_is_signed_and_privacy_safe(self):
        private_key = Ed25519PrivateKey.generate()
        public_raw = private_key.public_key().public_bytes_raw()
        public_b64 = base64.urlsafe_b64encode(public_raw).rstrip(b"=").decode("ascii")
        key_id = hashlib.sha256(public_raw).hexdigest()[:16]
        manifest = {
            "schema_version": 1,
            "product": "USB File Locker",
            "platform": "windows-source",
            "version": "9999.2",
            "minimum_supported_version": "2026.07.12.9",
            "published_at_utc": "2026-07-13T20:00:00Z",
            "package_filename": "VaultLink-Windows-9999.2.zip",
            "download_path": "/api/v1/updates/windows/download",
            "sha256": "a" * 64,
            "size_bytes": 4096,
            "signing_key_id": key_id,
            "notes": ["Privacy-safe receipt test"],
            "preserves_local_app_data": True,
        }
        manifest["signature"] = base64.urlsafe_b64encode(
            private_key.sign(locker.canonical_update_manifest_bytes(manifest))
        ).rstrip(b"=").decode("ascii")
        validated = dict(manifest, api_version="test-api")
        with (
            mock.patch.object(locker, "UPDATE_SIGNING_PUBLIC_KEY_B64", public_b64),
            mock.patch.object(locker, "UPDATE_SIGNING_KEY_ID", key_id),
        ):
            receipt = locker.update_verification_receipt(validated, "2026-07-13T21:00:00Z")
        self.assertTrue(receipt["signature_verified"])
        self.assertTrue(receipt["app_data_preserved"])
        self.assertEqual(receipt["package_sha256"], "a" * 64)
        self.assertEqual(receipt["verified_at_utc"], "2026-07-13T21:00:00Z")
        serialized = json.dumps(receipt).lower()
        for forbidden in (
            '"license_key":',
            '"usb_secret":',
            '"pin":',
            '"password":',
            "do-not-store-secret-value",
            "c:\\\\users",
        ):
            self.assertNotIn(forbidden, serialized)

        tampered = dict(validated, package_filename="VaultLink-Windows-tampered.zip")
        with (
            mock.patch.object(locker, "UPDATE_SIGNING_PUBLIC_KEY_B64", public_b64),
            mock.patch.object(locker, "UPDATE_SIGNING_KEY_ID", key_id),
        ):
            with self.assertRaisesRegex(ValueError, "signature did not verify"):
                locker.update_verification_receipt(tampered)

    def test_update_size_formatting(self):
        self.assertEqual(locker.format_update_size(511), "511 bytes")
        self.assertEqual(locker.format_update_size(1536), "1.5 KB")
        self.assertEqual(locker.format_update_size(3 * 1024 * 1024), "3.0 MB")

    def test_update_readiness_is_signed_and_contains_no_local_paths(self):
        private_key = Ed25519PrivateKey.generate()
        public_raw = private_key.public_key().public_bytes_raw()
        public_b64 = base64.urlsafe_b64encode(public_raw).rstrip(b"=").decode("ascii")
        key_id = hashlib.sha256(public_raw).hexdigest()[:16]
        manifest = {
            "schema_version": 1,
            "product": "USB File Locker",
            "platform": "windows-source",
            "version": "9999.3",
            "minimum_supported_version": "2026.07.12.9",
            "published_at_utc": "2026-07-13T20:00:00Z",
            "package_filename": "VaultLink-Windows-9999.3.zip",
            "download_path": "/api/v1/updates/windows/download",
            "sha256": "b" * 64,
            "size_bytes": 4096,
            "signing_key_id": key_id,
            "notes": ["Readiness test"],
            "preserves_local_app_data": True,
        }
        manifest["signature"] = base64.urlsafe_b64encode(
            private_key.sign(locker.canonical_update_manifest_bytes(manifest))
        ).rstrip(b"=").decode("ascii")
        with tempfile.TemporaryDirectory(prefix="vaultlink_readiness_") as folder:
            root = Path(folder)
            data_root = root / "data"
            data_root.mkdir()
            with (
                mock.patch.object(locker, "UPDATE_SIGNING_PUBLIC_KEY_B64", public_b64),
                mock.patch.object(locker, "UPDATE_SIGNING_KEY_ID", key_id),
            ):
                report = locker.update_readiness_report(manifest, root, data_root)
                self.assertTrue(report["ready_for_automatic_install"])
                (root / ".git").mkdir()
                git_report = locker.update_readiness_report(manifest, root, data_root)
            self.assertEqual(git_report["installation_mode"], "git-manual")
            self.assertFalse(git_report["ready_for_automatic_install"])
            self.assertNotIn(str(root).lower(), json.dumps(report).lower())

    def test_update_activity_summary_excludes_paths_and_unrelated_events(self):
        records = [
            {"sequence": 1, "time_utc": "2026-07-13T20:00:00Z", "event_id": "event-one", "action": "file_lock", "result": "success"},
            {"sequence": 2, "time_utc": "2026-07-13T20:01:00Z", "event_id": "event-two", "action": "application_update_completed", "result": "success"},
        ]
        with tempfile.TemporaryDirectory(prefix="vaultlink_update_activity_") as folder:
            status_path = Path(folder) / "update-status.json"
            status_path.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "version": "2026.07.13.3",
                        "time_utc": "2026-07-13T20:01:00Z",
                        "backup_dir": r"C:\Users\Person\private-backup",
                    }
                ),
                encoding="utf-8",
            )
            report = locker.update_activity_summary(records, status_path)
        self.assertEqual(len(report["events"]), 1)
        self.assertEqual(report["events"][0]["event_id"], "event-two")
        self.assertTrue(report["latest_install"]["backup_created"])
        serialized = json.dumps(report).lower()
        self.assertNotIn("private-backup", serialized)
        self.assertNotIn("file_lock", serialized)

    def test_install_and_verified_copy_use_separate_update_operations(self):
        class ImmediateThread:
            def __init__(self, target, **_kwargs):
                self.target = target

            def start(self):
                self.target()

        manifest = {
            "version": "9999.4",
            "size_bytes": 4096,
            "package_filename": "VaultLink-Windows-9999.4.zip",
            "update_available": True,
        }
        with tempfile.TemporaryDirectory(prefix="vaultlink_update_workflows_") as folder:
            root = Path(folder)
            app = SimpleNamespace(
                latest_update_manifest=manifest,
                update_operation="",
                update_button=FakeButton(),
                update_window=None,
                update_results=queue.Queue(),
                status=FakeVar(),
                refresh_update_window=mock.Mock(),
                after=mock.Mock(),
                poll_update_results=mock.Mock(),
            )
            with (
                mock.patch.object(locker, "RUNTIME_DIR", root),
                mock.patch.object(locker.messagebox, "askyesno", return_value=True),
                mock.patch.object(locker, "load_settings", return_value={}),
                mock.patch.object(locker, "load_license_state", return_value={}),
                mock.patch.object(locker, "stage_windows_update", return_value=(root, root / "manifest", root / "package")),
                mock.patch.object(locker.threading, "Thread", ImmediateThread),
            ):
                locker.USBFileLocker.install_latest_update(app)
            self.assertEqual(app.update_operation, "stage")
            self.assertEqual(app.update_results.get_nowait()[0], "stage")

            app.update_operation = ""
            target = root / manifest["package_filename"]
            with (
                mock.patch.object(locker.filedialog, "asksaveasfilename", return_value=str(target)),
                mock.patch.object(locker, "load_settings", return_value={}),
                mock.patch.object(locker, "load_license_state", return_value={}),
                mock.patch.object(locker, "download_windows_update_package", return_value=target),
                mock.patch.object(locker.threading, "Thread", ImmediateThread),
            ):
                locker.USBFileLocker.download_latest_update_copy(app)
            self.assertEqual(app.update_operation, "copy")
            copy_result = app.update_results.get_nowait()
            self.assertEqual(copy_result[0], "copy")
            self.assertEqual(copy_result[1], target)

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

    def test_required_signed_update_ignores_optional_auto_update_setting(self):
        manifest = {
            "version": "9999.2",
            "update_available": True,
            "current_version_supported": False,
        }
        app = SimpleNamespace(
            update_results=queue.Queue(),
            update_operation="check",
            update_button=FakeButton(state="disabled"),
            latest_update_manifest=None,
            settings={"auto_install_signed_updates": False},
            status=FakeVar(),
            refresh_update_window=mock.Mock(),
            schedule_required_update_install=mock.Mock(),
        )
        app.update_results.put(("check", manifest, "", True))
        with (
            mock.patch.object(locker, "save_settings"),
            mock.patch.object(locker, "log_event") as log,
            mock.patch.object(locker.messagebox, "askyesno") as ask,
        ):
            locker.USBFileLocker.poll_update_results(app)
        app.schedule_required_update_install.assert_called_once_with()
        ask.assert_not_called()
        self.assertIn("Required signed update 9999.2", app.status.value)
        self.assertTrue(any(call.args[0] == "application_required_update" for call in log.call_args_list))

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
