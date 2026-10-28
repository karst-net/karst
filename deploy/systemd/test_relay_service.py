# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("relay_service", Path(__file__).with_name("relay-service.py"))
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        for name, contents in {"relay.key": "private", "relays.json": "{}", "roster.toml": "# empty", "tls/relay.crt": "cert", "tls/relay.key": "private"}.items():
            path = self.directory / name
            path.parent.mkdir(exist_ok=True)
            path.write_text(contents)
        self.desired = {"schema_version": 1, "ponor": {"enabled": True}}

    def write_manifest(self, ponor="true"):
        path = self.directory / "relay-service.toml"
        path.write_text(f'schema_version=1\n[ponor]\nenabled={ponor}\n')
        return path

    def test_manifest_strict_and_explicit(self):
        self.assertEqual(relay.manifest(self.write_manifest()), self.desired)
        with self.assertRaises(relay.Invalid):
            relay.manifest(self.write_manifest("1"))
        path = self.write_manifest()
        path.write_text(path.read_text() + "typo=true\n")
        with self.assertRaises(relay.Invalid):
            relay.manifest(path)

    def test_modes_reconcile_independently(self):
        self.assertEqual(relay.operations(self.desired, relay.DEFAULT_UNIT), [["start", relay.DEFAULT_UNIT]])
        self.desired["ponor"]["enabled"] = False
        self.assertEqual(relay.operations(self.desired, relay.DEFAULT_UNIT), [["stop", relay.DEFAULT_UNIT]])

    def test_bootstrap_credentials_are_validated_without_rewriting_material(self):
        before = {str(path): path.read_bytes() for path in self.directory.rglob("*") if path.is_file()}
        relay.validate_material(self.directory, self.desired)
        self.assertEqual(before, {str(path): path.read_bytes() for path in self.directory.rglob("*") if path.is_file()})
        (self.directory / "relay.key").unlink()
        with self.assertRaises(relay.Invalid):
            relay.validate_material(self.directory, self.desired)

    def test_snapshot_preserves_previous_success_and_private_permissions(self):
        relay.save_applied(self.directory, b"old manifest")
        relay.save_applied(self.directory, b"new manifest")
        target = self.directory / "relay-service.applied.toml"
        self.assertEqual(target.read_bytes(), b"new manifest")
        self.assertEqual(target.with_suffix(".toml.previous").read_bytes(), b"old manifest")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_status_distinguishes_absent_from_inactive_and_stays_unprobed(self):
        with patch.object(relay, "systemctl", return_value=subprocess.CompletedProcess([], 0, stdout="LoadState=not-found\nActiveState=inactive\nSubState=dead\n")):
            absent = relay.status(self.desired, relay.DEFAULT_UNIT)
        self.assertEqual(absent["ponor"]["state"], "absent")
        self.assertEqual(absent["ponor"]["health"], "unprobed")
        with patch.object(relay, "systemctl", return_value=subprocess.CompletedProcess([], 0, stdout="LoadState=loaded\nActiveState=active\nSubState=running\n")):
            running = relay.status(self.desired, relay.DEFAULT_UNIT)
        self.assertEqual(running["ponor"]["state"], "active")
        self.assertEqual(running["ponor"]["health"], "unprobed")

    def test_cli_plan_is_read_only_and_does_not_disclose_secrets(self):
        path = self.write_manifest()
        result = subprocess.run(["python3", str(Path(relay.__file__)), "plan", "--directory", str(self.directory)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        import json
        plan = json.loads(result.stdout)
        self.assertEqual(plan["desired"], relay.manifest(path))
        self.assertIn(relay.DEFAULT_UNIT, plan["commands"][0])
        self.assertFalse((self.directory / "relay-service.applied.toml").exists())

    @unittest.skipUnless(os.environ.get("KARST_SYSTEMD_LIFECYCLE_TEST") == "1", "requires root and real systemd")
    def test_real_systemd_lifecycle(self):
        import json
        import uuid
        unit = f"karst-relay-test-{uuid.uuid4().hex[:12]}.service"
        unit_path = Path("/etc/systemd/system") / unit
        unit_path.write_text(
            "[Unit]\nDescription=karst relay test stand-in\n"
            "[Service]\nExecStart=/bin/sleep 600\n"
            "[Install]\nWantedBy=multi-user.target\n")
        subprocess.run(["systemctl", "daemon-reload"], check=True)

        def cleanup():
            subprocess.run(["systemctl", "stop", unit], check=False)
            unit_path.unlink(missing_ok=True)
            subprocess.run(["systemctl", "daemon-reload"], check=False)

        self.addCleanup(cleanup)

        self.write_manifest()
        argv = ["python3", str(Path(relay.__file__)), "apply", "--directory", str(self.directory), "--unit", unit, "--acknowledge-process-change"]
        status_argv = ["python3", str(Path(relay.__file__)), "status", "--directory", str(self.directory), "--unit", unit]

        subprocess.run(argv, check=True, capture_output=True, text=True)
        self.assertEqual(json.loads(subprocess.run(status_argv, check=True, capture_output=True, text=True).stdout)["ponor"]["state"], "active")

        self.write_manifest(ponor="false")
        subprocess.run(argv, check=True, capture_output=True, text=True)
        self.assertEqual(json.loads(subprocess.run(status_argv, check=True, capture_output=True, text=True).stdout)["ponor"]["state"], "inactive")

    def test_failed_apply_does_not_replace_last_successful_manifest(self):
        self.write_manifest(ponor="false")
        relay.save_applied(self.directory, b"previous success")
        binary = self.directory / "systemctl"
        log = self.directory / "commands.log"
        binary.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(log) + '"\ncase "$*" in "stop "*) exit 7;; esac\n')
        binary.chmod(0o755)
        argv = ["python3", str(Path(relay.__file__)), "apply", "--directory", str(self.directory)]
        env = {**os.environ, "PATH": str(self.directory) + os.pathsep + os.environ["PATH"]}
        denied = subprocess.run(argv, env=env, capture_output=True, text=True)
        self.assertNotEqual(denied.returncode, 0)
        self.assertFalse(log.exists(), "missing acknowledgment must perform no systemd operations")
        failed = subprocess.run([*argv, "--acknowledge-process-change"], env=env, capture_output=True, text=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("earlier actions may have completed", failed.stderr)
        self.assertIn("stop", log.read_text())
        self.assertEqual((self.directory / "relay-service.applied.toml").read_bytes(), b"previous success")

    def test_cli_failure_never_records_success_or_leaks_systemd_diagnostics(self):
        self.write_manifest()
        binary = self.directory / "systemctl"
        secret = "test-secret-do-not-print"
        binary.write_text(f'#!/bin/sh\necho "{secret}" >&2\nexit 7\n')
        binary.chmod(0o755)
        result = subprocess.run(["python3", str(Path(relay.__file__)), "apply", "--directory", str(self.directory), "--acknowledge-process-change"], env={**os.environ, "PATH": str(self.directory) + os.pathsep + os.environ["PATH"]}, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertFalse((self.directory / "relay-service.applied.toml").exists())


if __name__ == "__main__":
    unittest.main()
