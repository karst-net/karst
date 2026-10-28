# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.

"""Exercise the exact installer embedded in the console download."""
import base64
import copy
import hashlib
import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

source = Path(__file__).resolve().parents[2] / "web/console/src/installation/relay-install.py"
spec = importlib.util.spec_from_file_location("relay_install", source)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.state = self.directory / "state"
        (self.state / "tls").mkdir(parents=True)
        (self.state / "tls/relay.crt").write_text("existing trusted certificate")
        (self.state / "tls/relay.key").write_text("existing private key")
        (self.state / "relay.key").write_text("existing relay seed")
        (self.state / "management.json").write_text("do not modify control credentials")
        self.settings = {"schema_version": 1, "address": "203.0.113.7:443", "tls_server_name": "relay.example.com", "region": "denver", "image": "ghcr.io/karst-net/karst-relay:dev", "control_image": "ghcr.io/karst-net/karst-control:dev", "location": None}
        self.config = {"services": {"control": {"image": "control:current", "volumes": [{"type": "bind", "source": str(self.state), "target": "/var/lib/karst"}], "environment": {"PRIVATE": "must not be logged"}}, "relay": {"ports": [{"target": 443, "published": "443", "protocol": "tcp"}], "volumes": [{"source": str(self.state), "target": "/var/lib/karst"}]}}}
        self.calls = []
        self.failure = None
        self.capability = "managed-roster-v1"
        self.project_directory = str(self.directory)
        self.public = base64.b64encode(bytes(2592)).decode()
        self.identity = hashlib.sha256(b"karst-relay-id-v1" + bytes(2592)).hexdigest()

    def fake_run(self, command, capture=False):
        self.calls.append(command)
        if self.failure and self.failure(command):
            raise subprocess.CalledProcessError(1, command, stderr="secret Docker diagnostic")
        output = ""
        if "--relay-installation-capabilities" in command:
            output = self.capability
        elif "--format" in command and "config" in command:
            output = json.dumps(self.config)
        elif "pubkey" in command:
            output = f"relay_id {self.identity}\nidentity_pk {self.public}\n"
        elif "inspect" in command:
            output = json.dumps({"com.docker.compose.project.working_dir": self.project_directory})
        elif "ps" in command:
            output = json.dumps([{"ID": service + "-id", "Service": service, "State": "running"} for service in ("control", "relay")])
        elif "-pubkey" in command or "-pubout" in command:
            output = "matching public certificate key"
        return subprocess.CompletedProcess(command, 0, output, "")

    def apply(self):
        with patch.object(installer, "run", self.fake_run):
            installer.apply(self.directory, self.settings)

    def test_installs_strict_writer_without_overwriting_secrets_and_retries(self):
        before = {name: (self.state / name).read_bytes() for name in ("relay.key", "tls/relay.key", "tls/relay.crt", "management.json")}
        self.apply()
        install = self.state / "relay-install"
        receipt = json.loads((install / "receipt.json").read_text())
        self.assertEqual(receipt["entry"]["identity_key"], self.public)
        self.assertNotIn("PRIVATE", (install / "receipt.json").read_text())
        self.assertEqual(json.loads((install / "status.json").read_text()), {"state": "runtime_started", "ready": False})
        self.assertEqual(json.loads((install / "compose.json").read_text())["services"]["control"]["environment"]["KARST_RELAY_REQUIRE_MANAGED"], "true")
        self.assertIn("default deny", (self.state / "roster.toml").read_text())
        self.assertEqual((self.state / "relay-roster.id").read_text().strip(), self.identity)
        self.assertLess(next(i for i, call in enumerate(self.calls) if "stop" in call), next(i for i, call in enumerate(self.calls) if "up" in call))
        self.apply()
        for name, contents in before.items():
            self.assertEqual((self.state / name).read_bytes(), contents)
        self.assertEqual((install / "receipt.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((install / "compose.json").stat().st_mode & 0o777, 0o600)

    def test_start_failure_records_retry_without_false_success_or_stale_receipt(self):
        self.apply()
        self.failure = lambda args: "up" in args
        with self.assertRaises(subprocess.CalledProcessError):
            self.apply()
        install = self.state / "relay-install"
        self.assertFalse((install / "receipt.json").exists())
        self.assertEqual(json.loads((install / "status.json").read_text())["state"], "failed")
        self.failure = None
        self.apply()
        self.assertTrue((install / "receipt.json").exists())

    def test_project_name_collision_cannot_stop_another_deployment(self):
        self.project_directory = "/another/deployment"
        with self.assertRaises(installer.Invalid):
            self.apply()
        self.assertFalse((self.state / "relay-install").exists())
        self.assertFalse(any("stop" in call for call in self.calls))

    def test_unsupported_control_never_changes_files_or_stops_services(self):
        self.capability = "older"
        with self.assertRaises(installer.Invalid):
            self.apply()
        self.assertFalse((self.state / "relay-install").exists())
        self.assertFalse(any("stop" in call for call in self.calls))

    def test_rejects_other_writer_and_unsafe_merged_execution_before_restart(self):
        for mutate in (
            lambda c: c["services"]["control"]["environment"].update(KARST_RELAY_ROSTER_FILE="/another/roster"),
            lambda c: c["services"]["relay"].update(privileged=True),
            lambda c: c["services"]["relay"]["ports"].append({"target": 443, "published": "444"}),
        ):
            with self.subTest(mutate=mutate):
                original = copy.deepcopy(self.config)
                mutate(self.config)
                with self.assertRaises(installer.Invalid):
                    self.apply()
                self.assertFalse(any("stop" in call for call in self.calls))
                self.config = original

    def test_registry_mismatch_and_changed_handoff_require_explicit_migration(self):
        (self.state / "relays.json").write_text(json.dumps({"relays": [{**self.settings, "address": "203.0.113.8:443", "identity_key": self.public}]}))
        with self.assertRaises(installer.Invalid):
            self.apply()
        self.assertFalse(any("stop" in call for call in self.calls))
        (self.state / "relays.json").unlink()
        self.apply()
        self.calls = []
        self.settings["region"] = "different"
        with self.assertRaises(installer.Invalid):
            self.apply()
        self.assertFalse(any("stop" in call for call in self.calls))

    def test_settings_reject_injection_invalid_ip_ports_images_and_location(self):
        for key, value in (("address", "relay.example.com:443"), ("address", "203.0.113.7:0"), ("address", "203.0.113.7:65536"), ("tls_server_name", 'x\"; evil'), ("region", 'x\"\nroster="other"'), ("image", "evil/image:latest"), ("location", {"lat": 91, "lon": 0})):
            with self.subTest(key=key, value=value), self.assertRaises((installer.Invalid, ValueError)):
                installer.validate({**self.settings, key: value})
        self.assertEqual(installer.validate({**self.settings, "address": "[2001:db8::7]:443"}), 443)

    def test_real_compose_normalizes_generated_overlay(self):
        binary = os.environ.get("KARST_COMPOSE_BIN")
        command = [binary] if binary else ["docker", "compose"] if shutil.which("docker") else None
        if not command:
            self.skipTest("Docker Compose CLI unavailable")
        reference = Path(__file__).with_name("docker-compose.yml").resolve()
        # Relative state mounts resolve against the explicit project directory.
        overlay = self.directory / "overlay.json"
        overlay.write_text(json.dumps(installer.overlay(self.state, self.settings)))
        result = subprocess.run([*command, "--project-directory", str(self.directory), "-f", str(reference), "-f", str(overlay), "config", "--format", "json"], check=True, capture_output=True, text=True)
        config = json.loads(result.stdout)
        installer.check_merged(config, self.state, self.settings)
        self.assertEqual(config["services"]["control"]["environment"]["KARST_RELAY_REQUIRE_MANAGED"], "true")
        self.assertEqual(config["services"]["relay"]["command"], ["--config", "/var/lib/karst/relay-install/relay.toml"])
        overlay.write_text(json.dumps(installer.overlay(self.state, {**self.settings, "address": "203.0.113.7:444"})))
        result = subprocess.run([*command, "--project-directory", str(self.directory), "-f", str(reference), "-f", str(overlay), "config", "--format", "json"], check=True, capture_output=True, text=True)
        with self.assertRaises(installer.Invalid):
            installer.check_merged(json.loads(result.stdout), self.state, {**self.settings, "address": "203.0.113.7:444"})

    def test_real_tls_hostname_and_private_key_validation(self):
        if not shutil.which("openssl"):
            self.skipTest("OpenSSL unavailable")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=relay.example.com", "-addext", "subjectAltName=DNS:relay.example.com", "-addext", "basicConstraints=critical,CA:FALSE", "-keyout", str(self.state / "tls/relay.key"), "-out", str(self.state / "tls/relay.crt")], check=True, capture_output=True)
        original_run = installer.run
        def with_real_openssl(command, capture=False):
            if command[0] == "openssl":
                return original_run(command, capture)
            return self.fake_run(command, capture)
        with patch.object(installer, "run", with_real_openssl):
            self.assertEqual(installer.inspect(self.directory, self.settings), self.state)
            with self.assertRaises(installer.Invalid):
                installer.inspect(self.directory, {**self.settings, "tls_server_name": "wrong.example.com"})
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(self.state / "tls/relay.key")], check=True, capture_output=True)
            with self.assertRaises(installer.Invalid):
                installer.inspect(self.directory, self.settings)
        self.assertFalse(any("stop" in call for call in self.calls))

    def test_plan_only_checks_prerequisites(self):
        with patch.object(installer, "run", self.fake_run):
            installer.inspect(self.directory, self.settings)
        self.assertFalse((self.state / "relay-install").exists())
        self.assertFalse(any("stop" in call or "up" in call or "pubkey" in call for call in self.calls))


if __name__ == "__main__":
    unittest.main()
