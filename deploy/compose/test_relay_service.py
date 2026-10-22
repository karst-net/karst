# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.

import importlib.util
import json
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
        self.state = self.directory / "state"
        self.state.mkdir()
        self.secret = "test-secret-do-not-print"
        for name, contents in {"relay.toml": "config", "relay.key": "private", "relays.json": "{}", "roster.toml": "# empty", "tls/relay.crt": "cert", "tls/relay.key": "private", "turn-secret": self.secret, "turns.json": '{"turn":[{"uri":"turn:127.0.0.1:3478"}]}', "turnserver.conf": f"use-auth-secret\nstatic-auth-secret={self.secret}\nrealm=karst\n"}.items():
            path = self.state / name
            path.parent.mkdir(exist_ok=True)
            path.write_text(contents)
        (self.state / "turn-secret").chmod(0o600)
        (self.directory / ".env").write_text("KARST_TURN_REGISTRY_FILE=/var/lib/karst/turns.json\nKARST_TURN_SHARED_SECRET_FILE=/var/lib/karst/turn-secret\n")
        self.desired = {"schema_version": 1, "ponor": {"enabled": True}, "turn": {"enabled": True, "backend": "coturn-companion"}}

    def write_manifest(self, ponor="true", enabled="true", backend="coturn-companion"):
        path = self.directory / "relay-service.toml"
        path.write_text(f'schema_version=1\n[ponor]\nenabled={ponor}\n[turn]\nenabled={enabled}\nbackend="{backend}"\n')
        return path

    def test_manifest_strict_and_explicit(self):
        self.assertEqual(relay.manifest(self.write_manifest()), self.desired)
        for values in [("1", "true", "coturn-companion"), ("true", "true", "none"), ("true", "false", "typo")]:
            with self.subTest(values=values), self.assertRaises(relay.Invalid):
                relay.manifest(self.write_manifest(*values))
        path = self.write_manifest()
        path.write_text(path.read_text()+"typo=true\n")
        with self.assertRaises(relay.Invalid):
            relay.manifest(path)

    def test_modes_reconcile_independently_and_external_never_starts_coturn(self):
        self.assertEqual(relay.operations(self.desired), [["up", "-d", "--no-deps", "relay", "coturn"]])
        self.desired["turn"]["enabled"] = False
        self.assertEqual(relay.operations(self.desired), [["up", "-d", "--no-deps", "relay"], ["stop", "coturn"]])
        self.desired["turn"].update(enabled=True, backend="external")
        self.assertEqual(relay.operations(self.desired)[-1], ["stop", "coturn"])
        self.desired["ponor"]["enabled"] = False
        self.assertEqual(relay.operations(self.desired), [["stop", "relay", "coturn"]])

    def test_bootstrap_credentials_are_validated_without_rewriting_material(self):
        before = {str(path): path.read_bytes() for path in self.state.rglob("*") if path.is_file()}
        relay.validate_material(self.directory, self.desired)
        self.assertEqual(before, {str(path): path.read_bytes() for path in self.state.rglob("*") if path.is_file()})
        (self.state / "turn-secret").chmod(0o644)
        with self.assertRaisesRegex(relay.Invalid, "group or others"):
            relay.validate_material(self.directory, self.desired)

    def test_managed_auth_mismatch_and_conflicts_fail(self):
        for config in ["use-auth-secret\nstatic-auth-secret=wrong", f"use-auth-secret\nstatic-auth-secret={self.secret}\nno-auth", f"use-auth-secret\nstatic-auth-secret={self.secret}\ninclude=other.conf"]:
            with self.subTest(config=config):
                (self.state / "turnserver.conf").write_text(config)
                with self.assertRaises(relay.Invalid) as error:
                    relay.validate_material(self.directory, self.desired)
                self.assertNotIn(self.secret, str(error.exception))

    def test_external_provider_has_no_companion_config_requirement(self):
        self.desired["turn"]["backend"] = "external"
        (self.state / "turnserver.conf").unlink()
        relay.validate_material(self.directory, self.desired)
        (self.directory / ".env").unlink()
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(relay.Invalid, "KARST_TURN_REGISTRY_FILE"):
            relay.validate_material(self.directory, self.desired)

    def test_snapshot_preserves_previous_success_and_private_permissions(self):
        relay.save_applied(self.directory, b"old manifest")
        relay.save_applied(self.directory, b"new manifest")
        target = self.state / "relay-service.applied.toml"
        self.assertEqual(target.read_bytes(), b"new manifest")
        self.assertEqual(target.with_suffix(".toml.previous").read_bytes(), b"old manifest")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_status_keeps_health_independent_and_unprobed(self):
        rows = [{"Service": "relay", "State": "running"}, {"Service": "coturn", "State": "exited", "Health": "unhealthy"}]
        for output in [json.dumps(rows), "\n".join(json.dumps(row) for row in rows)]:
            with patch.object(relay, "compose", return_value=subprocess.CompletedProcess([], 0, stdout=output)):
                status = relay.status(self.directory, self.desired)
            self.assertEqual(status["ponor"]["health"], "unprobed")
            self.assertEqual(status["turn"]["state"], "exited")
            self.assertEqual(status["turn"]["health"], "unhealthy")

    def test_cli_plan_is_read_only_and_does_not_disclose_secrets(self):
        path = self.write_manifest()
        result = subprocess.run(["python3", str(Path(relay.__file__)), "plan", "--directory", str(self.directory)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(self.secret, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["desired"], relay.manifest(path))
        self.assertIn(str(self.directory / "docker-compose.yml"), json.loads(result.stdout)["commands"][0])
        self.assertFalse((self.state / "relay-service.applied.toml").exists())

    @unittest.skipUnless(os.environ.get("KARST_COMPOSE_LIFECYCLE_TEST") == "1", "requires Docker and local alpine:latest image")
    def test_real_compose_lifecycle_keeps_control_and_other_mode_running(self):
        # Real Compose process orchestration with harmless stand-ins: protocol
        # allocation/admission readiness belongs to the separate coturn suites.
        import uuid
        project = "karst-relay-test-" + uuid.uuid4().hex[:12]
        (self.directory / "docker-compose.yml").write_text(
            "name: " + project + "\nservices:\n" + "".join(
                f"  {name}:\n    image: alpine:latest\n    command: [sleep, '600']\n" + ("    profiles: [turn]\n" if name == "coturn" else "")
                for name in ("control", "relay", "coturn")))
        self.addCleanup(lambda: relay.compose(self.directory, ["down", "--remove-orphans"]))
        relay.compose(self.directory, ["up", "-d", "control"])
        self.write_manifest()
        argv = ["python3", str(Path(relay.__file__)), "apply", "--directory", str(self.directory), "--acknowledge-process-change"]
        subprocess.run(argv, check=True, capture_output=True, text=True)
        self.assertEqual(relay.status(self.directory, self.desired)["turn"]["state"], "running")
        self.write_manifest(enabled="false")
        subprocess.run(argv, check=True, capture_output=True, text=True)
        self.desired["turn"]["enabled"] = False
        status = relay.status(self.directory, self.desired)
        self.assertEqual(status["ponor"]["state"], "running")
        self.assertEqual(status["turn"]["state"], "exited")
        self.write_manifest()
        subprocess.run(argv, check=True, capture_output=True, text=True)
        self.desired["turn"]["enabled"] = True
        self.assertEqual(relay.status(self.directory, self.desired)["turn"]["state"], "running")
        self.write_manifest(backend="external")
        subprocess.run(argv, check=True, capture_output=True, text=True)
        self.desired["turn"]["backend"] = "external"
        status = relay.status(self.directory, self.desired)
        self.assertEqual(status["turn"]["state"], "external")
        self.assertEqual(status["turn"]["companion"]["state"], "exited")
        rows = relay.compose(self.directory, ["ps", "--format", "json", "control"], capture=True).stdout
        self.assertIn('"State":"running"', rows.replace(" ", ""))

    def test_partial_apply_does_not_replace_last_successful_manifest(self):
        self.write_manifest(enabled="false")
        relay.save_applied(self.directory, b"previous success")
        binary = self.directory / "docker"
        log = self.directory / "commands.log"
        binary.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(log) + '"\ncase "$*" in *" stop "*) exit 7;; esac\n')
        binary.chmod(0o755)
        argv = ["python3", str(Path(relay.__file__)), "apply", "--directory", str(self.directory)]
        env = {**os.environ, "PATH": str(self.directory)+os.pathsep+os.environ["PATH"]}
        denied = subprocess.run(argv, env=env, capture_output=True, text=True)
        self.assertNotEqual(denied.returncode, 0)
        self.assertFalse(log.exists(), "missing acknowledgment must perform no Docker operations")
        failed = subprocess.run([*argv, "--acknowledge-process-change"], env=env, capture_output=True, text=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("earlier actions may have completed", failed.stderr)
        self.assertIn("up -d --no-deps relay", log.read_text())
        self.assertIn("stop coturn", log.read_text())
        self.assertEqual((self.state / "relay-service.applied.toml").read_bytes(), b"previous success")

    def test_cli_failure_never_records_success_or_leaks_docker_diagnostics(self):
        self.write_manifest()
        binary = self.directory / "docker"
        binary.write_text(f'#!/bin/sh\necho "{self.secret}" >&2\nexit 7\n')
        binary.chmod(0o755)
        result = subprocess.run(["python3", str(Path(relay.__file__)), "apply", "--directory", str(self.directory), "--acknowledge-process-change"], env={**os.environ, "PATH": str(self.directory)+os.pathsep+os.environ["PATH"]}, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(self.secret, result.stdout + result.stderr)
        self.assertFalse((self.state / "relay-service.applied.toml").exists())


if __name__ == "__main__":
    unittest.main()
