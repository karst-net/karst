#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.

import importlib.util
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("compose_versions", Path(__file__).with_name("compose-versions.py"))
versions = importlib.util.module_from_spec(spec)
spec.loader.exec_module(versions)


class ObservedImageIdentityTests(unittest.TestCase):
    def container(self):
        return {"Name": "/relay", "Image": "sha256:running", "Config": {"Image": "relay:latest"}, "State": {"Status": "running"}}

    def test_reads_labels_from_observed_image_id_and_filters_secrets(self):
        image = {"RepoTags": ["relay:latest"], "Config": {"Labels": {
            "org.opencontainers.image.version": "v0.1.0-rc.31",
            "org.opencontainers.image.revision": "running-commit",
            "private.secret": "never-expose",
        }, "Env": ["TOKEN=never-expose"]}}
        with patch.object(versions, "docker", return_value=json.dumps([image])) as docker:
            observed = versions.observe_component(self.container())
        docker.assert_called_once_with("image", "inspect", "sha256:running")
        self.assertEqual(observed["version"], "v0.1.0-rc.31")
        self.assertEqual(observed["revision"], "running-commit")
        self.assertEqual(observed["image_id"], "sha256:running")
        self.assertNotIn("never-expose", json.dumps(observed))

    def test_does_not_infer_identity_from_tags_without_labels(self):
        for config in ({}, {"Labels": None}, {"Labels": {}}):
            with self.subTest(config=config):
                image = {"RepoTags": ["relay:v99"], "Config": config}
                with patch.object(versions, "docker", return_value=json.dumps([image])):
                    observed = versions.observe_component(self.container())
                self.assertIsNone(observed["version"])
                self.assertIsNone(observed["revision"])


class NomadContainerSelectionTests(unittest.TestCase):
    def test_uses_exact_job_namespace_and_mandatory_allocation_label(self):
        allocations = [
            {"ID": "active", "JobID": "karst", "Namespace": "prod", "ClientStatus": "running"},
            {"ID": "starting", "JobID": "karst", "Namespace": "prod", "ClientStatus": "pending"},
            {"ID": "old", "JobID": "karst", "Namespace": "prod", "ClientStatus": "complete"},
            {"ID": "other-job", "JobID": "karst-other", "Namespace": "prod", "ClientStatus": "running"},
            {"ID": "other-namespace", "JobID": "karst", "Namespace": "staging", "ClientStatus": "running"},
        ]
        with patch.object(versions.subprocess, "check_output", return_value=json.dumps(allocations)) as nomad:
            with patch.object(versions, "docker", side_effect=["container-b\ncontainer-a\n", "container-b\n"]) as docker:
                ids = versions.container_ids("karst", "prod")
        nomad.assert_called_once_with(["nomad", "job", "allocs", "-all", "-json", "-namespace=prod", "karst"], text=True)
        self.assertEqual(ids, ["container-a", "container-b"])
        self.assertEqual(docker.call_args_list, [
            unittest.mock.call("ps", "--all", "--quiet", "--filter", "label=com.hashicorp.nomad.alloc_id=active"),
            unittest.mock.call("ps", "--all", "--quiet", "--filter", "label=com.hashicorp.nomad.alloc_id=starting"),
        ])

    def test_does_not_fall_back_to_other_containers_for_an_empty_job(self):
        with patch.object(versions.subprocess, "check_output", return_value="[]"):
            with patch.object(versions, "docker") as docker:
                self.assertEqual(versions.container_ids("empty", "prod"), [])
                docker.assert_not_called()

    def test_preserves_compose_project_selection_by_default(self):
        with patch.object(versions, "docker", return_value="project-container\n") as docker:
            self.assertEqual(versions.container_ids(), ["project-container"])
        docker.assert_called_once_with("compose", "ps", "--all", "--quiet")

    def test_empty_nomad_selection_preserves_previous_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "components.json"
            output.write_text("previous observation")
            arguments = ["compose-versions.py", "--output", str(output), "--nomad-job", "empty"]
            with patch("sys.argv", arguments), patch.object(versions, "container_ids", return_value=[]):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                    versions.main()
            self.assertEqual(result.exception.code, 2)
            self.assertEqual(output.read_text(), "previous observation")


if __name__ == "__main__":
    unittest.main()
