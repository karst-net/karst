#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.

import importlib.util
import json
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
