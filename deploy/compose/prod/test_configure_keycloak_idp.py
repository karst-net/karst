# SPDX-License-Identifier: MIT OR Apache-2.0
"""Unit tests for the opt-in deployment configuration helper."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).with_name("configure-keycloak-idp.py")
spec = importlib.util.spec_from_file_location("configure_keycloak_idp", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ConfigureKeycloakIdpTests(unittest.TestCase):
    def test_preserves_existing_management_fields(self):
        original = {"DataStoreEncryptionKey": "keep-this", "HttpConfig": {"Address": "127.0.0.1:33071"}}
        result = module.configure(original, "http://keycloak:8080/auth", "karst", "sync", "secret")
        self.assertEqual(result["DataStoreEncryptionKey"], "keep-this")
        self.assertEqual(result["HttpConfig"], original["HttpConfig"])
        self.assertNotIn("IdpManagerConfig", original)
        self.assertEqual(result["IdpManagerConfig"]["ManagerType"], "keycloak")
        self.assertEqual(
            result["IdpManagerConfig"]["KeycloakClientCredentials"]["AdminEndpoint"],
            "http://keycloak:8080/auth/admin/realms/karst",
        )

    def test_refuses_other_identity_provider(self):
        with self.assertRaises(ValueError):
            module.configure({"IdpManagerConfig": {"ManagerType": "auth0"}}, "http://keycloak:8080/auth", "karst", "sync", "secret")

    def test_validates_internal_and_external_urls(self):
        self.assertEqual(module.endpoint("http://keycloak:8080/auth/"), "http://keycloak:8080/auth")
        self.assertEqual(module.endpoint("https://idp.example.com/auth"), "https://idp.example.com/auth")
        for url in ("http://example.com/auth", "https://user:pass@example.com/auth", "file:///etc/passwd", "https://host/auth?token=foo"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                module.endpoint(url)

    def test_rejects_missing_client_secret_and_bad_realm(self):
        for realm in ("", "../master", "x?admin=true"):
            with self.subTest(realm=realm), self.assertRaises(ValueError):
                module.configure({}, "http://keycloak:8080/auth", realm, "sync", "secret")
        with self.assertRaises(ValueError):
            module.configure({}, "http://keycloak:8080/auth", "karst", "sync", "")


if __name__ == "__main__":
    unittest.main()
