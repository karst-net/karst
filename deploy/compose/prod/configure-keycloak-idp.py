#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Opt in an existing Karst management.json to Keycloak directory lookups.

No service restarts or Keycloak mutations are performed here.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import tempfile
from urllib.parse import urlparse


def endpoint(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Keycloak base URL must be an http(s) origin without userinfo, query or fragment")
    if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1", "::1", "keycloak"):
        raise ValueError("Use HTTPS for non-local Keycloak connections")
    return value.rstrip("/")


def configure(data: dict, base: str, realm: str, client_id: str, client_secret: str) -> dict:
    if not isinstance(data, dict):
        raise ValueError("management.json must contain a JSON object")
    if not realm or "/" in realm or "?" in realm or "#" in realm:
        raise ValueError("realm must be a single URL path segment")
    if not client_id or not client_secret:
        raise ValueError("client ID and secret must not be empty")
    current = data.get("IdpManagerConfig")
    if current is not None and current.get("ManagerType", "").lower() not in ("", "none", "keycloak"):
        raise ValueError("Existing non-Keycloak IdP configuration will not be replaced")
    config = dict(data)
    config["IdpManagerConfig"] = {
        "ManagerType": "keycloak",
        "KeycloakClientCredentials": {
            "ClientID": client_id,
            "ClientSecret": client_secret,
            "GrantType": "client_credentials",
            "TokenEndpoint": f"{base}/realms/{realm}/protocol/openid-connect/token",
            "AdminEndpoint": f"{base}/admin/realms/{realm}",
        },
    }
    return config


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--management", type=Path, default=Path("deploy/compose/state/management.json"))
    parser.add_argument("--keycloak-url", default="http://keycloak:8080/auth",
                        help="URL reachable by the control container, including /auth")
    parser.add_argument("--realm", default="karst")
    parser.add_argument("--client-id", default="karst-directory-sync")
    parser.add_argument("--secret-file", type=Path, required=True,
                        help="File containing the existing Keycloak confidential client's secret")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    base = endpoint(args.keycloak_url)
    src = args.management
    if not src.is_file() or src.is_symlink():
        parser.error("management configuration must be an existing regular file (not a symlink)")
    if not args.secret_file.is_file() or args.secret_file.is_symlink():
        parser.error("secret-file must be an existing regular file (not a symlink)")
    secret_mode = args.secret_file.stat().st_mode
    if secret_mode & (stat.S_IRWXG | stat.S_IRWXO):
        parser.error("secret-file is accessible to group/others; chmod 600 it first")
    secret = args.secret_file.read_text(encoding="utf-8").strip()
    original = src.read_text(encoding="utf-8")
    updated = configure(json.loads(original), base, args.realm, args.client_id, secret)
    if args.dry_run:
        print("Validated Keycloak directory configuration; no files changed.")
        return
    # Preserve the original in a root/user-only backup; refuse to clobber backups.
    backup = src.with_name(src.name + ".pre-idp-sync")
    if backup.exists():
        parser.error(f"backup already exists: {backup}; move it aside to reconfigure")
    original_mode = stat.S_IMODE(src.stat().st_mode)
    backup_fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(backup_fd, "w", encoding="utf-8") as out:
        out.write(original)
    fd, temp = tempfile.mkstemp(prefix=".management-idp-", dir=src.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(updated, out, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temp, original_mode & 0o600)
        os.replace(temp, src)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    print(f"Updated {src}. Private backup: {backup}")
    print("Restart the control service and validate /users; Keycloak groups are not synchronized by this adapter.")


if __name__ == "__main__":
    main()
