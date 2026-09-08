// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![cfg(unix)]

//! First-run provisioning from a trusted enrollment bundle. Keys stay local;
//! the daemon configuration is published only after server authentication.

use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::Path;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::Deserialize;

use crate::config::{encode_hex, ControlSection, PRIVATE_KEY_LEN};
use crate::control::Client;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    server: String,
    server_kem_pin: String,
    server_verify_pin: String,
    setup_key: String,
    #[serde(default = "minimum_version")]
    control_minimum_version: u32,
}

/// Pasted invitations use a versioned, URL-safe envelope. The payload includes
/// the trust anchors; no unauthenticated discovery is needed before enrollment.
const INVITATION_PREFIX: &str = "karst-invite-v1:";
const MAX_INVITATION_BYTES: usize = 65536;

fn parse_invitation(invitation: &str) -> Result<Bundle, String> {
    let invitation = invitation.trim();
    if invitation.len() > MAX_INVITATION_BYTES {
        return Err("enrollment invitation is too large".to_owned());
    }
    let encoded = invitation.strip_prefix(INVITATION_PREFIX).ok_or(
        "unsupported enrollment invitation; request a new invitation from your administrator",
    )?;
    let decoded = zeroize::Zeroizing::new(
        Base64UrlUnpadded::decode_vec(encoded)
            .map_err(|_| "invalid enrollment invitation".to_owned())?,
    );
    // Never return JSON parser diagnostics: they may echo the credential.
    let bundle: Bundle =
        serde_json::from_slice(&decoded).map_err(|_| "invalid enrollment invitation".to_owned())?;
    validate_bundle(&bundle)?;
    Ok(bundle)
}

fn hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.is_ascii() || s.len() % 2 != 0 {
        return Err("invalid server pin".to_owned());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid server pin".to_owned()))
        .collect()
}

fn minimum_version() -> u32 {
    1
}

#[cfg(unix)]
fn load_bundle(bundle_path: &Path) -> Result<Bundle, String> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = fs::symlink_metadata(bundle_path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        return Err(
            "enrollment bundle must be a regular file with mode 600; run chmod 600 on it"
                .to_owned(),
        );
    }
    let mut raw = zeroize::Zeroizing::new(String::new());
    fs::File::open(bundle_path)
        .map_err(|e| e.to_string())?
        .take(65537)
        .read_to_string(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() > 65536 {
        return Err("enrollment bundle is too large".to_owned());
    }
    // Parser errors can contain source lines with the bearer credential.
    let bundle: Bundle =
        toml::from_str(&raw).map_err(|_| "invalid enrollment bundle".to_owned())?;
    validate_bundle(&bundle)?;
    Ok(bundle)
}

fn validate_bundle(bundle: &Bundle) -> Result<(), String> {
    if !(bundle.server.starts_with("https://") || bundle.server.starts_with("http://"))
        || bundle.setup_key.is_empty()
    {
        return Err("bundle needs a control URL and an enrollment key".to_owned());
    }
    let suite = karst_control_client::suite::suite_for(bundle.control_minimum_version)
        .map_err(|e| e.to_string())?;
    suite
        .check_pins(
            &hex(&bundle.server_kem_pin)?,
            &hex(&bundle.server_verify_pin)?,
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(unix)]
fn create_data_key(key_path: &Path) -> Result<(), String> {
    if fs::symlink_metadata(key_path).is_ok() {
        return Ok(());
    }
    let mut seed = zeroize::Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
    getrandom::fill(seed.as_mut()).map_err(|_| "OS randomness unavailable")?;
    let encoded = zeroize::Zeroizing::new(encode_hex(seed.as_ref()));
    publish_config(key_path, &encoded)
}

#[cfg(unix)]
fn publish_config(config_path: &Path, text: &str) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    // hard_link publishes the complete file atomically and refuses an existing
    // destination, including a symlink created while enrollment was in flight.
    let sibling = config_path.with_file_name(format!(
        ".karst-enrollment-{}.tmp",
        encode_hex(&crate::random_seed())
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&sibling)
        .map_err(|e| e.to_string())?;
    let result = file
        .write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::hard_link(&sibling, config_path))
        .map_err(|e| e.to_string());
    let _ = fs::remove_file(&sibling);
    result?;
    fs::File::open(config_path.parent().ok_or("configuration parent missing")?)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(unix)]
fn lock_state(state_dir: &Path) -> Result<fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(
            i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
                .map_err(|_| "invalid no-follow flag")?,
        )
        .open(state_dir.join("enrollment.lock"))
        .map_err(|e| e.to_string())?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| "another enrollment is running for this state directory".to_owned())?;
    Ok(lock)
}

/// Enroll from a bundle obtained through the authenticated HTTPS portal or
/// delivered by the deployment administrator. Never overwrites a configured node.
///
/// # Errors
/// Returns invalid bundle, filesystem, credential and server-authentication errors.
#[cfg(unix)]
pub fn enroll(bundle_path: &Path, config_path: &Path, state_dir: &Path) -> Result<(), String> {
    enroll_bundle(load_bundle(bundle_path)?, config_path, state_dir)
}

/// Provision directly from a pasted administrator invitation without writing
/// its credential to a bundle file. Service startup is handled by setup.
///
/// # Errors
/// Returns invitation, filesystem, credential and server-authentication errors.
pub fn enroll_invitation(
    invitation: &str,
    config_path: &Path,
    state_dir: &Path,
) -> Result<(), String> {
    enroll_bundle(parse_invitation(invitation)?, config_path, state_dir)
}

fn enroll_bundle(bundle: Bundle, config_path: &Path, state_dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    if !config_path.is_absolute() || !state_dir.is_absolute() {
        return Err("configuration and state paths must be absolute".to_owned());
    }
    if config_path.symlink_metadata().is_ok() {
        return Err("configuration already exists; use the existing daemon or explicitly remove it before re-enrollment".to_owned());
    }
    for dir in [
        state_dir,
        config_path
            .parent()
            .ok_or("configuration needs a parent directory")?,
    ] {
        match fs::symlink_metadata(dir) {
            Ok(meta) if meta.is_dir() && meta.permissions().mode() & 0o022 == 0 => {},
            Ok(_) => return Err("configuration and state directories must be real directories, writable only by their owner".to_owned()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(0o700).create(dir).map_err(|e| e.to_string())?;
            },
            Err(e) => return Err(e.to_string()),
        }
    }
    // An OS lock survives neither a crash nor process exit. Keep its inode:
    // unlinking the lock file would let a concurrent process lock a new inode.
    let _lock = lock_state(state_dir)?;
    let key_path = state_dir.join("node.key");
    create_data_key(&key_path)?;
    let mut node = toml::Table::new();
    node.insert("listen".into(), "0.0.0.0:51820".into());
    node.insert(
        "interface".into(),
        if cfg!(target_os = "macos") {
            "utun"
        } else {
            "karst0"
        }
        .into(),
    );
    node.insert(
        "private_key_file".into(),
        key_path.to_string_lossy().as_ref().into(),
    );
    let mut control = toml::Table::new();
    control.insert("server".into(), bundle.server.into());
    control.insert("server_kem_pin".into(), bundle.server_kem_pin.into());
    control.insert("server_verify_pin".into(), bundle.server_verify_pin.into());
    control.insert(
        "control_minimum_version".into(),
        i64::from(bundle.control_minimum_version).into(),
    );
    control.insert(
        "identity_key_file".into(),
        state_dir
            .join("identity.key")
            .to_string_lossy()
            .as_ref()
            .into(),
    );
    control.insert(
        "cache_file".into(),
        state_dir
            .join("netmap.cache")
            .to_string_lossy()
            .as_ref()
            .into(),
    );
    let mut config = toml::Table::new();
    config.insert("node".into(), node.into());
    config.insert("control".into(), control.clone().into());
    let text = toml::to_string(&config).map_err(|_| "cannot serialize configuration")?;
    // A non-secret staging file allows use of the normal key/config validator.
    // It is never the service's config, so a failed attempt cannot start a tunnel.
    let staged = state_dir.join("enrollment.toml");
    crate::control::write_secret_bytes(&staged, text.as_bytes()).map_err(|e| e.to_string())?;
    let keys = crate::config::load_keys(&staged).map_err(|e| e.to_string())?;
    control.insert("setup_key".into(), bundle.setup_key.into());
    let section: ControlSection = toml::Value::Table(control)
        .try_into()
        .map_err(|_| "invalid control configuration")?;
    let mut client = Client::new(&section, state_dir, &keys).map_err(|e| e.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(30), client.enroll())
            .await
            .map_err(|_| "enrollment timed out; retry with the same state directory".to_owned())?
            .map_err(|e| e.to_string())
    })?;
    publish_config(config_path, &text)?;
    let _ = fs::remove_file(staged);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::scratch::Scratch;
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    #[test]
    fn invitation_validation_never_echoes_credentials() {
        let secret = "SECRET-DO-NOT-ECHO";
        for raw in [
            format!("{{\"setup_key\":\"{secret}\" broken"),
            format!("{{\"setup_key\":\"{secret}\",\"server\":\"http://localhost\"}}"),
        ] {
            let invitation = format!(
                "{INVITATION_PREFIX}{}",
                Base64UrlUnpadded::encode_string(raw.as_bytes())
            );
            let error = parse_invitation(&invitation).err().unwrap();
            assert!(!error.contains(secret));
        }
        assert!(parse_invitation("karst-invite-v2:e30").is_err());
        assert!(parse_invitation(&"x".repeat(MAX_INVITATION_BYTES + 1)).is_err());
    }

    #[test]
    fn invitation_preserves_trust_and_requires_valid_pins() {
        let mut payload = serde_json::json!({
            "server": "https://control.example.test",
            "server_kem_pin": "01".repeat(1184),
            "server_verify_pin": "02".repeat(2592),
            "setup_key": "fixture",
            "control_minimum_version": 1
        });
        let encode = |value: &serde_json::Value| {
            format!(
                "{INVITATION_PREFIX}{}",
                Base64UrlUnpadded::encode_string(value.to_string().as_bytes())
            )
        };
        let parsed = parse_invitation(&format!("  {}\n", encode(&payload))).unwrap();
        assert_eq!(parsed.server, "https://control.example.test");
        assert_eq!(parsed.setup_key, "fixture");
        *payload.get_mut("server_kem_pin").unwrap() = "01".into();
        assert!(parse_invitation(&encode(&payload)).is_err());
    }

    #[test]
    fn lock_excludes_concurrent_enrollment_and_is_released_on_exit() {
        let dir = Scratch::new("enrollment-lock");
        let first = lock_state(dir.path()).unwrap();
        assert!(lock_state(dir.path()).is_err());
        drop(first);
        assert!(lock_state(dir.path()).is_ok());
    }

    #[test]
    fn publishing_never_overwrites_a_file_or_follows_a_symlink() {
        let dir = Scratch::new("enrollment-publish");
        let path = dir.join("config");
        publish_config(&path, "original").unwrap();
        assert!(publish_config(&path, "replacement").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "original");
        let link = dir.join("link");
        symlink(&path, &link).unwrap();
        assert!(publish_config(&link, "replacement").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "original");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn malformed_bundle_errors_do_not_disclose_credentials() {
        let dir = Scratch::new("enrollment-parser");
        let path = dir.join("bundle");
        publish_config(&path, "setup_key = \"SECRET\" broken").unwrap();
        let error = load_bundle(&path).err().unwrap();
        assert!(!error.contains("SECRET"));
    }
}
