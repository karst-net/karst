// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Privileged setup invoked by the desktop launcher. Credentials arrive only
//! through stdin; paths and service names are fixed by the installed package.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::io::{Read, Write as _};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CONFIG: &str = "/etc/karst/karstd.toml";
const STATE: &str = "/var/lib/karst";

fn read_invitation(reader: impl Read) -> Result<zeroize::Zeroizing<String>, String> {
    let mut invitation = zeroize::Zeroizing::new(String::new());
    reader
        .take(65537)
        .read_to_string(&mut invitation)
        .map_err(|_| "Could not read the invitation. Paste it again.".to_owned())?;
    if invitation.len() > 65536 {
        return Err(
            "The invitation is too large. Ask your administrator for a new invitation.".to_owned(),
        );
    }
    Ok(invitation)
}

/// Run first installation, or resume service startup after registration.
///
/// # Errors
/// Returns safe, actionable enrollment and service-start errors.
pub fn from_stdin(resume: bool) -> Result<String, String> {
    if resume {
        // Validate the saved configuration and keys before asking systemd to use
        // them. Never require another invitation merely to restart the service.
        crate::config::load_keys(Path::new(CONFIG)).map_err(|_| {
            "No usable saved device configuration. Enroll this device first.".to_owned()
        })?;
    } else {
        let invitation = read_invitation(std::io::stdin().lock())?;
        crate::enrollment::enroll_invitation(&invitation, Path::new(CONFIG), Path::new(STATE))?;
    }
    start_service()?;
    readiness(Path::new(CONFIG))
}

/// Enable and start the daemon, by whatever this platform's service manager
/// is. Both variants report the same two failure modes the caller already
/// knows how to word: "the manager could not run at all" versus "it ran and
/// said no" — the daemon logs (`journalctl`/`/var/log/karst/karstd.log`) are
/// where the real reason lives, and repeating it here would only go stale.
#[cfg(target_os = "linux")]
fn start_service() -> Result<(), String> {
    let status = Command::new("/usr/bin/systemctl")
        .args(["enable", "--now", "karstd.service"])
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .status().map_err(|_| "Device registered, but the service manager could not start. Choose Retry; no new invitation is needed.".to_owned())?;
    if !status.success() {
        return Err("Device registered, but service startup failed. Choose Retry; no new invitation is needed.".to_owned());
    }
    Ok(())
}

/// `launchctl bootstrap` is `systemctl enable --now`'s macOS counterpart —
/// it both loads the daemon into the system domain and starts it, and
/// `RunAtLoad` in the plist means a future boot needs no help from this at
/// all. The `load -w` fallback matches `packaging/macos/scripts/postinstall`
/// exactly, for the same reason it is there: `bootstrap` refuses a label
/// that is already loaded on some macOS versions, where `load -w` does not.
#[cfg(target_os = "macos")]
fn start_service() -> Result<(), String> {
    const PLIST: &str = "/Library/LaunchDaemons/dev.karst.karstd.plist";
    let bootstrap = Command::new("/bin/launchctl")
        .args(["bootstrap", "system", PLIST])
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .status().map_err(|_| "Device registered, but the service manager could not start. Choose Retry; no new invitation is needed.".to_owned())?;
    if bootstrap.success() {
        return Ok(());
    }
    let status = Command::new("/bin/launchctl")
        .args(["load", "-w", PLIST])
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .status().map_err(|_| "Device registered, but the service manager could not start. Choose Retry; no new invitation is needed.".to_owned())?;
    if !status.success() {
        return Err("Device registered, but service startup failed. Choose Retry; no new invitation is needed.".to_owned());
    }
    Ok(())
}

fn readiness(config: &Path) -> Result<String, String> {
    // Prefer the daemon's own authenticated session. A second connection with
    // the same identity can displace its live stream on the control server.
    let mut saw_daemon = false;
    for _ in 0..20 {
        if let Some((synchronized, peers)) = daemon_readiness() {
            saw_daemon = true;
            if synchronized {
                return Ok(connected_message(peers));
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if saw_daemon {
        return Err("The service is running but its control connection is not ready. Check your network connection and choose Retry.".to_owned());
    }
    // Startup can be refused before the daemon opens its socket, notably for
    // Bedrock approval. Only that no-daemon case needs a diagnostic connection.
    let raw = std::fs::read_to_string(config)
        .map_err(|_| "Cannot read the saved device configuration.")?;
    let file: crate::config::File =
        toml::from_str(&raw).map_err(|_| "The saved device configuration is invalid.")?;
    let section = file
        .control
        .ok_or("The saved configuration has no control server.")?;
    let keys =
        crate::config::load_keys(config).map_err(|_| "Cannot load the saved device identity.")?;
    let mut client = crate::control::Client::new(&section, Path::new("/etc/karst"), &keys)
        .map_err(|_| {
            "Cannot use the saved enrollment. Ask your administrator to check this device."
        })?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "Cannot start the connection check. Choose Retry.")?;
    let synchronized = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), client.sync()).await
            .map_err(|_| "The control server did not respond. Check your internet connection and choose Retry.")
    })?;
    match synchronized {
        Ok(_) => {},
        Err(crate::control::Error::Uncovered) => return Ok(approval_message()),
        Err(_) => return Err("The control server could not authorize this connection. Check your connection or ask your administrator to check this device, then choose Retry.".to_owned()),
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Correct this device's clock and choose Retry.")?
        .as_secs();
    if client.bedrock_mode() == crate::bedrock::Mode::Enforcing
        && !client.bedrock_covers_self(i64::try_from(now).map_err(|_| "Invalid device clock.")?)
    {
        return Ok(approval_message());
    }
    // An authenticated control response alone is not proof the daemon applied
    // its configuration. Wait for its protected local status socket as well.
    for _ in 0..20 {
        if let Some((true, peers)) = daemon_readiness() {
            return Ok(connected_message(peers));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("Device registered, but the network service is not ready. Choose Retry; no new invitation is needed.".to_owned())
}

fn connected_message(peers: usize) -> String {
    if peers == 0 {
        "Registered and connected to the control server. No peer access is assigned yet; ask your administrator to check access policy.".to_owned()
    } else {
        "Connected. The device service is running and the control server has supplied its network configuration.".to_owned()
    }
}

fn approval_message() -> String {
    "Waiting for administrator approval. This device is registered; ask your administrator to approve it in Bedrock, then choose Retry. No new invitation is needed.".to_owned()
}

fn daemon_readiness() -> Option<(bool, usize)> {
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(crate::ipc::DEFAULT_SOCKET) else {
        return None;
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .is_err()
        || stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .is_err()
        || stream.write_all(b"status\n").is_err()
        || stream.shutdown(std::net::Shutdown::Write).is_err()
    {
        return None;
    }
    let mut response = String::new();
    if stream
        .take(1_048_577)
        .read_to_string(&mut response)
        .is_err()
        || response.len() > 1_048_576
    {
        return None;
    }
    parse_daemon_readiness(&response)
}

fn parse_daemon_readiness(response: &str) -> Option<(bool, usize)> {
    if !status_has_interface(response) {
        return None;
    }
    let header: toml::Value = toml::from_str(response.split("\n[").next()?).ok()?;
    let synchronized = header
        .get("control_synchronized")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
    let peers = usize::try_from(
        header
            .get("control_peers")
            .and_then(toml::Value::as_integer)
            .unwrap_or(0),
    )
    .ok()?;
    Some((synchronized, peers))
}

fn status_has_interface(response: &str) -> bool {
    // The human-readable sections following the top-level interface fields
    // include Rust debug values (e.g. None), so the whole response is not a
    // TOML document. Parse only the bounded interface header we consume.
    let header = response.split("\n[").next().unwrap_or_default();
    let Ok(value) = toml::from_str::<toml::Value>(header) else {
        return false;
    };
    value
        .get("interface")
        .and_then(toml::Value::as_str)
        .is_some()
        && value
            .get("addresses")
            .and_then(toml::Value::as_array)
            .is_some_and(|addresses| !addresses.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_interface_alone_does_not_prove_a_live_control_connection() {
        let header = "interface = \"karst0\"\naddresses = [\"100.64.0.3/16\"]\n";
        assert_eq!(parse_daemon_readiness(header), Some((false, 0)));
        assert_eq!(
            parse_daemon_readiness(&format!(
                "control_synchronized = false\ncontrol_peers = 2\n{header}"
            )),
            Some((false, 2))
        );
        assert_eq!(
            parse_daemon_readiness(&format!(
                "control_synchronized = true\ncontrol_peers = 2\n{header}"
            )),
            Some((true, 2))
        );
    }

    #[test]
    fn readiness_accepts_live_interface_header_despite_human_readable_sections() {
        let live = "interface = \"karst0\"\naddresses = [\"100.64.0.3/16\"]\n\n[routing]\nselected_exit = None\n";
        assert!(status_has_interface(live));
        assert!(!status_has_interface(
            "interface = \"karst0\"\naddresses = []\n"
        ));
        assert!(!status_has_interface("error = \"not running\"\n"));
    }

    #[test]
    fn rejects_oversized_or_non_utf8_input_without_echoing_it() {
        assert!(read_invitation(&vec![b'x'; 65537][..]).is_err());
        let error = read_invitation(&b"SECRET\xff"[..])
            .err()
            .unwrap_or_default();
        assert!(!error.contains("SECRET"));
        assert!(!error.is_empty());
    }
}
