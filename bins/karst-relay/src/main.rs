// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! `karst-relay` — the Ponor relay server.
//!
//! See `spec/ponor-v1.md`.

use std::path::PathBuf;
use std::process::ExitCode;

use base64ct::{Base64, Encoding as _};
use karst_relay::config::Config;
use karst_relay::roster::FileRoster;
use karst_relay::sign::Identity;

const DEFAULT_CONFIG: &str = "/etc/karst/relay.toml";

const USAGE: &str = "\
karst-relay — the Ponor relay server

USAGE:
    karst-relay [--config PATH]         run the relay
    karst-relay check [--config PATH]   validate the configuration and exit
    karst-relay pubkey [--config PATH]  print this relay's registry entry

OPTIONS:
    -c, --config PATH   configuration file (default: /etc/karst/relay.toml)
    -h, --help          this text

A relay admits only nodes present in its roster (spec/ponor-v1.md §5.3); it
cannot verify a node it has not been told about. Use `check` after every roster
change.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();

    match refs.split_first() {
        None => command_run(&[]),
        Some((&"-h" | &"--help", _)) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some((&"check", rest)) => command_check(rest),
        Some((&"pubkey", rest)) => command_pubkey(rest),
        Some((first, _)) if first.starts_with('-') => command_run(&refs),
        Some((other, _)) => {
            eprintln!("karst-relay: unknown command {other:?}\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

/// Extract `--config PATH`, rejecting anything unrecognised.
///
/// An unknown option is an error rather than something to skip: a mistyped
/// flag that is silently ignored is a relay running with settings its operator
/// believes it is not running with.
fn config_path(args: &[&str]) -> Result<PathBuf, String> {
    let mut path = PathBuf::from(DEFAULT_CONFIG);
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match *arg {
            "-c" | "--config" => {
                let value = it
                    .next()
                    .ok_or_else(|| "--config needs a path".to_owned())?;
                path = PathBuf::from(value);
            }
            other => return Err(format!("unknown option {other:?}")),
        }
    }
    Ok(path)
}

fn load(args: &[&str]) -> Result<(PathBuf, Config), String> {
    let path = config_path(args)?;
    let cfg = Config::load(&path).map_err(|e| e.to_string())?;
    Ok((path, cfg))
}

fn command_check(args: &[&str]) -> ExitCode {
    let (path, cfg) = match load(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("karst-relay: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = cfg.validate() {
        eprintln!("karst-relay: {e}");
        return ExitCode::FAILURE;
    }

    // The roster is parsed, not merely stat-ed. It is the whole of admission
    // control, and a syntax error in it is the difference between a relay that
    // works and one that admits nobody — which is exactly the failure an
    // operator wants to hear about now rather than at 3am.
    let roster = match FileRoster::load(&cfg.roster) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("karst-relay: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("{}: ok", path.display());
    println!("  listen        {}", cfg.listen);
    println!(
        "  roster        {} nodes, {} mesh peers",
        roster.client_count(),
        roster.mesh_count()
    );
    if roster.client_count() == 0 {
        // Not an error — an empty roster is a legitimate starting state — but
        // it means nobody can connect, and saying so beats an operator
        // debugging TLS for an hour.
        println!("                (no nodes admitted; every connection will be rejected)");
    }
    println!("  queue depth   {}", cfg.limits.queue_depth);
    ExitCode::SUCCESS
}

fn command_pubkey(args: &[&str]) -> ExitCode {
    let (_, cfg) = match load(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("karst-relay: {e}");
            return ExitCode::FAILURE;
        }
    };
    match Identity::load_or_create(&cfg.identity_key) {
        Ok(identity) => {
            // What the coordination server needs to publish in the relay
            // registry. Clients pin the key from there, never from the
            // connection — §4.2.
            println!("relay_id     {}", hex(&identity.relay_id()));
            println!(
                "identity_pk  {}",
                Base64::encode_string(identity.public_key())
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("karst-relay: {e}");
            ExitCode::FAILURE
        }
    }
}

fn command_run(args: &[&str]) -> ExitCode {
    let (_, cfg) = match load(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("karst-relay: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = cfg.validate() {
        eprintln!("karst-relay: {e}");
        return ExitCode::FAILURE;
    }

    // A multi-threaded runtime: connections are independent and a relay's
    // whole job is to carry many of them. The datapath in `karstd` is
    // deliberately synchronous; this is not that.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("karst-relay: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(karst_relay::server::run(&cfg)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("karst-relay: {e}");
            ExitCode::FAILURE
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_default_config_path_is_used_when_none_is_given() {
        assert_eq!(config_path(&[]).expect("ok"), PathBuf::from(DEFAULT_CONFIG));
    }

    #[test]
    fn a_config_path_can_be_given_either_way() {
        assert_eq!(
            config_path(&["-c", "/tmp/a.toml"]).expect("ok"),
            PathBuf::from("/tmp/a.toml")
        );
        assert_eq!(
            config_path(&["--config", "/tmp/b.toml"]).expect("ok"),
            PathBuf::from("/tmp/b.toml")
        );
    }

    #[test]
    fn an_unknown_option_is_refused() {
        // Silently ignoring it means a relay running with settings its
        // operator believes it is not running with.
        assert!(config_path(&["--verbose"]).is_err());
        assert!(config_path(&["-c"]).is_err());
    }
}
