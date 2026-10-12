// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! `karst-relay` — the Ponor relay server.
//!
//! See `spec/ponor-v1.md`.

use std::path::PathBuf;
use std::process::ExitCode;

use base64ct::{Base64, Encoding as _};
use karst_relay::cloud_location;
use karst_relay::config::Config;
use karst_relay::roster::FileRoster;
use karst_relay::sign::Identity;

const DEFAULT_CONFIG: &str = "/etc/karst/relay.toml";

const USAGE: &str = "\
karst-relay — the Ponor relay server

USAGE:
    karst-relay [--config PATH]                  run the relay
    karst-relay check [--config PATH]             validate the configuration and exit
    karst-relay pubkey [--config PATH]            print this relay's registry entry
    karst-relay enroll [--config PATH] --bundle PATH
                                                   complete roster admission using a
                                                   relay-enroll token (ADR-0045 §7
                                                   Phase 2), then exit

OPTIONS:
    -c, --config PATH   configuration file (default: /etc/karst/relay.toml)
    --bundle PATH       enroll's own token/address bundle (see its own docs)
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
        Some((&"enroll", rest)) => command_enroll(rest),
        Some((first, _)) if first.starts_with('-') => command_run(&refs),
        Some((other, _)) => {
            eprintln!("karst-relay: unknown command {other:?}\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

/// Extract `--config PATH`, rejecting anything unrecognized.
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

/// What a scaled-up relay's `enroll --bundle` file carries — everything
/// `enroll` needs that is not already in its own `relay.toml` (`region`
/// is; see ADR-0045 §7 Phase 2 PR 4's own notes on why it is not
/// duplicated here). The scaler's own drivers (`karst-scaler-k8s`,
/// `karst-scaler-aws`) write this exact shape.
///
/// `address` is absent when the driver that wrote this bundle could not
/// know it in advance — `karst-scaler-aws`'s own crate doc explains why
/// an EC2 instance's address is one such case. `command_enroll` resolves
/// a missing `address` itself, via cloud instance metadata, rather than
/// treating an absent address as a configuration error.
#[derive(Debug, serde::Deserialize)]
struct EnrollBundle {
    control_api_base: String,
    token: String,
    address: Option<String>,
    tls_server_name: String,
}

/// The same registry-entry shape `pubkey` prints, but as the JSON
/// `relayreg.Entry` the control server's `POST /karst/v1/relays/enroll`
/// expects — see `server/management/internals/karst/relayreg/relayreg.go`.
#[derive(Debug, serde::Serialize)]
struct RegistryEntry<'a> {
    address: &'a str,
    tls_server_name: &'a str,
    identity_key: String,
    region: &'a str,
}

/// Extract `--config PATH` and `--bundle PATH` — `enroll`'s own two
/// options; unlike every other subcommand, `--bundle` is mandatory (there
/// is no reasonable default path for a one-off credential).
fn enroll_args(args: &[&str]) -> Result<(PathBuf, PathBuf), String> {
    let mut config = PathBuf::from(DEFAULT_CONFIG);
    let mut bundle = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match *arg {
            "-c" | "--config" => {
                let value = it
                    .next()
                    .ok_or_else(|| "--config needs a path".to_owned())?;
                config = PathBuf::from(value);
            }
            "--bundle" => {
                let value = it
                    .next()
                    .ok_or_else(|| "--bundle needs a path".to_owned())?;
                bundle = Some(PathBuf::from(value));
            }
            other => return Err(format!("unknown option {other:?}")),
        }
    }
    let bundle = bundle.ok_or_else(|| "enroll needs --bundle PATH".to_owned())?;
    Ok((config, bundle))
}

/// Resolves `address` (`host:port`, where `host` may already be a
/// literal IP or may be a DNS name) to one concrete `ip:port` --
/// `relayreg.go`'s own `compile()` requires a literal
/// `netip.ParseAddrPort`, matching `bins/karstd/src/netmap.rs::Relay::
/// from_wire`'s own `SocketAddr`-only parse. `karst-scaler-k8s`'s own
/// bundle writes a pod's stable DNS name here (chosen for its stability
/// across pod restarts, which a raw pod IP does not have); an address
/// that is already a literal socket address — including the one
/// `command_enroll` resolves itself via cloud instance metadata when a
/// bundle has none at all — resolves to itself. A blocking lookup, not
/// async: `command_enroll` is otherwise a synchronous, one-shot CLI path
/// (like its own `enroll()` below, which blocks on `ureq` the same way).
///
/// # Errors
/// If `address` cannot be parsed/resolved at all, or resolves to no
/// address.
fn resolve_address(address: &str) -> Result<String, String> {
    use std::net::ToSocketAddrs as _;
    address
        .to_socket_addrs()
        .map_err(|e| format!("resolving: {e}"))?
        .next()
        .map(|addr| addr.to_string())
        .ok_or_else(|| "resolved to no address".to_owned())
}

fn command_enroll(args: &[&str]) -> ExitCode {
    let (config_path_arg, bundle_path) = match enroll_args(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("karst-relay: {e}");
            return ExitCode::FAILURE;
        }
    };
    let cfg = match Config::load(&config_path_arg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("karst-relay: {e}");
            return ExitCode::FAILURE;
        }
    };
    let bundle_text = match std::fs::read_to_string(&bundle_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("karst-relay: reading {}: {e}", bundle_path.display());
            return ExitCode::FAILURE;
        }
    };
    let bundle: EnrollBundle = match toml::from_str(&bundle_text) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("karst-relay: parsing {}: {e}", bundle_path.display());
            return ExitCode::FAILURE;
        }
    };
    // Same identity every other subcommand uses -- created on first run if
    // this is a genuinely new instance, loaded unchanged if `enroll` is
    // ever re-run against the same `identity_key` path.
    let identity = match Identity::load_or_create(&cfg.identity_key) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("karst-relay: {e}");
            return ExitCode::FAILURE;
        }
    };
    // A bundle with no `address` is one `karst-scaler-aws` wrote (see its
    // own crate doc): an EC2 instance's address is unknowable to the
    // driver before `RunInstances` returns, so `enroll` resolves its own
    // via cloud instance metadata instead. The `Runtime` is built here,
    // not held across the whole command, since this is the one place
    // this otherwise-synchronous subcommand needs an async call at all.
    let address = if let Some(address) = bundle.address {
        address
    } else {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("karst-relay: building the async runtime: {e}");
                return ExitCode::FAILURE;
            }
        };
        if let Some(address) = rt.block_on(cloud_location::self_address()) {
            address
        } else {
            eprintln!(
                "karst-relay: {}: no address, and this instance's own cloud metadata did \
                 not yield one",
                bundle_path.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let address = match resolve_address(&address) {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "karst-relay: {}: address {address:?}: {e}",
                bundle_path.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let entry = RegistryEntry {
        address: &address,
        tls_server_name: &bundle.tls_server_name,
        identity_key: Base64::encode_string(identity.public_key()),
        region: &cfg.region,
    };
    match enroll(&bundle.control_api_base, &bundle.token, &entry) {
        Ok(()) => {
            println!("karst-relay: enrolled (identity_pk {})", entry.identity_key);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("karst-relay: enroll: {e}");
            ExitCode::FAILURE
        }
    }
}

/// POSTs `entry` to `control_api_base`'s relay-enroll endpoint, bearing
/// `token` — the one outbound HTTP call this crate makes; see
/// `Cargo.toml`'s own comment on the `ureq` dependency this needs.
fn enroll(control_api_base: &str, token: &str, entry: &RegistryEntry<'_>) -> Result<(), String> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let loaded = rustls_native_certs::load_native_certs();
    if loaded.certs.is_empty() {
        return Err("the host has no usable certificate authority roots".to_owned());
    }
    let roots: ureq::tls::RootCerts = loaded
        .certs
        .into_iter()
        .map(|der| ureq::tls::Certificate::from_der(der.as_ref()).to_owned())
        .collect::<Vec<_>>()
        .into();
    let tls_config = ureq::tls::TlsConfig::builder().root_certs(roots).build();
    let config = ureq::Agent::config_builder().tls_config(tls_config).build();
    let agent = ureq::Agent::new_with_config(config);

    let url = format!(
        "{}/karst/v1/relays/enroll",
        control_api_base.trim_end_matches('/')
    );
    agent
        .post(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .send_json(entry)
        .map_err(|e| format!("POST {url}: {e}"))?;
    Ok(())
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

    #[test]
    fn enroll_requires_a_bundle_path() {
        assert!(enroll_args(&[]).is_err());
        assert!(enroll_args(&["-c", "/tmp/a.toml"]).is_err());
    }

    #[test]
    fn enroll_accepts_config_and_bundle_together() {
        let (config, bundle) =
            enroll_args(&["--bundle", "/tmp/e.toml", "-c", "/tmp/a.toml"]).expect("ok");
        assert_eq!(config, PathBuf::from("/tmp/a.toml"));
        assert_eq!(bundle, PathBuf::from("/tmp/e.toml"));
    }

    #[test]
    fn enroll_defaults_the_config_path_when_only_bundle_is_given() {
        let (config, bundle) = enroll_args(&["--bundle", "/tmp/e.toml"]).expect("ok");
        assert_eq!(config, PathBuf::from(DEFAULT_CONFIG));
        assert_eq!(bundle, PathBuf::from("/tmp/e.toml"));
    }

    #[test]
    fn resolve_address_passes_a_literal_socket_address_through() {
        assert_eq!(
            resolve_address("203.0.113.5:443").expect("ok"),
            "203.0.113.5:443"
        );
    }

    #[test]
    fn resolve_address_resolves_a_dns_name_to_a_literal_address() {
        // `localhost` is resolved via /etc/hosts or the system resolver's
        // own built-in loopback entry, not a real network lookup -- this
        // is the same shape of fix `karst-scaler-k8s`'s own pod FQDN
        // needs, exercised without a real DNS server.
        let resolved = resolve_address("localhost:443").expect("ok");
        assert!(
            resolved == "127.0.0.1:443" || resolved == "[::1]:443",
            "resolved to {resolved}"
        );
    }

    #[test]
    fn resolve_address_rejects_a_name_with_no_port() {
        assert!(resolve_address("localhost").is_err());
    }
}
