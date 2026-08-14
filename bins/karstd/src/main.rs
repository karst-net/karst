// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! `karstd` — the Karst node agent.
//!
//! # Shutdown
//!
//! There is deliberately no signal handler. Installing one needs `unsafe`, and
//! ADR-0003 confines that to `karst-tun` and the GSO paths. It also buys
//! nothing here: the TUN interface is not persistent (no `TUNSETPERSIST`), so
//! the kernel removes it when the process's descriptor closes — which happens
//! on any exit, including `SIGKILL`. Default signal disposition already gives
//! the clean teardown a handler would be written to provide.
//!
//! [`Shutdown`] exists for tests and for the IPC-driven `karst down` that
//! arrives with the CLI.

use std::path::PathBuf;
use std::process::ExitCode;

use karst_crypto::kem::{Kem as _, MlKem768Backend as MlKem};
use karstd::config::{encode_hex, Config, PRIVATE_KEY_LEN};
use karstd::control::{Origin, Source};
use karstd::run::Shutdown;

const DEFAULT_CONFIG: &str = "/etc/karst/karstd.toml";

const USAGE: &str = "\
karstd — the Karst node agent

USAGE:
    karstd [--config PATH]         run the daemon
    karstd check [--config PATH]   validate the configuration and exit
    karstd genkey                  generate a private key on stdout
    karstd pubkey [--config PATH]  print this node's public keys

OPTIONS:
    -c, --config PATH   configuration file (default: /etc/karst/karstd.toml)
    -s, --socket PATH   control socket (default: /run/karst/karstd.sock)
    -h, --help          this text

Use `karst status` to inspect a running daemon.
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
        Some((&"genkey", _)) => command_genkey(),
        Some((&"check", rest)) => command_check(rest),
        Some((&"pubkey", rest)) => command_pubkey(rest),
        // Options with no subcommand means "run".
        Some((first, _)) if first.starts_with('-') => command_run(&refs),
        Some((other, _)) => {
            eprintln!("karstd: unknown command {other:?}\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

/// Extract `--config PATH`, rejecting anything unrecognised.
///
/// An unknown option is an error rather than something to skip: a mistyped flag
/// that is silently dropped leaves the daemon running with settings the
/// operator did not choose and believes they set.
fn config_path(args: &[&str]) -> Result<PathBuf, String> {
    Ok(parse_args(args)?.0)
}

/// Parse the option pair every subcommand accepts.
fn parse_args(args: &[&str]) -> Result<(PathBuf, PathBuf), String> {
    let mut config = PathBuf::from(DEFAULT_CONFIG);
    let mut socket = None;
    let mut it = args.iter().copied();
    while let Some(arg) = it.next() {
        match arg {
            "-c" | "--config" => {
                config = it
                    .next()
                    .ok_or_else(|| format!("{arg} needs a path"))?
                    .into();
            }
            "-s" | "--socket" => {
                socket = Some(it.next().ok_or_else(|| format!("{arg} needs a path"))?);
            }
            other => return Err(format!("unknown option {other:?}")),
        }
    }
    Ok((config, karstd::ipc::socket_path(socket)))
}

/// Load a configuration from whichever source the file names.
///
/// A roster loads from disk alone; a `[control]` configuration reaches the
/// coordination server (or its cache) first.
fn load(args: &[&str]) -> Result<(Config, Source), String> {
    let (config, source, _) =
        karstd::control::load_config(&config_path(args)?).map_err(|e| e.to_string())?;
    Ok((config, source))
}

fn command_run(args: &[&str]) -> ExitCode {
    let (config_path, socket) = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("karstd: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (config, source, client) = match karstd::control::load_config(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("karstd: {e}");
            return ExitCode::FAILURE;
        }
    };
    describe(&source);
    match karstd::run::run_with_control(
        &std::sync::Arc::new(config),
        &Shutdown::default(),
        &socket,
        client,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("karstd: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Say where the peer set came from.
///
/// Worth a line at startup: an operator looking at an unexpected roster needs
/// to know whether the daemon is reading a file or a server, and — if a server
/// — whether it actually reached one or fell back to what it last knew.
fn describe(source: &Source) {
    match source {
        Source::Roster => eprintln!("karstd: peers from the local roster"),
        Source::Server { origin, peers } => {
            let from = match origin {
                Origin::Server => "the coordination server",
                Origin::Cache => "the cached netmap (the server was unreachable)",
            };
            eprintln!("karstd: {peers} peer(s) from {from}");
        }
    }
}

fn command_check(args: &[&str]) -> ExitCode {
    match load(args) {
        Ok((config, source)) => {
            describe(&source);
            println!(
                "configuration is valid: interface {}, listening on {}, {} peer(s)",
                config.interface,
                config.listen,
                config.peers.len()
            );
            for peer in &config.peers {
                let ranges: Vec<String> =
                    peer.allowed_ips.iter().map(ToString::to_string).collect();
                println!(
                    "  {:<16} {:<21} {}{}",
                    peer.name,
                    peer.endpoint
                        .map_or_else(|| "(no endpoint)".to_owned(), |e| e.to_string()),
                    ranges.join(", "),
                    if peer.psk_is_fallback {
                        "  [no PSK — §7.3 fallback]"
                    } else {
                        ""
                    }
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("karstd: {e}");
            ExitCode::FAILURE
        }
    }
}

fn command_genkey() -> ExitCode {
    let mut seed = [0u8; PRIVATE_KEY_LEN];
    let mut filled = 0;
    while filled < PRIVATE_KEY_LEN {
        let chunk = karstd::random_seed();
        let end = (filled + chunk.len()).min(PRIVATE_KEY_LEN);
        match (seed.get_mut(filled..end), chunk.get(..end - filled)) {
            (Some(dst), Some(src)) => dst.copy_from_slice(src),
            _ => break,
        }
        filled = end;
    }
    println!("{}", encode_hex(&seed));
    // On stderr so it survives redirection of the key itself.
    eprintln!(
        "karstd: write this to a file with mode 600. It is the node's identity, \
         it is not recoverable, and if it reached a terminal scrollback or a \
         shell history it should be considered disclosed."
    );
    ExitCode::SUCCESS
}

/// Print this node's public keys, in a form that can be pasted into another
/// node's roster.
///
/// Reads only the private key, not the roster: a node that has just been
/// created has no peers, and its operator needs this output precisely in order
/// to register it somewhere else.
fn command_pubkey(args: &[&str]) -> ExitCode {
    let path = match config_path(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("karstd: {e}");
            return ExitCode::FAILURE;
        }
    };
    match karstd::config::load_keys(&path) {
        Ok(keys) => {
            println!(
                "kem_public_key = \"{}\"",
                encode_hex(&MlKem::public_key_bytes(&keys.kem_pk))
            );
            println!("dh_public_key = \"{}\"", encode_hex(keys.dh_pk.as_bytes()));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("karstd: {e}");
            ExitCode::FAILURE
        }
    }
}
