// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! `karst` — the command-line interface to a running `karstd`.
//!
//! Talks to the daemon's local control socket. It holds no keys, opens no
//! sockets on the network, and needs no privileges beyond reaching that socket
//! — which is itself the administrative boundary (see `karstd::ipc`).

use std::process::ExitCode;

use karstd::ipc::{self, Command};

const USAGE: &str = "\
karst — control a running karstd

USAGE:
    karst status     peers, session state, tunnel MTU
    karst dns status KarstDNS listener, host integration, and routes
    karst dns query NAME  explain the resolver path for NAME
    karst dns revert restore the host's DNS configuration and exit
    karst bugreport  a support bundle, safe to attach to an issue
    karst down       ask the daemon to stop
    karst version    daemon version

OPTIONS:
    -s, --socket PATH   control socket (default: /run/karst/karstd.sock)
    -c, --config PATH   configuration file, for `dns revert` only
                         (default: /etc/karst/karstd.toml)
    -h, --help          this text

`dns revert` does not talk to the daemon — it undoes whatever host DNS change
is on disk or on the bus directly, which is what makes it usable from
`ExecStopPost=` after the daemon that applied the change has already exited.

`bugreport` reports facts about the configuration, never the configuration
itself: no PSKs, no private keys, no setup key. Attaching the config file
instead would ship every per-pair PSK in it, and whoever pasted it would have
no way to know.

The daemon itself is started separately; `karst up` is deliberately absent
because bringing the tunnel up means running karstd with a configuration, which
is a service-manager job rather than a CLI one.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();

    let Some((first, rest)) = refs.split_first() else {
        print!("{USAGE}");
        return ExitCode::FAILURE;
    };

    // `dns revert` needs no running daemon — it is meant to work when there
    // is none — so it never enters the IPC path below.
    if let ("dns", ["revert", tail @ ..]) = (*first, rest) {
        return command_dns_revert(tail);
    }

    let command = match (*first, rest) {
        ("-h" | "--help", _) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        ("status", _) => Command::Status,
        ("dns", ["status", ..]) => Command::DnsStatus,
        ("dns", ["query", name, ..]) => Command::DnsQuery((*name).to_owned()),
        ("bugreport", _) => Command::BugReport,
        ("down", _) => Command::Down,
        ("version", _) => Command::Version,
        (other, _) => {
            eprintln!("karst: unknown command {other:?}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    let command_args = match (*first, rest) {
        ("dns", ["status", tail @ ..] | ["query", _, tail @ ..]) => tail,
        ("dns", []) => &[],
        _ => rest,
    };
    let socket = match socket_arg(command_args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("karst: {e}");
            return ExitCode::FAILURE;
        }
    };

    match ipc::request(&socket, &command) {
        Ok(reply) => {
            print!("{reply}");
            ExitCode::SUCCESS
        }
        // The overwhelmingly common failure is "the daemon is not running", and
        // a bare ENOENT on a socket path does not say that to most people.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            eprintln!(
                "karst: no daemon is listening on {} — is karstd running?",
                socket.display()
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("karst: {}: {e}", socket.display());
            ExitCode::FAILURE
        }
    }
}

/// Parse `--socket PATH`, rejecting anything else.
fn socket_arg(args: &[&str]) -> Result<std::path::PathBuf, String> {
    let mut path = None;
    let mut it = args.iter().copied();
    while let Some(arg) = it.next() {
        match arg {
            "-s" | "--socket" => {
                path = Some(it.next().ok_or_else(|| format!("{arg} needs a path"))?);
            }
            other => return Err(format!("unknown option {other:?}")),
        }
    }
    Ok(ipc::socket_path(path))
}

/// Parse `--config PATH`, rejecting anything else.
fn config_arg(args: &[&str]) -> Result<std::path::PathBuf, String> {
    let mut path = None;
    let mut it = args.iter().copied();
    while let Some(arg) = it.next() {
        match arg {
            "-c" | "--config" => {
                path = Some(it.next().ok_or_else(|| format!("{arg} needs a path"))?);
            }
            other => return Err(format!("unknown option {other:?}")),
        }
    }
    Ok(path.map_or_else(
        || std::path::PathBuf::from(karstd::config::DEFAULT_CONFIG_PATH),
        std::path::PathBuf::from,
    ))
}

/// Restore host DNS directly from the configuration file, with no daemon
/// involved — see the module doc and `USAGE`.
fn command_dns_revert(args: &[&str]) -> ExitCode {
    let path = match config_arg(args) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("karst: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (settings, interface) = match karstd::config::load_dns_settings(&path) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("karst: {e}");
            return ExitCode::FAILURE;
        }
    };
    match karstd::dns::revert_host(&settings, &interface) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("karst: dns revert: {e}");
            ExitCode::FAILURE
        }
    }
}
