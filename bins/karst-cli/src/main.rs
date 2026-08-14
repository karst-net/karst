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
    karst bugreport  a support bundle, safe to attach to an issue
    karst down       ask the daemon to stop
    karst version    daemon version

OPTIONS:
    -s, --socket PATH   control socket (default: /run/karst/karstd.sock)
    -h, --help          this text

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

    let command = match *first {
        "-h" | "--help" => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        "status" => Command::Status,
        "bugreport" => Command::BugReport,
        "down" => Command::Down,
        "version" => Command::Version,
        other => {
            eprintln!("karst: unknown command {other:?}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    let socket = match socket_arg(rest) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("karst: {e}");
            return ExitCode::FAILURE;
        }
    };

    match ipc::request(&socket, command) {
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
