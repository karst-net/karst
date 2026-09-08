// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! `karst` — first-run enrollment and control of a running `karstd`.
//!
//! Status and administration use the protected local control socket. The
//! explicit `enroll` command provisions local keys and authenticates the pinned
//! server before a daemon exists; it needs permission to write the service's
//! configuration and state directories.

use std::process::ExitCode;

use karstd::ipc::{self, Command};

const USAGE: &str = "\
karst — enroll a device and control karstd

USAGE:
    karst setup --stdin        desktop setup helper (Linux, macOS; invitation on stdin)
    karst setup --resume       retry startup using the saved device identity
    karst enroll --bundle FILE  enroll using a trusted bundle (run with sudo)
      [--config PATH] [--state-dir PATH]  absolute paths for custom installations
    karst status     peers, session state, tunnel MTU
    karst dns status KarstDNS listener, host integration, and routes
    karst dns query NAME  explain the resolver path for NAME
    karst dns revert restore the host's DNS configuration and exit
    karst exit-node list          list exit routes and local selection
    karst exit-node use ROUTE_ID  persistently select an exit route
    karst exit-node disable       withdraw and forget exit consent
    karst bugreport  a support bundle, safe to attach to an issue
    karst metrics    Engine::Stats and route/gateway state as Prometheus text
    karst down       ask the daemon to stop
    karst version    the running daemon's version (needs the daemon up)

OPTIONS:
    -s, --socket PATH   control socket (default: /run/karst/karstd.sock on
                         Linux, /var/run/karst/karstd.sock on macOS)
    -c, --config PATH   configuration file, for `dns revert` only
                         (default: /etc/karst/karstd.toml)
    -V, --version       this CLI's own version, no daemon needed — for the
                         daemon's, use `karst version`
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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if *first == "setup" {
        let resume = match rest {
            ["--stdin"] => false,
            ["--resume"] => true,
            _ => {
                #[cfg(target_os = "linux")]
                eprintln!("Use Karst Setup from the applications menu.");
                #[cfg(target_os = "macos")]
                eprintln!("Use Setup… from Karst's menu bar item.");
                return ExitCode::FAILURE;
            }
        };
        return match karstd::setup::from_stdin(resume) {
            Ok(message) => {
                println!("{message}");
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
        };
    }

    if *first == "enroll" {
        return command_enroll(rest);
    }

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
        // This CLI's own build, no socket needed — distinct from `karst
        // version` below, which asks the running daemon for *its* build and
        // fails if there is none to ask.
        ("-V" | "--version", _) => {
            println!("karst {}", karstd::VERSION);
            return ExitCode::SUCCESS;
        }
        ("status", _) => Command::Status,
        ("dns", ["status", ..]) => Command::DnsStatus,
        ("dns", ["query", name, ..]) => Command::DnsQuery((*name).to_owned()),
        ("exit-node", ["list", ..]) => Command::ExitList,
        ("exit-node", ["use", id, ..]) => Command::ExitUse((*id).to_owned()),
        ("exit-node", ["disable", ..]) => Command::ExitDisable,
        ("bugreport", _) => Command::BugReport,
        ("metrics", _) => Command::Metrics,
        ("down", _) => Command::Down,
        ("version", _) => Command::Version,
        (other, _) => {
            eprintln!("karst: unknown command {other:?}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    let command_args = match (*first, rest) {
        ("dns", ["status", tail @ ..] | ["query", _, tail @ ..])
        | ("exit-node", ["list" | "disable", tail @ ..] | ["use", _, tail @ ..]) => tail,
        ("dns" | "exit-node", []) => &[],
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

#[cfg(unix)]
fn command_enroll(args: &[&str]) -> ExitCode {
    let mut bundle = None;
    let mut config = std::path::PathBuf::from("/etc/karst/karstd.toml");
    // See karstd::setup's STATE for why this default differs on macOS.
    #[cfg(target_os = "macos")]
    let mut state = std::path::PathBuf::from("/var/db/karst");
    #[cfg(not(target_os = "macos"))]
    let mut state = std::path::PathBuf::from("/var/lib/karst");
    let mut it = args.iter().copied();
    while let Some(arg) = it.next() {
        match (arg, it.next()) {
            ("--bundle", Some(path)) => bundle = Some(std::path::PathBuf::from(path)),
            ("--config", Some(path)) => config = path.into(),
            ("--state-dir", Some(path)) => state = path.into(),
            _ => {
                eprintln!(
                    "usage: sudo karst enroll --bundle FILE [--config PATH] [--state-dir PATH]"
                );
                return ExitCode::FAILURE;
            }
        }
    }
    let Some(bundle) = bundle else {
        eprintln!("karst: --bundle FILE is required");
        return ExitCode::FAILURE;
    };
    match karstd::enrollment::enroll(&bundle, &config, &state) {
        Ok(()) => {
            println!(
                "Device enrolled. Configuration saved to {}. Delete the downloaded bundle.",
                config.display()
            );
            #[cfg(target_os = "linux")]
            println!("Start the installed service: sudo systemctl enable --now karstd\nThen check: sudo karst status\nNetwork access still requires your deployment's ACL and Bedrock approval.");
            #[cfg(target_os = "macos")]
            println!("Start the installed launchd service, then check: sudo karst status");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("karst: enrollment failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn command_enroll(_: &[&str]) -> ExitCode {
    eprintln!("karst: guided enrollment is not yet supported on this platform");
    ExitCode::FAILURE
}
