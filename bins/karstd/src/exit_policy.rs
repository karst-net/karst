// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Linux policy routing for a locally consented exit offer.
//!
//! Exit traffic lives in a dedicated table. The main table is consulted first
//! with its default suppressed, preserving connected LAN and explicit host
//! routes; known control, relay, and peer underlay destinations get explicit
//! rules that may use the main-table default. The catch-all lookup is installed
//! last and removed first, so partial setup/cleanup cannot capture Karst's own
//! transport.
//!
//! **All three priorities sit below 32766.** Every network namespace and host
//! carries the kernel's own unconditional `32766: from all lookup main` rule
//! (and `32767: from all lookup default`) whether or not Karst has ever run.
//! It is *not* suppressed — only Karst's own `MAIN_PRIORITY` rule below sets
//! `suppress_prefixlength 0` — so a priority number at or above 32766 would
//! never be reached: the kernel's own default-route rule always matches a
//! packet to any destination first and terminates the lookup right there.
//! Confirmed the hard way — `bins/karstd/tests/aquifer.rs`'s exit-node row
//! reproduced exactly this against a real network namespace holding an
//! ordinary pre-existing default route, which every one of this module's own
//! mocked unit tests below is structurally unable to see, since `Mock`
//! records calls rather than asking a kernel to resolve one.

use std::collections::BTreeSet;
use std::io;
use std::net::IpAddr;
use std::process::{Command, Stdio};

const TABLE: &str = "51888";
const PROTOCOL: &str = "186";
const ESCAPE_PRIORITY: u32 = 100;
const MAIN_PRIORITY: u32 = 250;
const EXIT_PRIORITY: u32 = 260;
const MAX_ESCAPES: usize = (MAIN_PRIORITY - ESCAPE_PRIORITY) as usize;

trait Backend {
    fn run(&mut self, args: &[String]) -> io::Result<()>;
}

#[derive(Debug, Default)]
struct Host;

impl Backend for Host {
    fn run(&mut self, args: &[String]) -> io::Result<()> {
        let output = Command::new("ip")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn flag(self) -> &'static str {
        match self {
            Self::V4 => "-4",
            Self::V6 => "-6",
        }
    }

    fn host_len(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }
}

#[derive(Debug)]
struct State<B> {
    backend: B,
    undo: Vec<Vec<String>>,
    active: Option<Family>,
    escapes: BTreeSet<IpAddr>,
}

impl<B: Backend> State<B> {
    #[allow(clippy::too_many_lines)]
    fn activate(
        &mut self,
        interface: &str,
        family: Family,
        escapes: BTreeSet<IpAddr>,
    ) -> io::Result<()> {
        let escapes: BTreeSet<IpAddr> = escapes
            .into_iter()
            .filter(|address| address.is_ipv4() == (family == Family::V4))
            .collect();
        if escapes.len() > MAX_ESCAPES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} underlay escapes exceed the {MAX_ESCAPES} rule limit",
                    escapes.len()
                ),
            ));
        }
        if self.active == Some(family) && self.escapes == escapes {
            return Ok(());
        }
        self.clear();
        self.backend.run(&["-Version".to_owned()])?;

        let mut applied = Vec::new();
        let mut apply = |add: Vec<String>, delete: Vec<String>| -> io::Result<()> {
            // Best-effort delete before every add, not only the route below:
            // a crashed prior instance leaves its route *and* every rule
            // behind under Karst's own protocol marker — `Drop` does not run
            // under `SIGKILL` — and `ip rule add`, unlike `nft add table`, is
            // not idempotent against an exact duplicate. Without this, a bare
            // crash and restart with no netmap change at all made every one
            // of these five installs fail with "File exists" and the whole
            // activation roll back, leaving a previously-consented exit route
            // permanently dormant until something *else* changed enough to
            // retry — found by `bins/karstd/tests/aquifer.rs`'s own crash-
            // recovery row, which is the only one that restarts a node with
            // truly nothing about its config or netmap different from before.
            let _ = self.backend.run(&delete);
            self.backend.run(&add)?;
            applied.push(delete);
            Ok(())
        };
        let flag = family.flag().to_owned();
        if let Err(error) = apply(
            strings(&[
                family.flag(),
                "route",
                "add",
                "default",
                "dev",
                interface,
                "table",
                TABLE,
                "proto",
                PROTOCOL,
            ]),
            strings(&[
                family.flag(),
                "route",
                "del",
                "default",
                "dev",
                interface,
                "table",
                TABLE,
                "proto",
                PROTOCOL,
            ]),
        ) {
            rollback(&mut self.backend, &mut applied);
            return Err(error);
        }

        for (offset, address) in escapes.iter().enumerate() {
            let priority = ESCAPE_PRIORITY + u32::try_from(offset).unwrap_or(u32::MAX);
            let destination = format!("{address}/{}", family.host_len());
            if let Err(error) = apply(
                vec![
                    flag.clone(),
                    "rule".into(),
                    "add".into(),
                    "priority".into(),
                    priority.to_string(),
                    "to".into(),
                    destination.clone(),
                    "lookup".into(),
                    "main".into(),
                    "protocol".into(),
                    PROTOCOL.into(),
                ],
                vec![
                    flag.clone(),
                    "rule".into(),
                    "del".into(),
                    "priority".into(),
                    priority.to_string(),
                    "to".into(),
                    destination,
                    "lookup".into(),
                    "main".into(),
                    "protocol".into(),
                    PROTOCOL.into(),
                ],
            ) {
                rollback(&mut self.backend, &mut applied);
                return Err(error);
            }
        }

        if let Err(error) = apply(
            strings(&[
                family.flag(),
                "rule",
                "add",
                "priority",
                &MAIN_PRIORITY.to_string(),
                "lookup",
                "main",
                "suppress_prefixlength",
                "0",
                "protocol",
                PROTOCOL,
            ]),
            strings(&[
                family.flag(),
                "rule",
                "del",
                "priority",
                &MAIN_PRIORITY.to_string(),
                "lookup",
                "main",
                "suppress_prefixlength",
                "0",
                "protocol",
                PROTOCOL,
            ]),
        ) {
            rollback(&mut self.backend, &mut applied);
            return Err(error);
        }

        // Load-bearing last operation: until this succeeds, ordinary traffic
        // continues to use the host's original main-table default.
        if let Err(error) = apply(
            strings(&[
                family.flag(),
                "rule",
                "add",
                "priority",
                &EXIT_PRIORITY.to_string(),
                "lookup",
                TABLE,
                "protocol",
                PROTOCOL,
            ]),
            strings(&[
                family.flag(),
                "rule",
                "del",
                "priority",
                &EXIT_PRIORITY.to_string(),
                "lookup",
                TABLE,
                "protocol",
                PROTOCOL,
            ]),
        ) {
            rollback(&mut self.backend, &mut applied);
            return Err(error);
        }

        self.undo = applied;
        self.active = Some(family);
        self.escapes = escapes;
        Ok(())
    }

    fn clear(&mut self) {
        rollback(&mut self.backend, &mut self.undo);
        self.active = None;
        self.escapes.clear();
    }
}

fn rollback(backend: &mut impl Backend, undo: &mut Vec<Vec<String>>) {
    // Reverse order removes the catch-all exit lookup before any escape.
    while let Some(command) = undo.pop() {
        if let Err(error) = backend.run(&command) {
            eprintln!("karstd: could not remove exit policy rule: {error}");
        }
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[derive(Debug)]
pub struct Manager(State<Host>);

impl Default for Manager {
    fn default() -> Self {
        Self(State {
            backend: Host,
            undo: Vec::new(),
            active: None,
            escapes: BTreeSet::new(),
        })
    }
}

impl Manager {
    /// Activate one IP family through `interface` while preserving underlay
    /// destinations in the host's main routing table.
    ///
    /// # Errors
    /// If iproute2 rejects any staged route or policy rule. Applied stages are
    /// rolled back before the error is returned.
    pub fn activate(
        &mut self,
        interface: &str,
        exit: IpAddr,
        escapes: BTreeSet<IpAddr>,
    ) -> io::Result<()> {
        let family = if exit.is_ipv4() {
            Family::V4
        } else {
            Family::V6
        };
        self.0.activate(interface, family, escapes)
    }

    pub fn disable(&mut self) {
        self.0.clear();
    }

    #[must_use]
    pub fn active(&self) -> bool {
        self.0.active.is_some()
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.disable();
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

    use super::*;

    #[derive(Default, Debug)]
    struct Mock {
        commands: Vec<Vec<String>>,
        fail_at: Option<usize>,
        /// A crude kernel: an `add` whose spec (everything but the verb) is
        /// already present fails "File exists", the way a real `ip rule
        /// add`/`ip route add` does — unlike `nft add table`, neither
        /// tolerates an exact duplicate. `del` clears presence and is itself
        /// never an error, matching `remove_route`'s own "already absent is
        /// not a failure" convention. Empty (the default) for every test that
        /// is not specifically about this.
        already_present: std::collections::HashSet<Vec<String>>,
    }

    /// `args` with its verb (`add`/`del`, always index 2 — `-4`/`-6`, then
    /// `route`/`rule`, then the verb) removed, so `add priority 260 ...` and
    /// `del priority 260 ...` key the same install.
    fn spec_key(args: &[String]) -> Vec<String> {
        let mut key = args.to_vec();
        if key.len() > 2 {
            key.remove(2);
        }
        key
    }

    impl Backend for Mock {
        fn run(&mut self, args: &[String]) -> io::Result<()> {
            self.commands.push(args.to_vec());
            if self.fail_at == Some(self.commands.len()) {
                return Err(io::Error::other("synthetic ip failure"));
            }
            match args.get(2).map(String::as_str) {
                Some("add") if !self.already_present.insert(spec_key(args)) => {
                    return Err(io::Error::other("RTNETLINK answers: File exists"));
                }
                Some("del") => {
                    self.already_present.remove(&spec_key(args));
                }
                _ => {}
            }
            Ok(())
        }
    }

    fn state(mock: Mock) -> State<Mock> {
        State {
            backend: mock,
            undo: Vec::new(),
            active: None,
            escapes: BTreeSet::new(),
        }
    }

    #[test]
    fn activation_is_last_and_cleanup_removes_it_first() {
        let escapes = [
            "192.0.2.10".parse().unwrap(),
            "198.51.100.20".parse().unwrap(),
        ]
        .into_iter()
        .collect();
        let mut state = state(Mock::default());
        state.activate("karst0", Family::V4, escapes).unwrap();
        let activation = state.backend.commands.last().unwrap().join(" ");
        assert!(activation.contains("priority 260 lookup 51888"));

        let before = state.backend.commands.len();
        state.clear();
        let first_cleanup = state.backend.commands[before].join(" ");
        assert!(first_cleanup.contains("del priority 260"));
    }

    #[test]
    fn a_partial_failure_rolls_every_applied_stage_back() {
        // Position 9, not 6: each of the five installs now issues a
        // best-effort delete before its add (the crash-recovery fix above),
        // so the load-bearing last step — the exit table's own catch-all
        // rule — is the ninth command, not the sixth.
        let mut state = state(Mock {
            fail_at: Some(9),
            ..Mock::default()
        });
        let escapes = ["192.0.2.10".parse().unwrap()].into_iter().collect();
        assert!(state.activate("karst0", Family::V4, escapes).is_err());
        assert!(state.undo.is_empty());
        assert_eq!(state.active, None);
        assert!(state
            .backend
            .commands
            .iter()
            .any(|command| command.get(2).is_some_and(|v| v == "del")));
    }

    /// **The crash-recovery fix.** A prior instance's route and every rule
    /// survive a `SIGKILL` — `Drop` never runs — so a fresh process reusing
    /// the exact same priorities against the exact same kernel must not
    /// treat that as a failure. Before the fix, `bins/karstd/tests/
    /// aquifer.rs`'s own crash-recovery row hit exactly this: a bare crash
    /// and restart with no netmap change at all left a previously-active
    /// exit route permanently dormant.
    #[test]
    fn activation_tolerates_a_stale_rule_or_route_from_a_crashed_prior_instance() {
        let escapes: BTreeSet<IpAddr> = ["192.0.2.10".parse().unwrap()].into_iter().collect();

        // What a prior instance would have left installed before the crash.
        let mut crashed = state(Mock::default());
        crashed
            .activate("karst0", Family::V4, escapes.clone())
            .unwrap();
        let already_present: std::collections::HashSet<Vec<String>> = crashed
            .backend
            .commands
            .iter()
            .filter(|command| command.get(2).map(String::as_str) == Some("add"))
            .map(|command| spec_key(command))
            .collect();

        // A fresh process, with no memory of any of that — `undo` starts
        // empty, the same as any freshly constructed `State` — reusing the
        // exact same priorities against a kernel that still has them.
        let mut fresh = state(Mock {
            already_present,
            ..Mock::default()
        });
        fresh
            .activate("karst0", Family::V4, escapes)
            .expect("a bare crash and restart with an unchanged netmap must not fail activation");
    }

    #[test]
    fn only_the_selected_family_gets_escape_rules() {
        let escapes = [
            "192.0.2.10".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        ]
        .into_iter()
        .collect();
        let mut state = state(Mock::default());
        state.activate("karst0", Family::V6, escapes).unwrap();
        let all = state
            .backend
            .commands
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(all.contains("2001:db8::10/128"));
        assert!(!all.contains("192.0.2.10/32"));
    }
}
