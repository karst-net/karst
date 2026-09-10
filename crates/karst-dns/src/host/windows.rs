// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Windows host DNS integration: the Name Resolution Policy Table.
//!
//! The NRPT (`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`)
//! is what `plans/phase-5/07-windows-client.md` §6 calls "the correct
//! mechanism" — a registry-driven per-domain routing table the DNS Client
//! service consults before falling back to the adapter's own resolvers,
//! which is exactly the split-DNS semantics [`crate::Config`] already
//! describes. One subkey per domain, each naming the stub as that domain's
//! resolver — the same "longest match wins, everything else is untouched"
//! shape as the macOS `/etc/resolver` mechanism's one-file-per-domain resolver directory,
//! reached through the registry instead of the filesystem.
//!
//! **Subkey names are the domain itself, not a random GUID.** The plan's own
//! example (§6) shows a GUID-named rule because that is the convention
//! Group Policy and `Add-DnsClientNrptRule` follow, but nothing in the NRPT
//! schema requires it — the DNS Client service enumerates whatever child
//! keys `DnsPolicyConfig` has, and a name is otherwise inert. Using the
//! canonicalized domain instead means recovery never needs a separate
//! domain-to-GUID mapping: the name a killed daemon left behind *is* the
//! domain it was for. This mirrors `macos::resolver_name` closely
//! enough that both call [`crate::canonical_name`] for the same reason —
//! forwarding a control-plane string into an OS namespace exactly once.
//!
//! # What this does not do
//!
//! `SetInterfaceDnsSettings` (per-interface DNS on the tunnel adapter, which
//! the plan calls out because "some resolvers and some applications bypass
//! NRPT") is not implemented here. It is a separate IP Helper API keyed by
//! interface GUID rather than a registry write, needs real unsafe FFI with
//! no existing safe wrapper crate, and — per ADR-0003 — would belong in
//! `karst-tun`'s own `sys_windows` module beside the adapter it configures,
//! not here. Tracked as the remaining piece of plan §6; `karst dns status`
//! should eventually say so the way the macOS mechanism already reports its own
//! search-list gap, once a caller surfaces it.
//!
//! # Crash recovery
//!
//! The same contract as every other mechanism in this module: the revert
//! record is written to `state_path` before the first registry write and
//! removed after the last one is restored, so a daemon killed mid-apply
//! leaves enough behind for the next start (or `karst dns revert`) to undo —
//! see `plans/phase-5/01-karstdns.md` §7.1. Each rule also carries a marker
//! value (`Comment`, written first, before the values that make it a live
//! rule) so [`Nrpt::recover`] can find and remove its own leftovers even if
//! the record itself is gone, the same role macOS's own marker constant plays
//! for orphaned resolver files.

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(test)]
use std::sync::atomic::{AtomicU32, Ordering};

use windows_registry::{Key, LOCAL_MACHINE};
use windows_result::Error as RegistryError;

/// Where Group Policy and, now, Karst write Name Resolution Policy Table
/// rules.
pub const POLICY_ROOT: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";

/// The revert record. `%ProgramData%\Karst`, per
/// `plans/phase-6/10-windows-client.md` §5's ACL'd state directory — the
/// same place [`karst_secure_storage`](../../karst_secure_storage/index.html)
/// protects the node's other durable state, and unlike `%TEMP%` it survives
/// a reboot.
pub const REVERT_STATE: &str = r"C:\ProgramData\Karst\dns-revert";

/// The first bytes of the `Comment` value on every rule Karst writes —
/// the macOS mechanism's own marker constant's counterpart. Written before any of the values
/// that make a subkey an active rule, so a process killed mid-write still
/// leaves a recognizable, removable marker rather than a half-configured
/// rule with no way to tell it was ever Karst's.
const MARKER: &str = "Managed by KarstDNS";

/// Errors applying Windows host DNS configuration.
#[derive(Debug, thiserror::Error)]
pub enum NrptError {
    #[error("{path}: {source}")]
    Io { path: String, source: io::Error },
    #[error("registry key {path}: {source}")]
    Registry { path: String, source: RegistryError },
    /// A name arrived that Karst will not turn into a registry key name.
    /// Rule names come from the netmap, so this is a refusal, not a repair —
    /// see [`crate::host::MacosError::Domain`], which the same input takes
    /// on macOS.
    #[error(
        "{domain:?} is not a name KarstDNS will create an NRPT rule for: \
         every label must be 1-63 bytes of ASCII letters, digits or '-'"
    )]
    Domain { domain: String },
    #[error("KarstDNS DNS revert state at {path} is {detail}")]
    State { path: String, detail: &'static str },
    /// A subkey already exists at the name Karst would use, and its values
    /// do not read back as a rule Karst understands. Refused rather than
    /// overwritten — the same "leave host DNS alone rather than half-
    /// configured" posture the macOS mechanism takes for a domain it will not
    /// canonicalize, applied here to a registry key it cannot safely adopt.
    #[error(
        "registry key {path} already exists and is not one of KarstDNS's own NRPT rules; \
         refusing to overwrite it"
    )]
    Occupied { path: String },
}

/// One NRPT rule Karst owns, and whatever was there before it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ManagedRule {
    /// The subkey name under [`Nrpt::root`] — the canonicalized domain.
    name: String,
    /// The values to put back, or `None` if no subkey existed at this name.
    original: Option<RuleValues>,
    /// The values Karst wrote, so recovery can tell its own rule from a
    /// replacement somebody else installed afterwards.
    applied: RuleValues,
}

/// The full set of registry values one NRPT rule carries.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RuleValues {
    /// `Name`: the domain suffix this rule matches, `.`-wrapped per the
    /// plan's own example — a leading dot for suffix matching, a trailing
    /// dot because every value here is already the canonical, non-rooted
    /// form and this is the one place Windows expects the FQDN spelling
    /// back.
    name: Vec<String>,
    /// `GenericDNSServers`: the stub's address, as a bare IP — the value is
    /// documented as a string, not a `REG_MULTI_SZ`, so one resolver only.
    dns_servers: String,
    /// `ConfigOptions`: `0x8`, "DNS servers specified" — the one bit this
    /// rule ever sets.
    config_options: u32,
    /// `Version`: `1`, per the plan's example. The DNS Client service reads
    /// this; Karst never has cause to write anything else.
    version: u32,
    /// `Comment`: [`MARKER`], or whatever an unrelated key at the same name
    /// carried instead.
    comment: String,
}

impl RuleValues {
    fn for_stub(stub: SocketAddr) -> Self {
        Self {
            name: Vec::new(), // filled in by the caller, which knows the domain
            dns_servers: stub.ip().to_string(),
            config_options: 0x8,
            version: 1,
            comment: MARKER.to_owned(),
        }
    }

    /// Read all five values back. `None` if any is missing or not the type
    /// Karst itself would have written — a foreign key at this name is not
    /// something to partially adopt.
    fn read(key: &Key) -> Option<Self> {
        Some(Self {
            name: key.get_multi_string("Name").ok()?,
            dns_servers: key.get_string("GenericDNSServers").ok()?,
            config_options: key.get_u32("ConfigOptions").ok()?,
            version: key.get_u32("Version").ok()?,
            comment: key.get_string("Comment").ok()?,
        })
    }

    /// Write all five values, `Comment` first — see the module docs on why
    /// the marker goes first.
    fn write(&self, key: &Key) -> Result<(), RegistryError> {
        key.set_string("Comment", &self.comment)?;
        let name: Vec<&str> = self.name.iter().map(String::as_str).collect();
        key.set_multi_string("Name", &name)?;
        key.set_string("GenericDNSServers", &self.dns_servers)?;
        key.set_u32("ConfigOptions", self.config_options)?;
        key.set_u32("Version", self.version)?;
        Ok(())
    }
}

/// Everything one apply must undo.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Revert {
    rules: Vec<ManagedRule>,
    /// Whether Karst created [`Nrpt::root`] itself. A machine whose
    /// `DnsPolicyConfig` key did not exist before should not keep an empty
    /// one afterwards — see macOS's own `created_directory` flag on the same idea.
    created_root: bool,
}

/// How to nudge the DNS Client service after the NRPT rules change.
///
/// Mirrors the macOS mechanism's own `Flush` enum: rather than a boxed closure, so
/// the tests can assert a flush happened without losing `Debug`.
#[derive(Debug)]
enum Flush {
    /// `ipconfig /flushdns`. Discards cached negative and positive answers
    /// so a name resolved once under the host's previous resolvers does not
    /// keep answering from cache for the rest of its TTL. Whether the DNS
    /// Client service also needs a distinct "re-read policy" nudge beyond
    /// this is exactly the kind of thing plan §6 flags for a domain-joined
    /// machine to confirm — `ipconfig /flushdns` is the documented,
    /// unprivileged mechanism every other Windows DNS tool uses, and is
    /// what this ships until that manual verification says otherwise.
    Ipconfig,
    /// Count the calls instead of making them. Tests only.
    #[cfg(test)]
    Counted(AtomicU32),
}

/// Windows host DNS integration over the Name Resolution Policy Table.
///
/// `root` and `state_path` are constructor arguments so tests never touch
/// the real `DnsPolicyConfig` key — a live rule there is interpreted by the
/// DNS Client service on this machine for as long as it exists, which is
/// exactly the accidental-system-state [`Nrpt::system`]'s callers do not
/// want a test run to leave behind. [`Nrpt::system`] supplies the real pair.
#[derive(Debug)]
pub struct Nrpt {
    root: String,
    state_path: PathBuf,
    flush: Flush,
    applied: Option<Revert>,
    flush_error: Option<String>,
}

impl Nrpt {
    /// Integrate against a caller-supplied registry root and revert-state
    /// path. `root` is relative to `HKEY_LOCAL_MACHINE`.
    #[must_use]
    pub fn new(root: impl Into<String>, state_path: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            state_path: state_path.into(),
            flush: Flush::Ipconfig,
            applied: None,
            flush_error: None,
        }
    }

    /// Integrate against the real NRPT and `%ProgramData%\Karst`.
    #[must_use]
    pub fn system() -> Self {
        Self::new(POLICY_ROOT, REVERT_STATE)
    }

    /// Point every mesh name at the KarstDNS stub.
    ///
    /// Applying twice reverts the first application first, so the persisted
    /// original is always the host's pre-Karst state — see
    /// [`crate::host::Macos::apply`], which this mirrors exactly for the
    /// same reason.
    ///
    /// # Errors
    /// A name the netmap supplied is not one Karst will create a rule for
    /// ([`NrptError::Domain`]), a rule name is already occupied by
    /// something Karst does not recognize as its own
    /// ([`NrptError::Occupied`]), or the registry/state-file writes
    /// themselves fail.
    pub fn apply(
        &mut self,
        stub: SocketAddr,
        zone: &str,
        search_domains: &[String],
    ) -> Result<(), NrptError> {
        let names = rule_names(zone, search_domains)?;
        if let Some(previous) = self.applied.take() {
            self.restore(&previous)?;
        }

        let created_root = LOCAL_MACHINE.open(&self.root).is_err();
        let root = LOCAL_MACHINE
            .create(&self.root)
            .map_err(registry_at(&self.root))?;

        let mut rules = Vec::with_capacity(names.len());
        for name in names {
            let path = format!(r"{}\{name}", self.root);
            let original = match root.open(&name) {
                Ok(existing) => Some(
                    RuleValues::read(&existing)
                        .ok_or_else(|| NrptError::Occupied { path: path.clone() })?,
                ),
                Err(_) => None,
            };
            let mut applied = RuleValues::for_stub(stub);
            applied.name = vec![format!(".{name}.")];
            rules.push(ManagedRule {
                name,
                original,
                applied,
            });
        }
        let revert = Revert {
            rules,
            created_root,
        };

        // The record first, always — plan §7.1. Everything after this point
        // is undoable by a later process; anything written before it would
        // not be.
        self.write_state(&revert)?;
        for rule in &revert.rules {
            let key = root.create(&rule.name).map_err(registry_at(&self.root))?;
            rule.applied
                .write(&key)
                .map_err(registry_at(&format!(r"{}\{}", self.root, rule.name)))?;
        }
        self.applied = Some(revert);
        self.flush();
        Ok(())
    }

    /// Put the NRPT back the way it was found.
    ///
    /// # Errors
    /// A registry or state-file write failed.
    pub fn revert(&mut self) -> Result<(), NrptError> {
        let Some(revert) = self.applied.take() else {
            self.flush_error = None;
            return Ok(());
        };
        self.restore(&revert)?;
        self.flush();
        Ok(())
    }

    /// Undo an application this process did not make. Returns whether
    /// anything was undone; missing state is the ordinary first-start case,
    /// not an error. See [`crate::host::Macos::recover`] — same two-part
    /// recovery, registry keys standing in for files.
    ///
    /// # Errors
    /// The revert record exists but is corrupt, or a registry/state-file
    /// operation fails.
    pub fn recover(&mut self) -> Result<bool, NrptError> {
        let recorded = match fs::read(&self.state_path) {
            Ok(state) => Some(Revert::decode(&state).ok_or_else(|| NrptError::State {
                path: self.state_path.display().to_string(),
                detail: "truncated or malformed",
            })?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(io_at(&self.state_path)(error)),
        };

        let root = LOCAL_MACHINE.open(&self.root).ok();
        let mut restored = false;
        let mut known: Vec<String> = Vec::new();
        if let Some(revert) = &recorded {
            if let Some(root) = &root {
                for rule in &revert.rules {
                    known.push(rule.name.clone());
                    match root
                        .open(&rule.name)
                        .ok()
                        .and_then(|key| RuleValues::read(&key))
                    {
                        Some(live) if live == rule.applied => {
                            restore_rule(root, &rule.name, rule.original.as_ref())?;
                            restored = true;
                        }
                        // Replaced by somebody else, or already gone. No
                        // longer Karst's to put back.
                        _ => {}
                    }
                }
            }
            remove_if_present(&self.state_path)?;
        }

        if let Some(root) = &root {
            restored |= Self::sweep_orphans(root, &known);
            if recorded.as_ref().is_some_and(|revert| revert.created_root) {
                prune_if_empty(&self.root);
            }
        }
        if restored {
            self.flush();
        }
        Ok(restored)
    }

    /// Whether every rule this process applied still holds the values it
    /// wrote.
    ///
    /// # Errors
    /// A registry read failed for a reason other than the key being gone.
    pub fn observe(&self) -> Result<bool, NrptError> {
        let Some(revert) = &self.applied else {
            return Ok(false);
        };
        if revert.rules.is_empty() {
            return Ok(false);
        }
        let Ok(root) = LOCAL_MACHINE.open(&self.root) else {
            return Ok(false);
        };
        for rule in &revert.rules {
            match root
                .open(&rule.name)
                .ok()
                .and_then(|key| RuleValues::read(&key))
            {
                Some(live) if live == rule.applied => {}
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    /// Why the last cache flush failed, if it did — see
    /// [`crate::host::Macos::flush_error`] for why this is reported rather
    /// than folded into [`Nrpt::apply`]'s own result.
    #[must_use]
    pub fn flush_error(&self) -> Option<&str> {
        self.flush_error.as_deref()
    }

    fn restore(&mut self, revert: &Revert) -> Result<(), NrptError> {
        if let Ok(root) = LOCAL_MACHINE.open(&self.root) {
            for rule in &revert.rules {
                restore_rule(&root, &rule.name, rule.original.as_ref())?;
            }
        }
        remove_if_present(&self.state_path)?;
        if revert.created_root {
            prune_if_empty(&self.root);
        }
        Ok(())
    }

    fn sweep_orphans(root: &Key, known: &[String]) -> bool {
        let Ok(children) = root.keys() else {
            return false;
        };
        let mut removed = false;
        for name in children {
            if known.contains(&name) {
                continue;
            }
            let is_ours = root
                .open(&name)
                .and_then(|key| key.get_string("Comment"))
                .is_ok_and(|comment| comment == MARKER);
            if is_ours {
                let _ = root.remove_tree(&name);
                removed = true;
            }
        }
        removed
    }

    fn write_state(&self, revert: &Revert) -> Result<(), NrptError> {
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent).map_err(io_at(parent))?;
        }
        fs::write(&self.state_path, revert.encode()).map_err(io_at(&self.state_path))
    }

    fn flush(&mut self) {
        let outcome = self.flush.run().err();
        self.flush_error = outcome;
    }
}

impl Flush {
    fn run(&self) -> Result<(), String> {
        match self {
            #[cfg(test)]
            Self::Counted(calls) => {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Self::Ipconfig => {
                let output = Command::new("ipconfig")
                    .arg("/flushdns")
                    .output()
                    .map_err(|error| format!("ipconfig: {error}"))?;
                if !output.status.success() {
                    return Err(format!(
                        "ipconfig /flushdns exited {}: {}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr).trim()
                    ));
                }
                Ok(())
            }
        }
    }
}

fn restore_rule(root: &Key, name: &str, original: Option<&RuleValues>) -> Result<(), NrptError> {
    if let Some(values) = original {
        let key = root
            .create(name)
            .map_err(registry_at(&format!("{name} (restore)")))?;
        values
            .write(&key)
            .map_err(registry_at(&format!("{name} (restore)")))
    } else {
        let _ = root.remove_tree(name);
        Ok(())
    }
}

fn remove_if_present(path: &Path) -> Result<(), NrptError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_at(path)(error)),
    }
}

/// Best effort, like macOS's own `remove_directory_if_empty`: a rule
/// appearing between the emptiness check and the removal means the key is
/// in use, which is the outcome this wants anyway.
fn prune_if_empty(root: &str) {
    if let Ok(key) = LOCAL_MACHINE.open(root) {
        if key
            .keys()
            .is_ok_and(|mut children| children.next().is_none())
        {
            let _ = LOCAL_MACHINE.remove_tree(root);
        }
    }
}

fn io_at(path: &Path) -> impl FnOnce(io::Error) -> NrptError + '_ {
    move |source| NrptError::Io {
        path: path.display().to_string(),
        source,
    }
}

fn registry_at(path: &str) -> impl FnOnce(RegistryError) -> NrptError + '_ {
    move |source| NrptError::Registry {
        path: path.to_owned(),
        source,
    }
}

/// The rule names for one netmap DNS configuration — see
/// `macos::resolver_names`, which this is a direct counterpart of.
fn rule_names(zone: &str, search_domains: &[String]) -> Result<Vec<String>, NrptError> {
    let mut names = Vec::with_capacity(search_domains.len() + 1);
    for domain in std::iter::once(zone).chain(search_domains.iter().map(String::as_str)) {
        let name = rule_name(domain)?;
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names.sort_unstable();
    Ok(names)
}

/// One domain, as an NRPT subkey name — see `macos::resolver_name`,
/// which applies the identical rule for the identical reason (reusing
/// [`crate::canonical_name`] rather than a second, divergent definition of
/// an acceptable domain). A registry key name has none of a path's
/// traversal characters to worry about, but the validation is shared
/// anyway: the two mechanisms must refuse exactly the same netmap input.
fn rule_name(domain: &str) -> Result<String, NrptError> {
    let refuse = || NrptError::Domain {
        domain: domain.to_owned(),
    };
    let name = crate::canonical_name(domain.trim()).map_err(|_| refuse())?;
    if name.is_empty() {
        return Err(refuse());
    }
    Ok(name)
}

impl Revert {
    fn encode(&self) -> Vec<u8> {
        let mut state = Vec::new();
        let count = u64::try_from(self.rules.len()).unwrap_or(u64::MAX);
        state.extend_from_slice(&count.to_be_bytes());
        for rule in &self.rules {
            put_bytes(&mut state, rule.name.as_bytes());
            match &rule.original {
                Some(original) => {
                    state.push(1);
                    original.encode(&mut state);
                }
                None => state.push(0),
            }
            rule.applied.encode(&mut state);
        }
        state.push(u8::from(self.created_root));
        state
    }

    fn decode(state: &[u8]) -> Option<Self> {
        let mut rest = state;
        let count = usize::try_from(u64::from_be_bytes(take_array(&mut rest)?)).ok()?;
        let mut rules = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let name = String::from_utf8(take_bytes(&mut rest)?.to_vec()).ok()?;
            let original = match take_array::<1>(&mut rest)? {
                [0] => None,
                [1] => Some(RuleValues::decode(&mut rest)?),
                _ => return None,
            };
            let applied = RuleValues::decode(&mut rest)?;
            rules.push(ManagedRule {
                name,
                original,
                applied,
            });
        }
        let created_root = match take_array::<1>(&mut rest)? {
            [0] => false,
            [1] => true,
            _ => return None,
        };
        if !rest.is_empty() {
            return None;
        }
        Some(Self {
            rules,
            created_root,
        })
    }
}

impl RuleValues {
    fn encode(&self, state: &mut Vec<u8>) {
        let count = u64::try_from(self.name.len()).unwrap_or(u64::MAX);
        state.extend_from_slice(&count.to_be_bytes());
        for label in &self.name {
            put_bytes(state, label.as_bytes());
        }
        put_bytes(state, self.dns_servers.as_bytes());
        state.extend_from_slice(&self.config_options.to_be_bytes());
        state.extend_from_slice(&self.version.to_be_bytes());
        put_bytes(state, self.comment.as_bytes());
    }

    fn decode(rest: &mut &[u8]) -> Option<Self> {
        let count = usize::try_from(u64::from_be_bytes(take_array(rest)?)).ok()?;
        let mut name = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            name.push(String::from_utf8(take_bytes(rest)?.to_vec()).ok()?);
        }
        let dns_servers = String::from_utf8(take_bytes(rest)?.to_vec()).ok()?;
        let config_options = u32::from_be_bytes(take_array(rest)?);
        let version = u32::from_be_bytes(take_array(rest)?);
        let comment = String::from_utf8(take_bytes(rest)?.to_vec()).ok()?;
        Some(Self {
            name,
            dns_servers,
            config_options,
            version,
            comment,
        })
    }
}

fn put_bytes(state: &mut Vec<u8>, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    state.extend_from_slice(&length.to_be_bytes());
    state.extend_from_slice(bytes);
}

fn take_array<const N: usize>(rest: &mut &[u8]) -> Option<[u8; N]> {
    let (head, tail) = rest.split_at_checked(N)?;
    *rest = tail;
    head.try_into().ok()
}

fn take_bytes<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length = usize::try_from(u64::from_be_bytes(take_array(rest)?)).ok()?;
    let (head, tail) = rest.split_at_checked(length)?;
    *rest = tail;
    Some(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A disposable registry root and revert record, removed on drop so a
    /// failing assertion does not leave the next run's fixtures behind. The
    /// root lives under `SOFTWARE\Karst\test\...`, never under the real
    /// `DnsPolicyConfig` — see [`Nrpt`]'s own docs on why a test must not
    /// create a rule the DNS Client service would actually interpret.
    struct Fixture {
        root: String,
        state_path: PathBuf,
        host: Nrpt,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = LOCAL_MACHINE.remove_tree(&self.root);
            let _ = fs::remove_file(&self.state_path);
        }
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let unique = format!(
                "karst-dns-nrpt-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            )
            .replace(['(', ')', ':'], "-");
            let root = format!(r"SOFTWARE\Karst\test\{unique}");
            let state_path = std::env::temp_dir().join(format!("{unique}-dns-revert"));
            let _ = fs::remove_file(&state_path);
            let mut host = Nrpt::new(root.clone(), state_path.clone());
            host.flush = Flush::Counted(AtomicU32::new(0));
            Self {
                root,
                state_path,
                host,
            }
        }

        fn rule(&self, name: &str) -> Option<RuleValues> {
            LOCAL_MACHINE
                .open(&self.root)
                .ok()
                .and_then(|root| root.open(name).ok())
                .and_then(|key| RuleValues::read(&key))
        }

        fn flushes(&self) -> u32 {
            match &self.host.flush {
                Flush::Counted(calls) => calls.load(Ordering::Relaxed),
                Flush::Ipconfig => panic!("fixture must count flushes"),
            }
        }
    }

    fn stub() -> SocketAddr {
        "100.100.100.100:53".parse().expect("stub address")
    }

    #[test]
    fn the_zone_and_every_search_domain_get_a_rule() {
        let mut fixture = Fixture::new("apply");
        fixture
            .host
            .apply(stub(), "aquifer.karst.", &["corp.example.".to_owned()])
            .expect("apply");

        let zone = fixture.rule("aquifer.karst").expect("zone rule");
        assert_eq!(zone.name, vec![".aquifer.karst.".to_owned()]);
        assert_eq!(zone.dns_servers, "100.100.100.100");
        assert_eq!(zone.config_options, 0x8);
        assert_eq!(zone.version, 1);
        assert_eq!(zone.comment, MARKER);
        assert_eq!(fixture.rule("corp.example").expect("split rule"), zone);
        assert!(fixture.host.observe().expect("observe"));
        assert_eq!(fixture.flushes(), 1, "apply must flush the resolver cache");
    }

    /// The plan's exit criterion 4: nothing of Karst's is left behind,
    /// including the root key on a machine that had none.
    #[test]
    fn revert_leaves_the_machine_as_it_was_found() {
        let mut fixture = Fixture::new("revert");
        fixture
            .host
            .apply(stub(), "aquifer.karst.", &[])
            .expect("apply");
        fixture.host.revert().expect("revert");

        assert!(fixture.rule("aquifer.karst").is_none());
        assert!(
            LOCAL_MACHINE.open(&fixture.root).is_err(),
            "a root key Karst created must not survive its revert"
        );
        assert!(!fixture.state_path.exists());
        assert_eq!(fixture.flushes(), 2, "revert must flush too");
    }

    /// Unlike [`crate::host::Macos`], which backs up and restores a
    /// pre-existing resolver file byte for byte (a real risk there — an
    /// admin plausibly hand-authors a file named for a domain), a foreign
    /// key at an NRPT rule name is refused outright: nothing but Karst and
    /// GPO write this branch, GPO names its rules with GUIDs never a bare
    /// domain, and round-tripping arbitrary registry values correctly is a
    /// larger contract than this collision risk justifies taking on.
    #[test]
    fn a_pre_existing_rule_at_the_same_name_is_refused_not_adopted() {
        let fixture = Fixture::new("preexisting");
        let root = LOCAL_MACHINE.create(&fixture.root).expect("create root");
        let theirs = RuleValues {
            name: vec![".corp.example.".to_owned()],
            dns_servers: "10.0.0.53".to_owned(),
            config_options: 0x8,
            version: 1,
            comment: "not KarstDNS".to_owned(),
        };
        let key = root.create("corp.example").expect("their key");
        theirs.write(&key).expect("their values");

        let mut host = Nrpt::new(fixture.root.clone(), fixture.state_path.clone());
        host.flush = Flush::Counted(AtomicU32::new(0));
        let error = host
            .apply(stub(), "aquifer.karst.", &["corp.example".to_owned()])
            .expect_err("a foreign rule at this name must be refused, not adopted");
        assert!(matches!(error, NrptError::Occupied { .. }), "{error:?}");
        assert_eq!(
            fixture.rule("corp.example").expect("untouched"),
            theirs,
            "a refused rule must leave the foreign key exactly as found"
        );
    }

    /// The `taskkill /F` case (plan §11 exit criterion 5): the process that
    /// applied is gone, and the next start has only the record to work from.
    #[test]
    fn a_killed_daemon_leaves_a_record_the_next_start_consumes() {
        let fixture = Fixture::new("recover");
        let mut killed = Nrpt::new(fixture.root.clone(), fixture.state_path.clone());
        killed.flush = Flush::Counted(AtomicU32::new(0));
        killed
            .apply(stub(), "aquifer.karst.", &["corp.example".to_owned()])
            .expect("apply");
        drop(killed);

        let mut restarted = Nrpt::new(fixture.root.clone(), fixture.state_path.clone());
        restarted.flush = Flush::Counted(AtomicU32::new(0));
        assert!(restarted.recover().expect("recover"));
        assert!(fixture.rule("aquifer.karst").is_none());
        assert!(fixture.rule("corp.example").is_none());
        assert!(!fixture.state_path.exists());
        assert!(!restarted.observe().expect("observe after recovery"));
    }

    /// The state file living under a durable directory (not `%TEMP%`, in
    /// production) is what plan §7.1 requires; this asserts the *other*
    /// half of that contract still holds even when it is gone — the marker
    /// on each rule is what makes recovery possible at all in that case.
    #[test]
    fn orphaned_rules_are_recovered_without_a_record_at_all() {
        let fixture = Fixture::new("orphan");
        let mut killed = Nrpt::new(fixture.root.clone(), fixture.state_path.clone());
        killed.flush = Flush::Counted(AtomicU32::new(0));
        killed.apply(stub(), "aquifer.karst.", &[]).expect("apply");
        drop(killed);
        fs::remove_file(&fixture.state_path).expect("simulate a lost revert record");

        let mut restarted = Nrpt::new(fixture.root.clone(), fixture.state_path.clone());
        restarted.flush = Flush::Counted(AtomicU32::new(0));
        assert!(restarted.recover().expect("recover"));
        assert!(fixture.rule("aquifer.karst").is_none());
    }

    /// A rule somebody else replaced is theirs. Recovery must not write
    /// stale values over a change Karst no longer owns.
    #[test]
    fn recovery_does_not_clobber_a_later_external_change() {
        let fixture = Fixture::new("external");
        let mut killed = Nrpt::new(fixture.root.clone(), fixture.state_path.clone());
        killed.flush = Flush::Counted(AtomicU32::new(0));
        killed.apply(stub(), "aquifer.karst.", &[]).expect("apply");
        drop(killed);
        let root = LOCAL_MACHINE.open(&fixture.root).expect("root");
        let key = root.create("aquifer.karst").expect("existing key");
        key.set_string("GenericDNSServers", "10.0.0.53")
            .expect("administrator edit");

        let mut restarted = Nrpt::new(fixture.root.clone(), fixture.state_path.clone());
        restarted.flush = Flush::Counted(AtomicU32::new(0));
        assert!(!restarted.recover().expect("recover"));
        assert_eq!(
            fixture
                .rule("aquifer.karst")
                .map(|values| values.dns_servers),
            Some("10.0.0.53".to_owned()),
            "the administrator's edit must survive recovery untouched"
        );
        assert!(
            !fixture.state_path.exists(),
            "a consumed record must not be left behind"
        );
    }

    #[test]
    fn observe_reports_a_later_external_change() {
        let mut fixture = Fixture::new("observe");
        fixture
            .host
            .apply(stub(), "aquifer.karst.", &[])
            .expect("apply");
        assert!(fixture.host.observe().expect("Karst owns the rule"));
        let root = LOCAL_MACHINE.open(&fixture.root).expect("root");
        let key = root.open("aquifer.karst").expect("rule key");
        key.set_string("GenericDNSServers", "10.0.0.53")
            .expect("external edit");
        assert!(!fixture.host.observe().expect("external ownership"));
    }

    /// A second netmap generation with a different search list must leave
    /// the first generation's rules behind, reverting to the host's own
    /// state rather than the previous Karst generation.
    #[test]
    fn a_second_apply_removes_the_first_generations_rules() {
        let mut fixture = Fixture::new("regenerate");
        fixture
            .host
            .apply(stub(), "aquifer.karst.", &["first.example".to_owned()])
            .expect("first apply");
        fixture
            .host
            .apply(stub(), "aquifer.karst.", &["second.example".to_owned()])
            .expect("second apply");

        assert!(fixture.rule("first.example").is_none());
        assert!(fixture.rule("second.example").is_some());
        assert_eq!(fixture.flushes(), 2);

        fixture.host.revert().expect("revert");
        assert!(LOCAL_MACHINE.open(&fixture.root).is_err());
    }

    /// The zone is normally also reachable as a search domain. One rule,
    /// not a duplicate pair.
    #[test]
    fn a_domain_that_repeats_the_zone_is_written_once() {
        assert_eq!(
            rule_names(
                "Aquifer.Karst.",
                &["aquifer.karst".to_owned(), "corp.example.".to_owned()]
            )
            .expect("names"),
            vec!["aquifer.karst".to_owned(), "corp.example".to_owned()]
        );
    }

    /// The same refusal set `macos::resolver_name` enforces
    /// — shared validation, so a name that reaches one mechanism and not the
    /// other would itself be the bug.
    #[test]
    fn a_domain_that_would_escape_validation_is_refused() {
        let long_label = "a".repeat(64);
        let long_name = "a.".repeat(200);
        for bad in [
            "..",
            ".",
            "",
            "corp..example",
            ".corp.example",
            "corp example",
            "corp\0example",
            "corp$example",
            "corp_example",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(
                matches!(rule_name(bad), Err(NrptError::Domain { .. })),
                "{bad:?} must be refused"
            );
        }
    }

    /// One bad name in the search list must not leave the others applied.
    #[test]
    fn a_refused_domain_leaves_host_dns_untouched() {
        let mut fixture = Fixture::new("refused");
        let error = fixture
            .host
            .apply(stub(), "aquifer.karst.", &["../escape".to_owned()])
            .expect_err("refused");
        assert!(matches!(error, NrptError::Domain { .. }));
        assert!(LOCAL_MACHINE.open(&fixture.root).is_err());
        assert!(!fixture.state_path.exists());
        assert_eq!(fixture.flushes(), 0);
    }

    #[test]
    fn the_revert_record_round_trips() {
        let revert = Revert {
            rules: vec![
                ManagedRule {
                    name: "aquifer.karst".to_owned(),
                    original: None,
                    applied: {
                        let mut values = RuleValues::for_stub(stub());
                        values.name = vec![".aquifer.karst.".to_owned()];
                        values
                    },
                },
                ManagedRule {
                    name: "corp.example".to_owned(),
                    original: Some(RuleValues {
                        name: vec![".corp.example.".to_owned()],
                        dns_servers: "10.0.0.53".to_owned(),
                        config_options: 0x8,
                        version: 1,
                        comment: "not KarstDNS".to_owned(),
                    }),
                    applied: {
                        let mut values = RuleValues::for_stub(stub());
                        values.name = vec![".corp.example.".to_owned()];
                        values
                    },
                },
            ],
            created_root: true,
        };
        let encoded = revert.encode();
        assert_eq!(Revert::decode(&encoded), Some(revert));
    }

    #[test]
    fn a_truncated_or_padded_record_is_refused_outright() {
        let encoded = Revert {
            rules: vec![ManagedRule {
                name: "aquifer.karst".to_owned(),
                original: Some(RuleValues {
                    name: vec!["10.0.0.53".to_owned()],
                    dns_servers: "10.0.0.53".to_owned(),
                    config_options: 0x8,
                    version: 1,
                    comment: "not KarstDNS".to_owned(),
                }),
                applied: {
                    let mut values = RuleValues::for_stub(stub());
                    values.name = vec![".aquifer.karst.".to_owned()];
                    values
                },
            }],
            created_root: false,
        }
        .encode();
        for length in 0..encoded.len() {
            assert_eq!(
                Revert::decode(&encoded[..length]),
                None,
                "a {length}-byte prefix must not decode"
            );
        }
        let mut padded = encoded.clone();
        padded.push(0);
        assert_eq!(Revert::decode(&padded), None);
    }

    #[test]
    fn a_malformed_record_is_an_error_rather_than_a_silent_skip() {
        let fixture = Fixture::new("malformed");
        fs::create_dir_all(fixture.state_path.parent().expect("state parent"))
            .expect("state directory");
        fs::write(&fixture.state_path, b"not a revert record").expect("write");
        let mut host = Nrpt::new(fixture.root.clone(), fixture.state_path.clone());
        host.flush = Flush::Counted(AtomicU32::new(0));
        assert!(matches!(
            host.recover(),
            Err(NrptError::State { detail, .. }) if detail.contains("malformed")
        ));
    }

    #[test]
    fn recovery_of_a_machine_karst_never_touched_is_a_no_op() {
        let fixture = Fixture::new("untouched");
        let mut host = Nrpt::new(fixture.root.clone(), fixture.state_path.clone());
        host.flush = Flush::Counted(AtomicU32::new(0));
        assert!(!host.recover().expect("recover"));
    }
}
