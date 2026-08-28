// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! NetworkManager's temporary per-device DNS configuration.
//!
//! We update the *applied* connection with `Device.Reapply`, never its saved
//! profile. This keeps KarstDNS from leaving a connection file behind after it
//! exits and lets [`NetworkManager::revert`] put the exact snapshot back.

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{
    serialized::{Context, Data},
    OwnedObjectPath, OwnedValue, Value, LE,
};

const DESTINATION: &str = "org.freedesktop.NetworkManager";
const MANAGER_PATH: &str = "/org/freedesktop/NetworkManager";
const MANAGER_INTERFACE: &str = "org.freedesktop.NetworkManager";
const DEVICE_INTERFACE: &str = "org.freedesktop.NetworkManager.Device";

type Settings = HashMap<String, HashMap<String, OwnedValue>>;
const REVERT_PATH: &str = "/run/karst/networkmanager-dns-revert";

/// NetworkManager connection snapshot changed only in memory for one device.
#[derive(Debug)]
pub struct NetworkManager {
    connection: Connection,
    device: OwnedObjectPath,
    original: Option<Settings>,
    state_path: PathBuf,
    expected: Option<(String, String)>,
}

/// Errors from NetworkManager or value construction.
#[derive(Debug, thiserror::Error)]
pub enum NetworkManagerError {
    #[error("the NetworkManager device has no IPv4 settings")]
    MissingIpv4,
    #[error("D-Bus call to NetworkManager failed: {0}")]
    Bus(#[from] zbus::Error),
    #[error("cannot encode NetworkManager DNS setting: {0}")]
    Variant(#[from] zbus::zvariant::Error),
    #[error("cannot persist NetworkManager DNS recovery state: {0}")]
    Io(#[from] std::io::Error),
}

impl NetworkManager {
    /// Find a NetworkManager-managed interface by its IP interface name.
    pub fn connect(interface: &str) -> Result<Self, NetworkManagerError> {
        Self::connect_with_state(interface, REVERT_PATH)
    }

    /// Connect with an explicit state path. The alternate constructor keeps
    /// tests away from `/run` while production uses [`REVERT_PATH`].
    pub fn connect_with_state(
        interface: &str,
        state_path: impl Into<PathBuf>,
    ) -> Result<Self, NetworkManagerError> {
        let connection = Connection::system()?;
        let manager = Proxy::new(&connection, DESTINATION, MANAGER_PATH, MANAGER_INTERFACE)?;
        let device: OwnedObjectPath = manager.call("GetDeviceByIpIface", &interface)?;
        let mut result = Self {
            connection,
            device,
            original: None,
            state_path: state_path.into(),
            expected: None,
        };
        // A state file exists only if a previous process got as far as
        // changing NM. Restore before it can install a new snapshot.
        result.recover()?;
        Ok(result)
    }

    /// Scope the DNS stub to the mesh route on this device.
    ///
    /// `~zone` is NetworkManager's routing-domain notation. A priority of -50
    /// wins duplicate routing domains without becoming the host's `~.` default
    /// route, so non-mesh questions retain their ordinary path.
    pub fn apply(
        &mut self,
        stub: SocketAddr,
        zone: &str,
        search_domains: &[String],
    ) -> Result<(), NetworkManagerError> {
        let (mut settings, _version): (Settings, u64) =
            self.proxy()?.call("GetAppliedConnection", &0u32)?;
        if self.original.is_none() {
            self.persist(&settings)?;
            self.original = Some(settings.clone());
        }
        configure(&mut settings, stub, zone, search_domains)?;
        self.reapply(settings)?;
        self.expected = Some((
            stub.ip().to_string(),
            format!("~{}", zone.trim_end_matches('.')),
        ));
        Ok(())
    }

    /// Restore the applied-connection snapshot captured before [`Self::apply`].
    pub fn revert(&mut self) -> Result<(), NetworkManagerError> {
        let Some(settings) = self.original.take() else {
            return Ok(());
        };
        self.reapply(settings)?;
        remove_state(&self.state_path)?;
        self.expected = None;
        Ok(())
    }

    /// Read the applied connection back from NetworkManager and verify the
    /// route-only stub settings Karst installed are still present.
    pub fn observe(&self) -> Result<bool, NetworkManagerError> {
        let Some((stub, route)) = &self.expected else {
            return Ok(false);
        };
        let (settings, _): (Settings, u64) = self.proxy()?.call("GetAppliedConnection", &0u32)?;
        Ok(matches_expected(&settings, stub, route))
    }

    /// Restore a snapshot left by a killed daemon. A snapshot is tied to the
    /// D-Bus object path, preventing one old TUN instance from overwriting a
    /// different NetworkManager device that happens to start later.
    pub fn recover(&mut self) -> Result<bool, NetworkManagerError> {
        let Some((device, settings)) = load_state(&self.state_path)? else {
            return Ok(false);
        };
        if device != self.device.as_str() {
            return Ok(false);
        }
        self.reapply(settings)?;
        remove_state(&self.state_path)?;
        Ok(true)
    }

    fn reapply(&self, settings: Settings) -> Result<(), NetworkManagerError> {
        // The version is optimistic-concurrency metadata. Read it immediately
        // before every write: a persisted pre-Karst version is necessarily
        // stale after the initial Reapply.
        let (_, version): (Settings, u64) = self.proxy()?.call("GetAppliedConnection", &0u32)?;
        self.proxy()?
            .call::<_, _, ()>("Reapply", &(settings, version, 1u32))?;
        Ok(())
    }

    fn persist(&self, settings: &Settings) -> Result<(), NetworkManagerError> {
        let bytes = zbus::zvariant::to_bytes(
            Context::new_dbus(LE, 0),
            &(self.device.as_str().to_owned(), settings),
        )?;
        write_atomic(&self.state_path, bytes.bytes())?;
        Ok(())
    }

    fn proxy(&self) -> Result<Proxy<'_>, NetworkManagerError> {
        Ok(Proxy::new(
            &self.connection,
            DESTINATION,
            self.device.clone(),
            DEVICE_INTERFACE,
        )?)
    }
}

fn load_state(path: &Path) -> Result<Option<(String, Settings)>, NetworkManagerError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let data = Data::new(bytes, Context::new_dbus(LE, 0));
    let (snapshot, used): ((String, Settings), usize) = data.deserialize()?;
    if used != data.len() {
        return Err(
            zbus::zvariant::Error::Message("trailing NetworkManager DNS state".into()).into(),
        );
    }
    Ok(Some(snapshot))
}

fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("DNS state has no parent"))?;
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("DNS state has no name"))?;
    let temporary = parent.join(format!(".{}.karst-new", name.to_string_lossy()));
    fs::write(&temporary, data)?;
    fs::rename(temporary, path)
}

fn remove_state(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn configure(
    settings: &mut Settings,
    stub: SocketAddr,
    zone: &str,
    search_domains: &[String],
) -> Result<(), NetworkManagerError> {
    let ipv4 = settings
        .get_mut("ipv4")
        .ok_or(NetworkManagerError::MissingIpv4)?;
    let mut domains = Vec::with_capacity(search_domains.len() + 1);
    domains.push(format!("~{}", zone.trim_end_matches('.')));
    domains.extend(
        search_domains
            .iter()
            .map(|domain| domain.trim_end_matches('.').to_owned()),
    );
    // dns-data is the modern string form (rather than the deprecated packed
    // numeric ipv4.dns property); this also refuses an accidental port.
    ipv4.insert("dns-data".to_owned(), owned(vec![stub.ip().to_string()])?);
    ipv4.insert("dns-search".to_owned(), owned(domains)?);
    ipv4.insert("dns-priority".to_owned(), OwnedValue::from(-50i32));
    Ok(())
}

fn matches_expected(settings: &Settings, stub: &str, route: &str) -> bool {
    let Some(ipv4) = settings.get("ipv4") else {
        return false;
    };
    let dns = ipv4
        .get("dns-data")
        .cloned()
        .and_then(|value| Vec::<String>::try_from(value).ok());
    let domains = ipv4
        .get("dns-search")
        .cloned()
        .and_then(|value| Vec::<String>::try_from(value).ok());
    matches!(dns, Some(values) if values == [stub])
        && matches!(domains, Some(values) if values.iter().any(|value| value == route))
}

fn owned<T>(value: T) -> Result<OwnedValue, zbus::zvariant::Error>
where
    T: zbus::zvariant::Type + Into<Value<'static>>,
{
    OwnedValue::try_from(Value::new(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    const SIGKILL_CHILD: &str =
        "host::networkmanager::tests::networkmanager_apply_and_wait_for_sigkill";

    #[test]
    #[ignore = "helper for the real NetworkManager SIGKILL recovery test"]
    fn networkmanager_apply_and_wait_for_sigkill() {
        if std::env::var_os("KARST_DNS_NM_SIGKILL_CHILD").is_none() {
            return;
        }
        let interface =
            std::env::var("KARST_DNS_HOST_TEST_INTERFACE").expect("test interface requested");
        let mut network_manager =
            NetworkManager::connect(&interface).expect("connect NetworkManager");
        network_manager
            .apply(
                "100.100.100.100:53".parse().expect("stub"),
                "karst-test.invalid.",
                &[],
            )
            .expect("apply temporary DNS");
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    #[test]
    fn configures_a_routing_only_mesh_domain_without_a_default_route() {
        let mut settings = HashMap::from([(String::from("ipv4"), HashMap::new())]);
        configure(
            &mut settings,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100)), 53),
            "aquifer.karst.",
            &["corp.example".to_owned()],
        )
        .expect("settings");
        let ipv4 = settings.get("ipv4").expect("ipv4");
        assert_eq!(
            Vec::<String>::try_from(ipv4.get("dns-data").expect("dns-data").clone())
                .expect("dns data"),
            vec!["100.100.100.100"]
        );
        assert_eq!(
            Vec::<String>::try_from(ipv4.get("dns-search").expect("dns search").clone())
                .expect("dns search"),
            vec!["~aquifer.karst", "corp.example"]
        );
    }

    #[test]
    fn durable_snapshot_round_trips_without_a_live_dbus() {
        let root = std::env::temp_dir().join(format!("karst-nm-state-{}", std::process::id()));
        let state = root.join("revert");
        let settings: Settings = HashMap::from([(String::from("ipv4"), HashMap::new())]);
        let bytes = zbus::zvariant::to_bytes(
            Context::new_dbus(LE, 0),
            &(
                String::from("/org/freedesktop/NetworkManager/Devices/9"),
                &settings,
            ),
        )
        .expect("serialize snapshot");
        write_atomic(&state, bytes.bytes()).expect("persist snapshot");
        assert_eq!(
            load_state(&state).expect("load snapshot"),
            Some((
                String::from("/org/freedesktop/NetworkManager/Devices/9"),
                settings
            ))
        );
        remove_state(&state).expect("remove snapshot");
        assert_eq!(load_state(&state).expect("missing state"), None);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn observes_the_route_only_settings_it_applied() {
        let mut settings = HashMap::from([(String::from("ipv4"), HashMap::new())]);
        configure(
            &mut settings,
            "100.100.100.100:53".parse().expect("stub"),
            "aquifer.karst",
            &[],
        )
        .expect("settings");
        assert!(matches_expected(
            &settings,
            "100.100.100.100",
            "~aquifer.karst"
        ));
        assert!(!matches_expected(&settings, "192.0.2.1", "~aquifer.karst"));
    }

    #[test]
    #[ignore = "requires a disposable NM-managed interface named by KARST_DNS_HOST_TEST_INTERFACE"]
    fn applies_observes_and_reverts_a_real_networkmanager_connection() {
        let interface =
            std::env::var("KARST_DNS_HOST_TEST_INTERFACE").expect("test interface requested");
        let mut network_manager =
            NetworkManager::connect(&interface).expect("connect NetworkManager");
        network_manager
            .apply(
                "100.100.100.100:53".parse().expect("stub"),
                "karst-test.invalid.",
                &["search.karst-test.invalid".to_owned()],
            )
            .expect("apply temporary DNS");
        assert!(network_manager.observe().expect("observe applied DNS"));
        network_manager.revert().expect("revert temporary DNS");
        assert!(!network_manager.observe().expect("observe reverted DNS"),);

        let mut child =
            std::process::Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact", SIGKILL_CHILD, "--ignored"])
                .env("KARST_DNS_NM_SIGKILL_CHILD", "1")
                .env("KARST_DNS_HOST_TEST_INTERFACE", &interface)
                .spawn()
                .expect("spawn NM helper");
        let state = std::path::Path::new(REVERT_PATH);
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !state.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(state.exists(), "helper did not persist NM recovery state");
        child.kill().expect("SIGKILL NM helper");
        assert!(!child.wait().expect("wait for helper").success());

        // `connect` recovers an interrupted generation before returning a
        // handle that could apply another one.
        let recovered = NetworkManager::connect(&interface).expect("recover NetworkManager");
        assert!(!recovered.observe().expect("observe recovered DNS"));
        assert!(!state.exists(), "recovery state survives restart");
    }
}
