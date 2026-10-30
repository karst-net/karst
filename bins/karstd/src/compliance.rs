// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Fresh, self-reported version observations, and the permit-snapshot client
//! side (spec/device-compliance-v1.md's "proposed authorization and
//! enforcement contract"). This module makes no compliance verdict itself
//! and collects no disk, screen-lock, management or endpoint-security data;
//! [`PermitSnapshot`](karst_control_client::compliance::PermitSnapshot) is
//! the reference verdict evaluator, consulted by [`crate::engine`].
use karst_control_client::compliance::PermitContext;
use karst_control_client::transport::pb::{
    karst_compliance_observation::Status, KarstComplianceObservation as Observation,
    KarstComplianceReport,
};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime};

/// Poll/report every 30 seconds on supporting servers, leaving headroom below
/// the 60-second reporting target. Only live capability advertisements count.
pub const REPORT_INTERVAL: Duration = Duration::from_secs(30);
/// Entire challenge/collect/submit round; a timed-out stream must be discarded.
pub const REPORT_TIMEOUT: Duration = Duration::from_secs(5);
/// Refresh a permit every 30 seconds (spec's own target), independent of
/// `REPORT_INTERVAL` even though the two happen to share a value today --
/// a future change to one must not accidentally couple to the other.
pub const PERMIT_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
/// Entire request/accept round; a timed-out stream must be discarded, the
/// same reasoning `REPORT_TIMEOUT` documents.
pub const PERMIT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const COLLECTION_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(any(target_os = "linux", test))]
const MAX_OS_RELEASE: u64 = 16 * 1024;

pub(crate) fn report_due(last: Option<Instant>, now: Instant) -> bool {
    due(last, now, REPORT_INTERVAL)
}

pub(crate) fn permit_due(last: Option<Instant>, now: Instant) -> bool {
    due(last, now, PERMIT_REFRESH_INTERVAL)
}

fn due(last: Option<Instant>, now: Instant, interval: Duration) -> bool {
    last.is_none_or(|last| now.saturating_duration_since(last) >= interval)
}

/// A nonempty `compliance_permit_schema == 1` trust context, or `None` if
/// the server omitted any field -- schema `1` with a missing field is a
/// server bug, not a reason to construct and later fail on a
/// [`PendingPermitRequest`](karst_control_client::compliance::PendingPermitRequest)
/// that was never going to validate. The real security check is still
/// `PendingPermitRequest::new`'s own `valid_id`/`valid_handle`; this is only
/// a cheap, correct filter so an obviously-unusable advertisement does not
/// get treated as "permits are live" for cadence-gating purposes.
pub(crate) fn permit_context(
    tenant_id: String,
    device_id: String,
    handle: String,
    policy_revision: String,
) -> Option<PermitContext> {
    if tenant_id.is_empty()
        || device_id.is_empty()
        || handle.is_empty()
        || policy_revision.is_empty()
    {
        return None;
    }
    Some(PermitContext {
        tenant_id,
        device_id,
        handle,
        policy_revision,
    })
}

/// One process-wide, suspend-aware elapsed-time origin, shared by every
/// caller of [`elapsed_now`] -- the control loop (requesting/accepting
/// permits) and the datapath (evaluating them) must read the same clock, or
/// a snapshot's request-relative deadlines mean different things to each.
static ORIGIN: OnceLock<(Instant, SystemTime)> = OnceLock::new();

/// Elapsed time since this process's first call to this function, immune to
/// a monotonic clock that does not advance across suspend on some platforms
/// (`karst_control_client::compliance`'s own module doc: "`Instant` is not a
/// portable substitute"). Takes both a monotonic and a wall-clock reading and
/// keeps whichever shows more elapsed time -- the same "larger gap wins"
/// idiom [`crate::wake::Detector`] uses to tell a real suspend from an
/// ordinary clock adjustment, applied here to a duration instead of a gap.
/// A wall-clock-only *rollback* cannot move this backward, since the
/// monotonic reading never does; `PermitSnapshot`'s own permanent-invalidation
/// rule for a backward sample is a defense against a caller that did not use
/// this function, not a case this one can produce.
pub fn elapsed_now() -> Duration {
    let (origin_instant, origin_wall) = *ORIGIN.get_or_init(|| (Instant::now(), SystemTime::now()));
    let by_monotonic = Instant::now().saturating_duration_since(origin_instant);
    let by_wall = SystemTime::now()
        .duration_since(origin_wall)
        .unwrap_or(Duration::ZERO);
    by_monotonic.max(by_wall)
}

fn observation(status: Status, version: String) -> Observation {
    Observation {
        status: status.into(),
        version,
    }
}
fn error() -> Observation {
    observation(Status::CollectionError, String::new())
}
#[cfg(any(test, not(any(target_os = "macos", target_os = "windows"))))]
fn unsupported() -> Observation {
    observation(Status::Unsupported, String::new())
}

/// Collect only after receiving a fresh challenge. Never reuse observations
/// from another attempt; a collection error is itself submitted to the server.
pub async fn collect(challenge: Vec<u8>) -> KarstComplianceReport {
    let (platform, distribution, os_version) = native_os().await;
    KarstComplianceReport {
        challenge,
        collector_version: crate::VERSION.to_owned(),
        platform,
        distribution,
        client_version: Some(observation(Status::Collected, crate::VERSION.to_owned())),
        os_version: Some(os_version),
    }
}

#[cfg(target_os = "linux")]
async fn native_os() -> (String, String, Observation) {
    let collected = tokio::task::spawn_blocking(|| linux_os(read_os_release()));
    let (distribution, version) = match tokio::time::timeout(COLLECTION_TIMEOUT, collected).await {
        Ok(Ok(result)) => result,
        _ => (String::new(), error()),
    };
    ("linux".into(), distribution, version)
}

#[cfg(target_os = "macos")]
async fn native_os() -> (String, String, Observation) {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt as _;
    // Absolute executable and no shell. Disable Apple's legacy version
    // compatibility mode; an inherited environment must not report 10.16.
    let collect = async {
        let mut child = tokio::process::Command::new("/usr/bin/sw_vers")
            .arg("-productVersion")
            .env_clear()
            .env("SYSTEM_VERSION_COMPAT", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .ok()?;
        let stdout = child.stdout.take()?;
        let mut bytes = Vec::new();
        stdout.take(129).read_to_end(&mut bytes).await.ok()?;
        if bytes.len() > 128 {
            return None;
        }
        if !child.wait().await.ok()?.success() {
            return None;
        }
        product_version(&bytes, 2, 3)
    };
    let version = match tokio::time::timeout(COLLECTION_TIMEOUT, collect).await {
        Ok(Some(version)) => observation(Status::Collected, version),
        _ => error(),
    };
    ("darwin".into(), String::new(), version)
}

#[cfg(target_os = "windows")]
async fn native_os() -> (String, String, Observation) {
    // Microsoft's safe wrapper uses RtlGetVersion rather than the
    // application-manifest-dependent GetVersionEx API. Build only, no UBR.
    let collected = tokio::task::spawn_blocking(|| {
        let version = windows_version::OsVersion::current();
        if version.major == 0 || version.build == 0 {
            error()
        } else {
            observation(
                Status::Collected,
                format!("{}.{}.{}", version.major, version.minor, version.build),
            )
        }
    });
    let observed = match tokio::time::timeout(COLLECTION_TIMEOUT, collected).await {
        Ok(Ok(observed)) => observed,
        _ => error(),
    };
    ("windows".into(), String::new(), observed)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[allow(clippy::unused_async)] // Uniform collector interface; unsupported platforms perform no OS I/O.
async fn native_os() -> (String, String, Observation) {
    (std::env::consts::OS.into(), String::new(), unsupported())
}

#[cfg(target_os = "linux")]
fn read_os_release() -> std::io::Result<Vec<u8>> {
    read_os_release_with(|path| {
        use std::io::Read as _;
        let file = std::fs::File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::other("not a regular file"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_OS_RELEASE + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_OS_RELEASE {
            return Err(std::io::Error::other("os-release too large"));
        }
        Ok(bytes)
    })
}

#[cfg(any(target_os = "linux", test))]
fn read_os_release_with(
    mut read: impl FnMut(&str) -> std::io::Result<Vec<u8>>,
) -> std::io::Result<Vec<u8>> {
    match read("/etc/os-release") {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => read("/usr/lib/os-release"),
        result => result,
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_os(bytes: std::io::Result<Vec<u8>>) -> (String, Observation) {
    let Ok(bytes) = bytes else {
        return (String::new(), error());
    };
    let Ok((distribution, version)) = linux_release(&bytes) else {
        return (String::new(), error());
    };
    if distribution != "ubuntu" && distribution != "debian" {
        return (distribution, unsupported());
    }
    let Some(version) = version else {
        return (distribution, observation(Status::Missing, String::new()));
    };
    let (min, max) = if distribution == "ubuntu" {
        (2, 2)
    } else {
        (1, 2)
    };
    let Some(version) = product_version(version.as_bytes(), min, max) else {
        return (distribution, error());
    };
    (distribution, observation(Status::Collected, version))
}

// Only ID and VERSION_ID are consumed. Never execute or expand os-release as
// shell code; ID_LIKE is not evidence of a supported distribution's release.
#[cfg(any(target_os = "linux", test))]
fn linux_release(bytes: &[u8]) -> Result<(String, Option<String>), ()> {
    if bytes.len() as u64 > MAX_OS_RELEASE {
        return Err(());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ())?;
    let mut id = None;
    let mut version = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key != "ID" && key != "VERSION_ID" {
            continue;
        }
        let value = if value.starts_with('"') && value.ends_with('"')
            || value.starts_with('\'') && value.ends_with('\'')
        {
            value.get(1..value.len().saturating_sub(1)).ok_or(())?
        } else {
            value
        };
        // These fields only need simple product identifiers and release
        // components. Escapes, expansion and concatenated quotes fail closed.
        if value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(());
        }
        if key == "ID" {
            if value.is_empty() || value.len() > 64 || value.bytes().any(|b| b.is_ascii_uppercase())
            {
                return Err(());
            }
            id = Some(value.to_owned());
        } else {
            version = Some(value.to_owned());
        }
    }
    Ok((id.ok_or(())?, version.filter(|v| !v.is_empty())))
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn product_version(bytes: &[u8], min: usize, max: usize) -> Option<String> {
    let value = std::str::from_utf8(bytes).ok()?.trim();
    if value.is_empty() || value.len() > 128 {
        return None;
    }
    let parts: Vec<_> = value.split('.').collect();
    if !(min..=max).contains(&parts.len()) {
        return None;
    }
    for p in parts {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.parse::<u32>().is_err() {
            return None;
        }
    }
    Some(value.to_owned())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn reporting_cadence_has_exact_boundaries() {
        let now = std::time::Instant::now();
        assert!(report_due(None, now));
        assert!(!report_due(Some(now), now));
        assert!(!report_due(
            Some(now),
            now + REPORT_INTERVAL
                .checked_sub(Duration::from_nanos(1))
                .expect("positive reporting interval")
        ));
        assert!(report_due(Some(now), now + REPORT_INTERVAL));
    }

    #[test]
    fn linux_release_parses_only_typed_fields_without_execution() {
        let (id, version) = linux_os(Ok(
            b"NAME=arbitrary ignored\nID=ubuntu\nVERSION_ID=\"24.04\"\n".to_vec(),
        ));
        assert_eq!(id, "ubuntu");
        assert_eq!(version.status, i32::from(Status::Collected));
        assert_eq!(version.version, "24.04");
        let (_, version) = linux_os(Ok(b"ID='debian'\nVERSION_ID='12'\n".to_vec()));
        assert_eq!(version.version, "12");
        let (id, version) = linux_os(Ok(b"ID=mint\nID_LIKE=ubuntu\nVERSION_ID=22\n".to_vec()));
        assert_eq!(id, "mint");
        assert_eq!(version.status, i32::from(Status::Unsupported));
        assert!(version.version.is_empty());
        let (_, version) = linux_os(Ok(b"ID=ubuntu\nVERSION_ID=\"\"\n".to_vec()));
        assert_eq!(version.status, i32::from(Status::Missing));
        for text in [
            "ID=ubuntu\nVERSION_ID=$(echo 24.04)",
            "ID=ubuntu\nVERSION_ID=\"24.04\"\"1\"",
            "ID=ubuntu\nVERSION_ID=6.8.0",
            "ID=ubuntu\nVERSION_ID=24.04beta",
            "ID=UBUNTU\nVERSION_ID=24.04",
            "VERSION_ID=24.04",
        ] {
            let (_, version) = linux_os(Ok(text.as_bytes().to_vec()));
            assert_eq!(version.status, i32::from(Status::CollectionError), "{text}");
            assert!(version.version.is_empty());
        }
        assert!(linux_release(&vec![b'x'; 16 * 1024 + 1]).is_err());
        assert!(linux_release(&[0xff]).is_err());
    }

    #[test]
    fn linux_fallback_is_only_for_a_missing_etc_file() {
        let mut paths = Vec::new();
        let _ = read_os_release_with(|p| {
            paths.push(p.to_owned());
            Err(std::io::ErrorKind::PermissionDenied.into())
        });
        assert_eq!(paths, ["/etc/os-release"]);
        paths.clear();
        let _ = read_os_release_with(|p| {
            paths.push(p.to_owned());
            Err(std::io::ErrorKind::NotFound.into())
        });
        assert_eq!(paths, ["/etc/os-release", "/usr/lib/os-release"]);
    }

    #[test]
    fn product_releases_are_bounded_numeric_values() {
        assert_eq!(
            product_version(b"15.10.1\n", 2, 3).as_deref(),
            Some("15.10.1")
        );
        for value in [
            "Darwin 24.0.0",
            "15..1",
            "15.1;echo hi",
            "15.4294967296",
            "15",
        ] {
            assert!(product_version(value.as_bytes(), 2, 3).is_none());
        }
    }

    #[test]
    fn live_native_collection_reports_typed_observations() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let report = runtime.block_on(collect(vec![7; 32]));
        assert_eq!(report.challenge, vec![7; 32]);
        assert_eq!(report.collector_version, crate::VERSION);
        assert_eq!(
            report.client_version.expect("client version").version,
            crate::VERSION
        );
        let observed = report.os_version.expect("OS version");
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            assert_eq!(observed.status, i32::from(Status::Collected));
            assert!(!observed.version.is_empty());
        }
        #[cfg(target_os = "linux")]
        {
            assert!(
                [i32::from(Status::Collected), i32::from(Status::Unsupported)]
                    .contains(&observed.status)
            );
        }
    }

    #[test]
    fn permit_cadence_has_exact_boundaries_independent_of_report_cadence() {
        let now = Instant::now();
        assert!(permit_due(None, now));
        assert!(!permit_due(Some(now), now));
        assert!(!permit_due(
            Some(now),
            now + PERMIT_REFRESH_INTERVAL
                .checked_sub(Duration::from_nanos(1))
                .expect("positive refresh interval")
        ));
        assert!(permit_due(Some(now), now + PERMIT_REFRESH_INTERVAL));
    }

    #[test]
    fn a_permit_context_needs_every_field_nonempty() {
        let full = |t: &str, d: &str, h: &str, r: &str| {
            permit_context(t.into(), d.into(), h.into(), r.into())
        };
        assert!(full("t", "d", "h", "r").is_some());
        assert!(full("", "d", "h", "r").is_none());
        assert!(full("t", "", "h", "r").is_none());
        assert!(full("t", "d", "", "r").is_none());
        assert!(full("t", "d", "h", "").is_none());
    }

    #[test]
    fn elapsed_now_is_monotonic_and_shared_across_calls() {
        let a = elapsed_now();
        let b = elapsed_now();
        assert!(b >= a);
    }
}
