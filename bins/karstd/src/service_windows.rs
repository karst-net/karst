// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![cfg(windows)]

//! Service Control Manager integration — plan §5.
//!
//! `karstd.exe` is installed with `ServiceInstall`/`ImagePath` pointing
//! straight at the binary, no `--service` flag: [`try_run`] is what tells the
//! two cases apart. `windows_service::service_dispatcher::start` blocks for
//! the service's entire lifetime when this process really was launched by
//! the SCM, and fails immediately with
//! `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` when it was not (an operator's
//! `karstd.exe -c ...` at a console, or `karstd check`, or a test) — so
//! `main`'s `command_run` calls this first and falls back to the existing
//! foreground path on that one specific failure, unchanged on every other
//! platform.
//!
//! # Why no `SERVICE_CONTROL_POWEREVENT` handler
//!
//! Plan §5 asks for one, to force endpoint rediscovery on resume from
//! suspend — "the same requirement as macOS". [`crate::wake`] already meets
//! that requirement without any platform notification: its module docs lay
//! out why a clock-gap detector on the run loop's own tick beats an `IOKit` or
//! `systemd-logind` callback (a second, harder-to-test mechanism, for a
//! signal the loop can infer from clocks it already reads). Windows'
//! `SERVICE_CONTROL_POWEREVENT` is the same tradeoff a third time, so this
//! module declines it for the same reason and relies on `wake::Detector`
//! exactly as the other two platforms do.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::run::Shutdown;

/// Also the Event Log source name `karst-winlog` registers under.
pub const SERVICE_NAME: &str = "karstd";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// `StartServiceCtrlDispatcherW`'s documented error when the calling process
/// was not started by the SCM. Not one of `windows-sys`'s named constants in
/// any feature this crate already pulls in, and pulling in
/// `Win32_Foundation` just for this one value would be a bigger dependency
/// footprint than asserting the raw code — the same call this codebase made
/// for `ERROR_MOD_NOT_FOUND` in `crates/karst-tun/tests/windows_adapter.rs`.
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

/// What [`try_run`] passes down to [`service_main`] — set once, immediately
/// before dispatch, and read back inside it. `service_main` cannot be a
/// closure (the macro below requires a plain `fn` item), so this is the
/// alternative to re-parsing `std::env::args()` a second time from inside a
/// service context that has no argument-parsing code of its own.
struct StartArgs {
    config: PathBuf,
    socket: PathBuf,
    status_socket: Option<PathBuf>,
}

static START_ARGS: OnceLock<StartArgs> = OnceLock::new();
/// [`run_service`]'s outcome, since `service_dispatcher::start` returning
/// `Ok(())` only means the dispatcher ran the service to completion — not
/// that [`crate::run::run_with_control`] itself succeeded.
static OUTCOME: Mutex<Option<Result<(), String>>> = Mutex::new(None);

define_windows_service!(ffi_service_main, service_main);

/// Try to run `karstd` as a Windows service.
///
/// `Some(result)` means this process *was* dispatched by the SCM and has now
/// run to completion — `main` should exit with `result`. `None` means it was
/// not; the caller should fall back to running in the foreground.
///
/// # Errors
/// Wrapped in `Some`: a control-handler registration failure, or a fatal
/// error from [`crate::run::run_with_control`].
pub fn try_run(
    config_path: &Path,
    socket_path: &Path,
    status_socket_path: Option<&Path>,
) -> Option<Result<(), String>> {
    // `OnceLock::set` failing (already set) cannot happen — `main` calls
    // this at most once — but is not a reason to skip dispatch if it
    // somehow did.
    let _ = START_ARGS.set(StartArgs {
        config: config_path.to_owned(),
        socket: socket_path.to_owned(),
        status_socket: status_socket_path.map(Path::to_owned),
    });
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => Some(
            OUTCOME
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
                .unwrap_or_else(
                    || Err("service dispatcher returned without an outcome".to_owned()),
                ),
        ),
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) =>
        {
            None
        }
        Err(error) => Some(Err(error.to_string())),
    }
}

/// What `karstd`'s service wrapper does about one SCM control code — pulled
/// out of the registered handler closure so it is a plain function real
/// tests can call. (The closure itself cannot be tested directly: it only
/// runs inside a process the SCM started, which a test is not.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    /// Ask the run loop to stop.
    Stop,
    /// Acknowledge without acting — `Interrogate` only asks for the status
    /// already reported.
    Ignore,
    /// Tell the SCM this control is not handled.
    Unhandled,
}

fn classify(control: ServiceControl) -> Action {
    match control {
        ServiceControl::Stop | ServiceControl::Shutdown => Action::Stop,
        ServiceControl::Interrogate => Action::Ignore,
        _ => Action::Unhandled,
    }
}

fn service_main(_arguments: Vec<OsString>) {
    let outcome = run_service();
    if let Err(error) = &outcome {
        // No console exists in a service process — the Event Log is the
        // only place left for a failure this early to go. A second
        // registration if `run_service` already made one is harmless: each
        // is deregistered on drop and the log itself does not care how many
        // sources reported to it.
        if let Ok(source) = karst_winlog::Source::register(SERVICE_NAME) {
            let _ = source.error(&format!("karstd: fatal service error: {error}"));
        }
    }
    *OUTCOME.lock().unwrap_or_else(PoisonError::into_inner) = Some(outcome);
}

fn set_status(
    handle: service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    controls_accepted: ServiceControlAccept,
) -> Result<(), String> {
    handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(|error| error.to_string())
}

fn run_service() -> Result<(), String> {
    let args = START_ARGS
        .get()
        .ok_or("service arguments were not set before dispatch")?;
    let shutdown = Arc::new(Shutdown::default());
    let handler_shutdown = Arc::clone(&shutdown);

    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match classify(control) {
            Action::Stop => {
                handler_shutdown.request();
                ServiceControlHandlerResult::NoError
            }
            Action::Ignore => ServiceControlHandlerResult::NoError,
            Action::Unhandled => ServiceControlHandlerResult::NotImplemented,
        })
        .map_err(|error| error.to_string())?;

    // Config load and interface bring-up can take a moment; a bare jump to
    // `Running` risks the SCM's default start timeout on a slow machine.
    // `StartPending` with no controls accepted yet buys that time honestly
    // instead of lying about being ready.
    set_status(
        status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
    )?;

    let event_log = karst_winlog::Source::register(SERVICE_NAME).ok();
    let log_info = |message: &str| {
        if let Some(log) = &event_log {
            let _ = log.info(message);
        }
    };
    log_info("karstd: service starting");

    let (config, _source, control_client) =
        crate::control::load_config(&args.config).map_err(|error| error.to_string())?;

    set_status(
        status_handle,
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    )?;

    let result = crate::run::run_with_control(
        &Arc::new(config),
        &shutdown,
        &args.socket,
        control_client,
        args.status_socket.as_deref(),
    )
    .map_err(|error| error.to_string());

    if let Err(error) = &result {
        if let Some(log) = &event_log {
            let _ = log.error(&format!("karstd: {error}"));
        }
    }
    log_info("karstd: service stopped");

    set_status(
        status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
    )?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_and_shutdown_both_end_the_service() {
        assert_eq!(classify(ServiceControl::Stop), Action::Stop);
        assert_eq!(classify(ServiceControl::Shutdown), Action::Stop);
    }

    #[test]
    fn interrogate_is_acknowledged_without_acting() {
        assert_eq!(classify(ServiceControl::Interrogate), Action::Ignore);
    }

    /// Includes `PowerEvent` — see the module docs on why this deliberately
    /// does not accept it.
    #[test]
    fn anything_else_is_reported_unhandled() {
        assert_eq!(classify(ServiceControl::Pause), Action::Unhandled);
        assert_eq!(classify(ServiceControl::Continue), Action::Unhandled);
        assert_eq!(
            classify(ServiceControl::PowerEvent(
                windows_service::service::PowerEventParam::ResumeAutomatic
            )),
            Action::Unhandled
        );
    }
}
