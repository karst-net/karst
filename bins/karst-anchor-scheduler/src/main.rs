// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! `karst-anchor-scheduler` — ADR-0045 §4d (issue #352): toggles EC2 power
//! state (Start/Stop) on a configurable duty-cycle schedule for a small
//! set of pre-provisioned, pre-enrolled "ephemeral anchor" instances in
//! specific AWS Local Zones — never a relay pool, never a `karst-relay`.
//!
//! Not a `karst-scaler-aws` addition and not a `karst_scaler_driver::Driver`
//! implementation: that trait's shape (pool-scoped `create`/`drain`/
//! `destroy` with node-count reconciliation) has no slot for "toggle power
//! on a fixed, never-destroyed, never-pooled instance." This is the first
//! standalone AWS-talking binary in this workspace — see `scheduler.rs`'s
//! own module doc for why that is the smaller, more honest unit here.
//!
//! Usage: `karst-anchor-scheduler SCHEDULER_CONFIG.toml`

mod config;
mod fetch;
mod scheduler;
mod window;

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, config_path] = args.as_slice() else {
        eprintln!("usage: karst-anchor-scheduler SCHEDULER_CONFIG.toml");
        return ExitCode::FAILURE;
    };

    match run(config_path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("karst-anchor-scheduler: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(config_path: &str) -> Result<(), String> {
    // ureq's TLS backend is built with no crypto provider of its own --
    // it needs one installed process-wide before the first HTTPS request.
    // aws-lc-rs is the one every other crate in this workspace already
    // uses -- matches bins/karst-scaler/src/main.rs's own identical call.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cfg = config::SchedulerConfig::load(Path::new(config_path))
        .map_err(|e| format!("reading {config_path}: {e}"))?;
    let pat = std::fs::read_to_string(&cfg.pat_file)
        .map_err(|e| format!("reading {}: {e}", cfg.pat_file))?
        .trim()
        .to_owned();
    let endpoint = fetch::Endpoint {
        control_api_base: cfg.control_api_base.trim_end_matches('/').to_owned(),
        pat,
    };
    let agent = fetch::build_agent()?;

    scheduler::run(&cfg, &endpoint, &agent);
    Ok(())
}
