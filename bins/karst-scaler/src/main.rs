// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! `karst-scaler simulate COST_MODEL.toml USAGE_LOG` — ADR-0045 §7 Phase 0.
//! `karst-scaler advise ...` — §7 Phase 1; see [`advise_loop`]'s own module
//! doc. `karst-scaler drive ...` — §7 Phase 2's first PR (the driver trait
//! and a no-op implementation); see [`drive_loop`]'s own module doc.
//!
//! ```text
//! karst-scaler simulate COST_MODEL.toml USAGE_LOG
//!     replay recorded usage against a cost model; print spend per pool,
//!     per meter, per edge, and a grand total
//! karst-scaler spot-report COST_MODEL.toml USAGE_LOG
//!     ADR-0045 Open Question #4 (issue #339): for every pool with a
//!     [pools.*.spot] model, estimate headroom, on-demand vs. spot cost,
//!     and expected forced re-homes; see `simulate::evaluate_spot`'s own
//!     module doc
//! karst-scaler check COST_MODEL.toml
//!     parse and validate a cost-model file without simulating anything
//! karst-scaler advise ADVISE_CONFIG.toml
//!     poll the control server's demand endpoints on an interval and log a
//!     node-count recommendation per pool, forever; see `advise_config`'s
//!     own module doc for the config file's shape
//! karst-scaler drive ADVISE_CONFIG.toml
//!     the same recommendation loop as advise, reconciled against a driver
//!     instead of only printed; see `driver`'s own module doc
//! ```
//!
//! # Why this phase first
//!
//! ADR-0045 §7 phases this deliberately: Phase 0 is the schema and this
//! replay tool, with no actuation and no credentials, and it is "the
//! empirical basis for deciding whether Phase 2 is worth its attack
//! surface." An operator who writes a cost model, points it at a usage log
//! they already have (from their own Prometheus export, a provider billing
//! export, or a hand-reconciled file — ADR-0045 §2's first precedence-order
//! item, "operator-supplied... authoritative"), and gets back a number
//! close to their actual bill has validated the model before anything in
//! this codebase is trusted to spend money against it.
//!
//! # Why this binary has almost no dependencies
//!
//! `serde` and `toml` to read the one input format this needs, and nothing
//! else — no network stack, no cloud SDK, no CLI-argument-parsing crate.
//! That is itself part of ADR-0045 §6's posture carried backward: a
//! planner-adjacent tool earns a larger dependency footprint only in the
//! phase that actually needs one.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use karst_scaler::cost_model::Document;
use karst_scaler::{simulate, usage};

mod advise_config;
mod advise_loop;
mod allocate_config;
mod allocate_loop;
mod drive_loop;
mod metrics_http;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();

    let result = match refs.as_slice() {
        ["simulate", cost_model, usage_log] => run_simulate(cost_model, usage_log),
        ["spot-report", cost_model, usage_log] => run_spot_report(cost_model, usage_log),
        ["check", cost_model] => run_check(cost_model),
        ["advise", advise_config] => run_advise(advise_config),
        ["drive", advise_config] => run_drive(advise_config),
        ["allocate", allocate_config] => run_allocate(allocate_config),
        _ => {
            usage_text();
            return ExitCode::FAILURE;
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("karst-scaler: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage_text() {
    eprintln!(
        "karst-scaler — ADR-0045 Phase 0/1/2: cost model, offline simulator, Advisor, and driver

  simulate COST_MODEL.toml USAGE_LOG
                              replay recorded usage against a cost model;
                              print spend per pool, per meter, per edge
  spot-report COST_MODEL.toml USAGE_LOG
                              ADR-0045 Open Question #4 (issue #339): for
                              every pool with a [pools.*.spot] model,
                              estimate headroom, on-demand vs. spot cost,
                              and expected forced re-homes
  check COST_MODEL.toml       parse and validate a cost-model file only
  advise ADVISE_CONFIG.toml  poll the control server's demand endpoints on
                              an interval; log a node-count recommendation
                              per pool, forever; optionally serve /metrics
                              and /recommendations (see advise_config)
  drive ADVISE_CONFIG.toml   same recommendation loop as advise, but
                              reconciles each pool's actual instance count
                              against it through a driver (ADR-0045 §7
                              Phase 2), bounded by a budget/node-count
                              circuit breaker and an independent region
                              check (see breaker.rs); requires a [breaker]
                              section in ADVISE_CONFIG.toml. Today the
                              underlying driver is always the no-op one
                              -- see driver.rs
  allocate ALLOCATE_CONFIG.toml
                              ADR-0063/#455: polls the control server for
                              pending admin-triggered relay allocations
                              and drives each one through requested ->
                              provisioning -> granting -> ready, or ->
                              revoking -> deprovisioning ->
                              deprovisioned on teardown, forever. Not a
                              pool: see allocate_loop's own module doc
                              for why this is a sibling to drive, not a
                              mode of it. v1 is AWS-only (driver.kind =
                              \"aws\")."
    );
}

fn run_advise(advise_config_path: &str) -> Result<(), String> {
    let (config, _breaker, _driver) = load_drive_config(advise_config_path)?;
    advise_loop::run(&config)
}

fn run_drive(advise_config_path: &str) -> Result<(), String> {
    let (config, breaker, driver_section) = load_drive_config(advise_config_path)?;
    // ADR-0045 §6: no "unlimited" default. A `drive` config with no
    // [breaker] section is refused here, before anything is actuated,
    // rather than falling back to the bare no-op driver with no ceiling
    // at all.
    let breaker = breaker.ok_or_else(|| {
        format!(
            "{advise_config_path}: drive requires a [breaker] section (limits_path, \
             state_path) -- ADR-0045 §6 allows no \"unlimited\" default"
        )
    })?;

    let inner: Box<dyn karst_scaler::driver::Driver> =
        match driver_section.as_ref().map_or("noop", |d| d.kind.as_str()) {
            "noop" => Box::new(karst_scaler::driver::NoopDriver::new()),
            "k8s" => {
                // The match above only reaches this arm when `driver_section`
                // produced `"k8s"` via `.map_or(..., |d| d.kind.as_str())`,
                // which cannot happen for `None` -- so this is always `Some`.
                let section = driver_section.as_ref().unwrap_or_else(|| unreachable!());
                build_k8s_driver(section, &config.control_api_base)?
            }
            "aws" => {
                let section = driver_section.as_ref().unwrap_or_else(|| unreachable!());
                build_aws_driver(section, &config.control_api_base)?
            }
            other => {
                return Err(format!(
                    "{advise_config_path}: unknown driver.kind {other:?} (expected \"noop\", \
                     \"k8s\", or \"aws\")"
                ))
            }
        };

    let mut driver = karst_scaler::breaker::BoundedDriver::new(
        inner,
        Path::new(&config.cost_model_path),
        Path::new(&breaker.limits_path),
        Path::new(&breaker.state_path),
    )
    .map_err(|e| e.to_string())?;
    drive_loop::run(&config, &mut driver)
}

/// ADR-0063/#455: AWS only in v1 -- `karst-scaler-k8s` provisions cluster
/// workloads, not a single named host with its own address/TLS identity
/// the way `AwsDriver` does, and the LXD connection type (#430) has no
/// provisioning driver at all yet. Both are plausible later targets, not
/// v1 (ADR-0063's own "Negative" consequences).
fn run_allocate(allocate_config_path: &str) -> Result<(), String> {
    // Same reasoning as `load_drive_config`'s own identical line: ureq's
    // TLS backend needs a crypto provider installed process-wide before
    // the first HTTPS request.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cfg = allocate_config::AllocateConfig::load(Path::new(allocate_config_path))
        .map_err(|e| format!("reading {allocate_config_path}: {e}"))?;
    let pat = std::fs::read_to_string(&cfg.pat_file)
        .map_err(|e| format!("reading {}: {e}", cfg.pat_file))?
        .trim()
        .to_owned();
    let control_api_base = cfg.control_api_base.trim_end_matches('/').to_owned();

    if cfg.driver.kind != "aws" {
        return Err(format!(
            "{allocate_config_path}: driver.kind = {:?} is not supported by allocate yet \
             (v1 is AWS-only -- ADR-0063)",
            cfg.driver.kind
        ));
    }
    let mut driver = build_aws_driver(&cfg.driver, &control_api_base)?;

    let config = allocate_loop::Config {
        control_api_base,
        pat,
        poll_interval: Duration::from_secs(cfg.poll_interval_secs),
    };
    allocate_loop::run(&config, driver.as_mut())
}

#[cfg(feature = "k8s")]
fn build_k8s_driver(
    section: &advise_config::DriverSection,
    control_api_base: &str,
) -> Result<Box<dyn karst_scaler::driver::Driver>, String> {
    let namespace = section
        .namespace
        .clone()
        .ok_or_else(|| "driver.kind = \"k8s\" needs driver.namespace".to_owned())?;
    let enroll_pat_file = section
        .enroll_pat_file
        .clone()
        .ok_or_else(|| "driver.kind = \"k8s\" needs driver.enroll_pat_file".to_owned())?;
    let enroll_pat = std::fs::read_to_string(&enroll_pat_file)
        .map_err(|e| format!("reading {enroll_pat_file}: {e}"))?
        .trim()
        .to_owned();
    let driver = karst_scaler_k8s::K8sDriver::new(karst_scaler_k8s::K8sDriverConfig {
        namespace,
        control_api_base: control_api_base.to_owned(),
        enroll_pat,
    })
    .map_err(|e| e.to_string())?;
    Ok(Box::new(driver))
}

#[cfg(not(feature = "k8s"))]
fn build_k8s_driver(
    _section: &advise_config::DriverSection,
    _control_api_base: &str,
) -> Result<Box<dyn karst_scaler::driver::Driver>, String> {
    Err(
        "this build of karst-scaler was not compiled with k8s driver support -- \
         rebuild with --features k8s"
            .to_owned(),
    )
}

#[cfg(feature = "aws")]
fn build_aws_driver(
    section: &advise_config::DriverSection,
    control_api_base: &str,
) -> Result<Box<dyn karst_scaler::driver::Driver>, String> {
    let region = section
        .region
        .clone()
        .ok_or_else(|| "driver.kind = \"aws\" needs driver.region".to_owned())?;
    let ami_id = section
        .ami_id
        .clone()
        .ok_or_else(|| "driver.kind = \"aws\" needs driver.ami_id".to_owned())?;
    let instance_type = section
        .instance_type
        .clone()
        .ok_or_else(|| "driver.kind = \"aws\" needs driver.instance_type".to_owned())?;
    let subnet_id = section
        .subnet_id
        .clone()
        .ok_or_else(|| "driver.kind = \"aws\" needs driver.subnet_id".to_owned())?;
    if section.security_group_ids.is_empty() {
        return Err(
            "driver.kind = \"aws\" needs at least one driver.security_group_ids entry".to_owned(),
        );
    }
    let enroll_pat_file = section
        .enroll_pat_file
        .clone()
        .ok_or_else(|| "driver.kind = \"aws\" needs driver.enroll_pat_file".to_owned())?;
    let enroll_pat = std::fs::read_to_string(&enroll_pat_file)
        .map_err(|e| format!("reading {enroll_pat_file}: {e}"))?
        .trim()
        .to_owned();
    let driver = karst_scaler_aws::AwsDriver::new(karst_scaler_aws::AwsDriverConfig {
        region,
        ami_id,
        instance_type,
        subnet_id,
        security_group_ids: section.security_group_ids.clone(),
        control_api_base: control_api_base.to_owned(),
        enroll_pat,
    })
    .map_err(|e| e.to_string())?;
    Ok(Box::new(driver))
}

#[cfg(not(feature = "aws"))]
fn build_aws_driver(
    _section: &advise_config::DriverSection,
    _control_api_base: &str,
) -> Result<Box<dyn karst_scaler::driver::Driver>, String> {
    Err(
        "this build of karst-scaler was not compiled with aws driver support -- \
         rebuild with --features aws"
            .to_owned(),
    )
}

fn load_drive_config(
    advise_config_path: &str,
) -> Result<
    (
        advise_loop::Config,
        Option<advise_config::BreakerSection>,
        Option<advise_config::DriverSection>,
    ),
    String,
> {
    // ureq's TLS backend is built with no crypto provider of its own (see
    // Cargo.toml's comment on why) -- it needs one installed process-wide
    // before the first HTTPS request. aws-lc-rs is the one every other
    // crate in this workspace already uses; the `Err` case is only "already
    // installed," which cannot happen this early and would be harmless if
    // it somehow did.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cfg = advise_config::AdviseConfig::load(Path::new(advise_config_path))
        .map_err(|e| format!("reading {advise_config_path}: {e}"))?;
    let pat = std::fs::read_to_string(&cfg.pat_file)
        .map_err(|e| format!("reading {}: {e}", cfg.pat_file))?
        .trim()
        .to_owned();
    let config = advise_loop::Config {
        cost_model_path: cfg.cost_model_path,
        control_api_base: cfg.control_api_base.trim_end_matches('/').to_owned(),
        pat,
        poll_interval: Duration::from_secs(cfg.poll_interval_secs),
        metrics_listen: cfg.metrics.listen,
    };
    Ok((config, cfg.breaker, cfg.driver))
}

fn run_check(cost_model_path: &str) -> Result<(), String> {
    let doc = load_cost_model(cost_model_path)?;
    println!("{cost_model_path}: valid, {} pool(s)", doc.pools.len());
    Ok(())
}

fn run_simulate(cost_model_path: &str, usage_path: &str) -> Result<(), String> {
    let doc = load_cost_model(cost_model_path)?;
    let records =
        usage::load(Path::new(usage_path)).map_err(|e| format!("reading {usage_path}: {e}"))?;
    let report = simulate::simulate(&doc, &records).map_err(|e| e.to_string())?;
    println!("{report}");
    Ok(())
}

fn run_spot_report(cost_model_path: &str, usage_path: &str) -> Result<(), String> {
    let doc = load_cost_model(cost_model_path)?;
    let records =
        usage::load(Path::new(usage_path)).map_err(|e| format!("reading {usage_path}: {e}"))?;
    let report = simulate::evaluate_spot(&doc, &records).map_err(|e| e.to_string())?;
    println!("{report}");
    Ok(())
}

fn load_cost_model(path: &str) -> Result<Document, String> {
    let doc = Document::load(Path::new(path)).map_err(|e| format!("reading {path}: {e}"))?;
    doc.validate().map_err(|e| e.to_string())?;
    Ok(doc)
}
