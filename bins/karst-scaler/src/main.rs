// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! `karst-scaler simulate COST_MODEL.toml USAGE_LOG` — ADR-0045 §7 Phase 0.
//! `karst-scaler advise ...` — §7 Phase 1; see [`advise_loop`]'s own module
//! doc.
//!
//! ```text
//! karst-scaler simulate COST_MODEL.toml USAGE_LOG
//!     replay recorded usage against a cost model; print spend per pool,
//!     per meter, per edge, and a grand total
//! karst-scaler check COST_MODEL.toml
//!     parse and validate a cost-model file without simulating anything
//! karst-scaler advise ADVISE_CONFIG.toml
//!     poll the control server's demand endpoints on an interval and log a
//!     node-count recommendation per pool, forever; see `advise_config`'s
//!     own module doc for the config file's shape
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
mod metrics_http;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();

    let result = match refs.as_slice() {
        ["simulate", cost_model, usage_log] => run_simulate(cost_model, usage_log),
        ["check", cost_model] => run_check(cost_model),
        ["advise", advise_config] => run_advise(advise_config),
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
        "karst-scaler — ADR-0045 Phase 0/1: cost model, offline simulator, and Advisor

  simulate COST_MODEL.toml USAGE_LOG
                              replay recorded usage against a cost model;
                              print spend per pool, per meter, per edge
  check COST_MODEL.toml       parse and validate a cost-model file only
  advise ADVISE_CONFIG.toml  poll the control server's demand endpoints on
                              an interval; log a node-count recommendation
                              per pool, forever; optionally serve /metrics
                              and /recommendations (see advise_config)"
    );
}

fn run_advise(advise_config_path: &str) -> Result<(), String> {
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
    advise_loop::run(&config)
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

fn load_cost_model(path: &str) -> Result<Document, String> {
    let doc = Document::load(Path::new(path)).map_err(|e| format!("reading {path}: {e}"))?;
    doc.validate().map_err(|e| e.to_string())?;
    Ok(doc)
}
