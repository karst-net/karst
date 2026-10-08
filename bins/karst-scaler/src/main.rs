// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! `karst-scaler simulate COST_MODEL.toml USAGE_LOG` — ADR-0045 §7 Phase 0.
//!
//! ```text
//! karst-scaler simulate COST_MODEL.toml USAGE_LOG
//!     replay recorded usage against a cost model; print spend per pool,
//!     per meter, per edge, and a grand total
//! karst-scaler check COST_MODEL.toml
//!     parse and validate a cost-model file without simulating anything
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

use karst_scaler::cost_model::Document;
use karst_scaler::{simulate, usage};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();

    let result = match refs.as_slice() {
        ["simulate", cost_model, usage_log] => run_simulate(cost_model, usage_log),
        ["check", cost_model] => run_check(cost_model),
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
        "karst-scaler — ADR-0045 Phase 0: cost model and offline simulator

  simulate COST_MODEL.toml USAGE_LOG
                              replay recorded usage against a cost model;
                              print spend per pool, per meter, per edge
  check COST_MODEL.toml       parse and validate a cost-model file only"
    );
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
