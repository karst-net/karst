// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Recorded usage, replayed against a [`crate::cost_model`] — the input side
//! of ADR-0045 §7 Phase 0's "offline tool that replays recorded relay
//! telemetry against a cost model."
//!
//! **Why this is not ADR-0021's wire format.** A relay's signed telemetry
//! report (ADR-0021) is a relay-wide snapshot — client counts, a byte total,
//! uptime — with no per-meter or per-edge breakdown, and no history even of
//! that (ADR-0047: "latest-snapshot-per-relay... never accumulates its own
//! history"). Turning that into "how many GB did pool X move across a
//! cross-region edge this month" needs a traffic matrix nothing in the tree
//! produces yet. Rather than guess at that mapping, this module takes
//! already-attributed usage as its input — one record per (pool, meter or
//! edge class, time) — and leaves "how an operator gets there" (a
//! Prometheus export, a provider's own billing export, a hand-reconciled
//! spreadsheet) as a separate, later concern. This is the simulator's input
//! contract, not a claim that the ETL to produce it exists today.
//!
//! One plain-text format, deliberately not CSV via a parsing crate: the
//! column count is fixed and small, and a tool whose whole job is to be
//! auditable by a human reading the file next to it should not need a
//! dependency to read its own input.
//!
//! ```text
//! # timestamp,pool,kind,key,quantity
//! 1759536000,onprem-mia,meter,egress_gb,420.5
//! 1759536000,onprem-mia,edge,cross-region,12.0
//! ```

use crate::cost_model::EdgeClass;

/// Errors reading a usage file.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// A line could not be parsed, with its 1-based line number.
    Syntax(usize, String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "usage: {e}"),
            Self::Syntax(line, m) => write!(f, "usage: line {line}: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// What a usage record is charged against: a meter, or an edge class.
#[derive(Debug, Clone, PartialEq)]
pub enum Metric {
    Meter(String),
    Edge(EdgeClass),
}

/// One line of recorded usage: this much of this metric, for this pool, at
/// this time.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub timestamp: i64,
    pub pool: String,
    pub metric: Metric,
    pub quantity: f64,
}

/// Parse a usage file's text.
///
/// Blank lines and lines starting with `#` are skipped. Every other line is
/// `timestamp,pool,kind,key,quantity` with `kind` one of `meter` or `edge`.
///
/// # Errors
/// [`Error::Syntax`] naming the offending line.
pub fn parse(text: &str) -> Result<Vec<Record>, Error> {
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line_no = index + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        let [timestamp, pool, kind, key, quantity] = fields.as_slice() else {
            return Err(Error::Syntax(
                line_no,
                format!(
                    "want 5 comma-separated fields (timestamp,pool,kind,key,quantity), got {}",
                    fields.len()
                ),
            ));
        };
        let timestamp: i64 = timestamp.parse().map_err(|_| {
            Error::Syntax(
                line_no,
                format!("{timestamp:?} is not an integer timestamp"),
            )
        })?;
        let quantity: f64 = quantity
            .parse()
            .map_err(|_| Error::Syntax(line_no, format!("{quantity:?} is not a number")))?;
        if !quantity.is_finite() || quantity < 0.0 {
            return Err(Error::Syntax(
                line_no,
                format!("quantity {quantity} must be finite and non-negative"),
            ));
        }
        let metric = match *kind {
            "meter" => Metric::Meter((*key).to_owned()),
            "edge" => Metric::Edge(EdgeClass::parse_str(key).ok_or_else(|| {
                Error::Syntax(
                    line_no,
                    format!(
                        "{key:?} is not an edge class (want one of internet, same-region, \
                         cross-region, cross-provider, private-link)"
                    ),
                )
            })?),
            other => {
                return Err(Error::Syntax(
                    line_no,
                    format!("{other:?} is not a kind (want meter or edge)"),
                ))
            }
        };
        records.push(Record {
            timestamp,
            pool: (*pool).to_owned(),
            metric,
            quantity,
        });
    }
    Ok(records)
}

/// Read and parse a usage file from disk.
///
/// # Errors
/// [`Error::Io`] if the file cannot be read, plus everything [`parse`]
/// returns.
pub fn load(path: &std::path::Path) -> Result<Vec<Record>, Error> {
    let text = std::fs::read_to_string(path).map_err(Error::Io)?;
    parse(&text)
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

    #[test]
    fn blank_lines_and_comments_are_skipped() {
        let records = parse("\n# a comment\n\n1,p,meter,egress_gb,1.0\n").expect("parses");
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn a_meter_record_round_trips() {
        let records = parse("1759536000,onprem-mia,meter,egress_gb,420.5").expect("parses");
        assert_eq!(
            records[0],
            Record {
                timestamp: 1_759_536_000,
                pool: "onprem-mia".to_owned(),
                metric: Metric::Meter("egress_gb".to_owned()),
                quantity: 420.5,
            }
        );
    }

    #[test]
    fn an_edge_record_round_trips() {
        let records = parse("1759536000,onprem-mia,edge,cross-region,12.0").expect("parses");
        assert_eq!(records[0].metric, Metric::Edge(EdgeClass::CrossRegion));
    }

    #[test]
    fn wrong_field_count_names_the_line() {
        let err = parse("1,p,meter,egress_gb,5.0\n1,2,3").expect_err("too few fields");
        assert!(matches!(err, Error::Syntax(2, _)), "{err:?}");
    }

    #[test]
    fn an_unknown_kind_is_an_error() {
        let err = parse("1,p,bogus,egress_gb,1.0").expect_err("unknown kind");
        assert!(format!("{err}").contains("bogus"), "{err}");
    }

    #[test]
    fn an_unknown_edge_class_is_an_error() {
        let err = parse("1,p,edge,moon,1.0").expect_err("unknown edge class");
        assert!(format!("{err}").contains("moon"), "{err}");
    }

    #[test]
    fn a_negative_quantity_is_refused() {
        // Usage is a count of something that happened; it is never negative,
        // and a feed that produced one is more likely wrong than owed a
        // refund this tool should model.
        let err = parse("1,p,meter,egress_gb,-1.0").expect_err("negative quantity");
        assert!(format!("{err}").contains("non-negative"), "{err}");
    }

    #[test]
    fn a_non_numeric_quantity_names_the_line() {
        let err = parse("1,p,meter,egress_gb,lots").expect_err("non-numeric");
        assert!(format!("{err}").contains("lots"), "{err}");
    }
}
