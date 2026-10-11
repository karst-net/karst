// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The ADR-0050 boundary is complete frame acceptance, never queue insertion.
#![allow(clippy::expect_used)]

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use karst_relay::hub::{DeliveryUsage, Outbound};
use tokio::io::AsyncWrite;

struct Writer {
    accepted: usize,
    fail_at: Option<usize>,
    zero: bool,
}

impl AsyncWrite for Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.fail_at == Some(self.accepted) {
            return Poll::Ready(if self.zero {
                Ok(0)
            } else {
                Err(io::ErrorKind::BrokenPipe.into())
            });
        }
        let remaining = self.fail_at.map_or(bytes.len(), |end| end - self.accepted);
        let n = bytes.len().min(remaining).min(7);
        self.accepted += n;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn packet() -> Outbound {
    Outbound {
        bytes: vec![0; 136],
        delivery: Some(DeliveryUsage {
            mapping: None,
            payload_bytes: 100,
        }),
    }
}

#[tokio::test]
async fn short_writes_produce_one_payload_count_only_after_completion() {
    let mut writer = Writer {
        accepted: 0,
        fail_at: None,
        zero: false,
    };
    let evidence = packet()
        .write_to(&mut writer)
        .await
        .expect("complete write")
        .expect("delivery");
    assert_eq!(writer.accepted, 136);
    assert_eq!(evidence.payload_bytes, 100);
    assert!(
        evidence.mapping.is_none(),
        "unknown attribution stays unknown"
    );
}

#[tokio::test]
async fn every_partial_failure_excludes_the_entire_frame() {
    for fail_at in 0..136 {
        for zero in [false, true] {
            let mut writer = Writer {
                accepted: 0,
                fail_at: Some(fail_at),
                zero,
            };
            assert!(packet().write_to(&mut writer).await.is_err());
            assert_eq!(writer.accepted, fail_at);
        }
    }
}

#[tokio::test]
async fn control_or_mesh_write_produces_no_delivery_evidence() {
    let mut writer = Writer {
        accepted: 0,
        fail_at: None,
        zero: false,
    };
    let frame = Outbound {
        bytes: vec![0; 80],
        delivery: None,
    };
    assert!(frame.write_to(&mut writer).await.expect("write").is_none());
    assert_eq!(writer.accepted, 80);
}
