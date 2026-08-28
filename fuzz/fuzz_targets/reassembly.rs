// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]
//! Fuzz the reassembler — spec §9.1, the highest-risk code in the system
//! (THREAT-MODEL R1).
//!
//! Properties asserted, all of them DoS-relevant:
//!   * no panic on any sequence of operations;
//!   * occupancy never exceeds the configured capacity;
//!   * memory never grows after construction;
//!   * a completed message is never longer than MAX_MESSAGE.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use karst_proto::consts;
use karst_proto::reassembly::{Accept, Config, Reassembler, MAX_MESSAGE};
use karst_proto::FragmentHeader;

#[derive(Arbitrary, Debug)]
struct Op {
    source_byte: u8,
    addr_validated: bool,
    reassembly_id: u8,
    idx: u8,
    count: u8,
    payload_len: u16,
    time_step: u16,
}

const CAPACITY: usize = 8;

fuzz_target!(|ops: Vec<Op>| {
    let cfg = Config {
        max_entries: CAPACITY,
        max_per_source: 3,
        timeout_ms: 3_000,
        load_threshold: 5,
    };
    let mut r = Reassembler::new(cfg);
    let baseline = r.memory_bytes();
    let mut now: u64 = 0;

    for op in ops.iter().take(512) {
        now = now.wrapping_add(u64::from(op.time_step));

        let hdr = FragmentHeader {
            reassembly_id: u32::from(op.reassembly_id),
            idx: op.idx & 0b11,
            count: (op.count & 0b11) + 1,
            frag_mac: [0; consts::FRAG_MAC_LEN],
        };
        let len = usize::from(op.payload_len) % (consts::FRAGMENT_PAYLOAD_MAX + 2);
        let payload = vec![0xA5u8; len];
        let mut source = [0u8; 18];
        source[0] = op.source_byte;

        match r.push(source, op.addr_validated, &hdr, &payload, now) {
            Accept::Complete(msg) => {
                assert!(msg.len() <= MAX_MESSAGE, "completed message oversized");
            }
            Accept::Buffered | Accept::Rejected(_) => {}
        }

        assert!(r.occupied() <= CAPACITY, "occupancy exceeded capacity");
        assert_eq!(r.memory_bytes(), baseline, "reassembler grew");
    }
});
