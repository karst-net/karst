// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]
//! Fuzz DNS message decoding at the KarstDNS client/upstream boundary.

use karst_dns::message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Both malformed client requests and hostile upstream replies reach this
    // parser before resolver policy sees them. Its only acceptable result for
    // arbitrary bytes is a normal error or a decoded message, never a panic.
    let _ = message::decode(data);
});
