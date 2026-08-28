// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]
//! Fuzz the fragment-header codec — spec §5.
//!
//! The decoder sits on the pre-authentication path, so the property is total:
//! for ANY input it returns without panicking, and anything it accepts must
//! re-encode to a header that decodes identically.

use libfuzzer_sys::fuzz_target;
use karst_proto::FragmentHeader;

fuzz_target!(|data: &[u8]| {
    if let Ok(hdr) = FragmentHeader::decode(data) {
        // Round-trip: an accepted header must survive re-encoding unchanged.
        let re = hdr.encode();
        let again = FragmentHeader::decode(&re).expect("re-encode must decode");
        assert_eq!(hdr, again, "round-trip changed the header");
        assert!(hdr.idx < hdr.count, "decoder let idx >= count through");
        assert!(hdr.count >= 1 && hdr.count <= 4, "count out of range");
    }
});
