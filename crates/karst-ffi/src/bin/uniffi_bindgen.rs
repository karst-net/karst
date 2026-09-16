// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Regenerates Swift/Kotlin bindings from the compiled `karst_ffi` library —
//! ADR-0029 item 4. UniFFI's "library mode": it introspects the metadata
//! UniFFI's proc macros embed in the compiled `cdylib`/`staticlib`, so there
//! is no `.udl` file to keep in sync by hand.
//!
//! ```sh
//! cargo build -p karst-ffi --release
//! cargo run -p karst-ffi --bin uniffi-bindgen -- generate \
//!     --library target/release/libkarst_ffi.dylib \
//!     --language swift --out-dir packaging/macos/generated
//! ```
//!
//! Not run as part of the build: bindings are committed, reviewed source,
//! not a build artifact regenerated on every compile — the same posture
//! `packaging/macos`'s hand-written Swift already holds itself to.

fn main() {
    uniffi::uniffi_bindgen_main();
}
