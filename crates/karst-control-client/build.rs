// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Generates the gRPC client from the same `.proto` the Go server compiles.
//!
//! One source of truth for the wire format. Hand-writing a second definition
//! is how two implementations of one protocol drift apart in the field, and
//! the drift only shows up as a handshake that never completes.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = "../../server/shared/management/proto";
    let proto = format!("{proto_dir}/karst_control.proto");

    println!("cargo:rerun-if-changed={proto}");
    println!("cargo:rerun-if-changed={proto_dir}/management.proto");

    tonic_prost_build::configure()
        // The node needs a client; the server side is Go's.
        .build_server(false)
        .build_client(true)
        .compile_protos(&[proto.as_str()], &[proto_dir])?;
    Ok(())
}
