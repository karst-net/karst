// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import Darwin
import Foundation

/// Everything that can go wrong asking `karstd` for its status.
///
/// Every case is handled identically by `AppDelegate` — as "not reachable
/// right now" — so this exists for anyone who later wants to log the reason,
/// not because the caller branches on it today.
enum StatusClientError: Error {
    case pathTooLong
    case socketCreationFailed
    case connectFailed
}

/// Talks to `karstd`'s **unprivileged** status socket —
/// `bins/karstd/src/ipc.rs`'s `bind_unprivileged_status`, reachable without
/// `sudo` by design (plans/phase-6/13-macos-status-indicators.md §1). This is
/// deliberately not the admin control socket `karst status` uses: that one is
/// `0700`/root-owned and a per-user `LaunchAgent` cannot reach it at all.
///
/// One request, one reply, framed the same way `karstd::ipc::request` frames
/// it on the Rust side: write the command line, half-close the write side,
/// read to EOF. No length prefix, no keep-alive — a fresh connection every
/// poll, which is the whole protocol `ipc.rs`'s module doc describes.
struct StatusClient {
    let socketPath: String

    /// Ask for `status` and return the raw TOML-ish reply text, unparsed.
    ///
    /// - Throws: `StatusClientError` on any failure to reach the socket.
    ///   A refusal from the daemon itself (e.g. if this were ever pointed at
    ///   the admin socket, which refuses nothing but *would* answer `down`
    ///   too — exactly why this type must only ever be given the status
    ///   socket's path) comes back as ordinary reply text, not a thrown
    ///   error; `StatusParser` is what notices `error = "..."` in it.
    func fetchStatus() throws -> String {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw StatusClientError.socketCreationFailed }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        // `sun_path` must hold the path plus a trailing NUL.
        guard pathBytes.count < capacity else { throw StatusClientError.pathTooLong }
        withUnsafeMutableBytes(of: &addr.sun_path) { rawPtr in
            let buffer = rawPtr.bindMemory(to: CChar.self)
            for index in 0..<capacity { buffer[index] = 0 }
            for (index, byte) in pathBytes.enumerated() {
                buffer[index] = CChar(bitPattern: byte)
            }
        }

        let connectResult = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                connect(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connectResult == 0 else { throw StatusClientError.connectFailed }

        let request = "status\n"
        _ = request.withCString { write(fd, $0, strlen($0)) }
        // The half-close *is* the frame — see `ipc.rs`'s module doc. Without
        // this the daemon's `read_line` blocks forever waiting for a
        // newline it already has, and so does this call.
        shutdown(fd, SHUT_WR)

        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = read(fd, &buffer, buffer.count)
            if n <= 0 { break }
            data.append(contentsOf: buffer[0..<n])
        }
        return String(decoding: data, as: UTF8.self)
    }
}
