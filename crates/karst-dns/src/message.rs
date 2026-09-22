// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! DNS wire-message boundary.
//!
//! Karst owns resolver policy; hickory-proto owns the notoriously delicate
//! name-compression and DNS wire parsing. Keeping this small boundary makes it
//! impossible for forwarding code to accidentally parse a different grammar.

use std::io::{self, Read, Write};

use hickory_proto::op::Message;

/// Decode a complete DNS message received from a client or upstream.
pub fn decode(bytes: &[u8]) -> Result<Message, String> {
    Message::from_vec(bytes).map_err(|error| error.to_string())
}

/// Read one RFC 7766 length-prefixed DNS message — the framing both the TCP
/// client listener and the DoT upstream transport use.
pub fn read_framed(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix)?;
    let mut message = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut message)?;
    Ok(message)
}

/// Write one RFC 7766 length-prefixed DNS message.
pub fn write_framed(stream: &mut impl Write, message: &[u8]) -> io::Result<()> {
    let length = u16::try_from(message.len())
        .map_err(|_| io::Error::other("DNS TCP message exceeds RFC 7766 framing"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    #[test]
    fn round_trips_a_query_through_the_codec() {
        let mut message = Message::new(7, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("alpha.aquifer.karst.").expect("name"),
            RecordType::A,
        ));
        let wire = message.to_vec().expect("encode");
        assert_eq!(decode(&wire).expect("decode").queries, message.queries);
    }

    #[test]
    fn rejects_truncated_input() {
        assert!(decode(&[0, 1, 0]).is_err());
    }

    #[test]
    fn framing_round_trips() {
        let mut buffer = Vec::new();
        write_framed(&mut buffer, b"hello").expect("write");
        assert_eq!(buffer, [0, 5, b'h', b'e', b'l', b'l', b'o']);
        assert_eq!(read_framed(&mut buffer.as_slice()).expect("read"), b"hello");
    }
}
