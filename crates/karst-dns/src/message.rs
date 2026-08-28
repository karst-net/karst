// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! DNS wire-message boundary.
//!
//! Karst owns resolver policy; hickory-proto owns the notoriously delicate
//! name-compression and DNS wire parsing. Keeping this small boundary makes it
//! impossible for forwarding code to accidentally parse a different grammar.

use hickory_proto::op::Message;

/// Decode a complete DNS message received from a client or upstream.
pub fn decode(bytes: &[u8]) -> Result<Message, String> {
    Message::from_vec(bytes).map_err(|error| error.to_string())
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
}
