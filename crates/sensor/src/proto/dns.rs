//! DNS message parsing over a UDP-style payload (no TCP length prefix).
//!
//! Framing (e.g. stripping the two-byte TCP length prefix) is the 1D
//! pipeline's job; this module only decodes one raw DNS message as it
//! would appear in a UDP datagram.
//!
//! Never panics: malformed input degrades to `None`, and all strings are
//! capped so hostile input can never balloon memory.

use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::RData;

/// Maximum length in bytes of any string stored in [`DnsSummary`].
const MAX_STRING_LEN: usize = 255;
/// Maximum number of answer entries stored in [`DnsSummary`].
const MAX_ANSWERS: usize = 10;

/// Zeek-inspired summary of one DNS message. All strings capped; hostile
/// input can never balloon memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSummary {
    /// DNS header transaction ID.
    pub transaction_id: u16,
    /// True when the header message type is response.
    pub is_response: bool,
    /// Response code value from the header.
    pub rcode: u8,
    /// First question name (lowercased, no trailing dot normalization beyond what hickory gives), capped at 255 chars.
    pub query: Option<String>,
    /// First question record type number.
    pub qtype: Option<u16>,
    /// Answer names/RDATA rendered as strings — at most 10 entries, each capped at 255 chars.
    pub answers: Vec<String>,
}

/// Parse a raw DNS message payload (UDP-style: no TCP length prefix —
/// framing is the 1D pipeline's job). Returns None on malformed input;
/// never panics.
pub fn parse(payload: &[u8]) -> Option<DnsSummary> {
    let message = Message::from_vec(payload).ok()?;

    let (query, qtype) = match message.queries().first() {
        Some(question) => {
            let name = truncate_at_boundary(&question.name().to_string().to_lowercase());
            let qtype = u16::from(question.query_type());
            (Some(name), Some(qtype))
        }
        None => (None, None),
    };

    let mut answers = Vec::new();
    for record in message.answers().iter().take(MAX_ANSWERS) {
        answers.push(truncate_at_boundary(&render_answer(record)));
    }

    Some(DnsSummary {
        transaction_id: message.id(),
        is_response: message.message_type() == MessageType::Response,
        // Keep the 4-bit header rcode only: hickory folds extended OPT
        // rcodes into the same field, and the summary models the header.
        rcode: (u16::from(message.response_code()) & 0x0F) as u8,
        query,
        qtype,
        answers,
    })
}

/// Render one answer record as `"<name> <rdata-ish>"`.
///
/// Address and name targets use their own `Display`; every other type
/// falls back to the generic `RData` `Display`. Records without data
/// render as just the owner name.
fn render_answer(record: &hickory_proto::rr::Record) -> String {
    let name = record.name().to_string();
    let rdata = match record.data() {
        Some(RData::A(a)) => a.to_string(),
        Some(RData::AAAA(aaaa)) => aaaa.to_string(),
        Some(RData::CNAME(target)) => target.to_string(),
        Some(RData::NS(target)) => target.to_string(),
        Some(RData::PTR(target)) => target.to_string(),
        Some(other) => other.to_string(),
        None => String::new(),
    };
    if rdata.is_empty() {
        name
    } else {
        let mut out = String::with_capacity(name.len() + 1 + rdata.len());
        out.push_str(&name);
        out.push(' ');
        out.push_str(&rdata);
        out
    }
}

/// Copy `s` truncated to [`MAX_STRING_LEN`] bytes at a char boundary.
///
/// Never panics: the boundary scan only moves down toward 0, which is
/// always a char boundary.
fn truncate_at_boundary(s: &str) -> String {
    if s.len() <= MAX_STRING_LEN {
        return s.to_owned();
    }
    let mut boundary = MAX_STRING_LEN;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    s[..boundary].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn query_message() -> Vec<u8> {
        let name = Name::from_str("example.com.").unwrap();
        let mut message = Message::new();
        message
            .set_id(0x1234)
            .set_message_type(MessageType::Query)
            .set_recursion_desired(true)
            .add_query(Query::query(name, RecordType::A));
        message.to_vec().unwrap()
    }

    #[test]
    fn query_round_trips() {
        let summary = parse(&query_message()).unwrap();
        assert_eq!(summary.transaction_id, 0x1234);
        assert!(!summary.is_response);
        assert_eq!(summary.query, Some("example.com.".to_owned()));
        assert_eq!(summary.qtype, Some(u16::from(RecordType::A)));
        assert!(summary.answers.is_empty());
    }

    #[test]
    fn response_with_a_answer() {
        let name = Name::from_str("example.com.").unwrap();
        let mut message = Message::new();
        message
            .set_id(0x5678)
            .set_message_type(MessageType::Response)
            .set_response_code(ResponseCode::NoError)
            .add_query(Query::query(name.clone(), RecordType::A))
            .add_answer(Record::from_rdata(
                name,
                300,
                RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
            ));
        let summary = parse(&message.to_vec().unwrap()).unwrap();
        assert!(summary.is_response);
        assert_eq!(summary.rcode, 0);
        assert_eq!(summary.answers.len(), 1);
        assert!(summary.answers[0].contains("93.184.216.34"));
    }

    #[test]
    fn malformed_input_returns_none() {
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[0u8; 2]), None);
        assert_eq!(parse(&[0xFFu8; 64]), None);
    }

    #[test]
    fn answers_capped_at_ten() {
        let name = Name::from_str("example.com.").unwrap();
        let mut message = Message::new();
        message
            .set_id(1)
            .set_message_type(MessageType::Response)
            .add_query(Query::query(name.clone(), RecordType::A));
        for i in 0..15u8 {
            message.add_answer(Record::from_rdata(
                name.clone(),
                300,
                RData::A(A(Ipv4Addr::new(10, 0, 0, i))),
            ));
        }
        let summary = parse(&message.to_vec().unwrap()).unwrap();
        assert_eq!(summary.answers.len(), 10);
        assert!(summary.answers[0].contains("10.0.0.0"));
    }
}
