//! HTTP header-block parsing over a reassembled payload.
//!
//! Bytes in, [`HttpSummary`] out, no I/O. Only the header block is
//! summarized; any body bytes after the terminating blank line are ignored.
//!
//! Never panics: incomplete (`Status::Partial`), ambiguous, or malformed
//! blocks degrade to `None`. In particular v0 requires the full header block
//! (through the final `\r\n\r\n`) in a single payload — a block split across
//! payloads parses as `Partial` on both the request and response attempts and
//! yields `None`; reassembly is out of scope.

/// Maximum headers held while parsing; matches the fixed header array.
const MAX_HEADERS: usize = 16;
/// Maximum length of a summarized request method, in chars.
const METHOD_CAP: usize = 16;
/// Maximum length of a summarized request URI, in chars.
const URI_CAP: usize = 512;
/// Maximum length of a summarized Host header value, in chars.
const HOST_CAP: usize = 255;
/// Maximum length of a summarized User-Agent header value, in chars.
const USER_AGENT_CAP: usize = 128;

/// Parsed HTTP header block, request or response. All strings capped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpKind {
    Request,
    Response,
}

/// Summary of one HTTP header block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSummary {
    /// Whether the block parsed as a request or a response.
    pub kind: HttpKind,
    /// Requests; request method, capped at 16 chars.
    pub method: Option<String>,
    /// Requests; request target (path), capped at 512 chars.
    pub uri: Option<String>,
    /// Host header value, capped at 255 chars.
    pub host: Option<String>,
    /// User-Agent header value, capped at 128 chars.
    pub user_agent: Option<String>,
    /// Responses; numeric status code.
    pub status: Option<u16>,
}

/// Parse the start of an HTTP header block. Returns None when the block is
/// incomplete (Status::Partial), ambiguous, or malformed — never panics.
/// Body bytes are ignored; only the header block is summarized.
///
/// The payload is tried as a request first, then as a response. A block with
/// more than [`MAX_HEADERS`] headers exceeds the fixed header array, so
/// httparse fails that attempt with `Error::TooManyHeaders` and parsing falls
/// through to `None` (a >16-header request is not retried as a response
/// successfully either, since the response attempt fails on the request line).
pub fn parse(payload: &[u8]) -> Option<HttpSummary> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(payload) {
        Ok(httparse::Status::Complete(_)) => {
            let method = req
                .method
                .map(|m| cap(&String::from_utf8_lossy(m.as_bytes()), METHOD_CAP));
            let uri = req
                .path
                .map(|p| cap(&String::from_utf8_lossy(p.as_bytes()), URI_CAP));
            let (host, user_agent) = header_fields(req.headers);
            Some(HttpSummary {
                kind: HttpKind::Request,
                method,
                uri,
                host,
                user_agent,
                status: None,
            })
        }
        // Partial (truncated block) or Err (malformed / too many headers):
        // fall through to the response attempt.
        _ => {
            let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut res = httparse::Response::new(&mut headers);
            match res.parse(payload) {
                Ok(httparse::Status::Complete(_)) => {
                    let (host, user_agent) = header_fields(res.headers);
                    Some(HttpSummary {
                        kind: HttpKind::Response,
                        method: None,
                        uri: None,
                        host,
                        user_agent,
                        status: res.code,
                    })
                }
                // Partial or Err: incomplete, ambiguous, or malformed.
                _ => None,
            }
        }
    }
}

/// Extract Host and User-Agent values from parsed headers.
///
/// httparse preserves header-name case as sent on the wire (verified: no
/// case folding in httparse 1.10.1 sources), so matching is ASCII
/// case-insensitive here. Values are lossy-UTF-8 decoded and capped.
fn header_fields(headers: &[httparse::Header<'_>]) -> (Option<String>, Option<String>) {
    let mut host = None;
    let mut user_agent = None;
    for h in headers {
        if h.name.eq_ignore_ascii_case("host") && host.is_none() {
            host = Some(cap(&String::from_utf8_lossy(h.value), HOST_CAP));
        } else if h.name.eq_ignore_ascii_case("user-agent") && user_agent.is_none() {
            user_agent = Some(cap(&String::from_utf8_lossy(h.value), USER_AGENT_CAP));
        }
    }
    (host, user_agent)
}

/// Truncate `s` to at most `n` chars at a safe char boundary. Never panics.
fn cap(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_owned();
    }
    let mut end = 0;
    for (i, c) in s.char_indices() {
        let next = i + c.len_utf8();
        if next > n {
            break;
        }
        end = next;
    }
    s[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_request_with_host_and_user_agent() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test-agent/1.0\r\nAccept: */*\r\n\r\n";
        let summary = parse(raw).expect("well-formed request parses");
        assert_eq!(summary.kind, HttpKind::Request);
        assert_eq!(summary.method.as_deref(), Some("GET"));
        assert_eq!(summary.uri.as_deref(), Some("/index.html"));
        assert_eq!(summary.host.as_deref(), Some("example.com"));
        assert_eq!(summary.user_agent.as_deref(), Some("test-agent/1.0"));
        assert_eq!(summary.status, None);
    }

    #[test]
    fn post_with_long_uri_is_capped() {
        let long_path = format!("/{}", "a".repeat(600));
        let raw = format!("POST {long_path} HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let summary = parse(raw.as_bytes()).expect("long-uri request parses");
        assert_eq!(summary.kind, HttpKind::Request);
        assert_eq!(summary.method.as_deref(), Some("POST"));
        let uri = summary.uri.expect("uri present");
        assert_eq!(uri.chars().count(), 512);
        assert!(long_path.starts_with(&uri));
    }

    #[test]
    fn not_found_response() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n";
        let summary = parse(raw).expect("well-formed response parses");
        assert_eq!(summary.kind, HttpKind::Response);
        assert_eq!(summary.status, Some(404));
        assert_eq!(summary.method, None);
        assert_eq!(summary.uri, None);
    }

    #[test]
    fn truncated_header_block_is_none() {
        // Cut before the final blank line: header block incomplete (Partial).
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert_eq!(parse(raw), None);
    }

    #[test]
    fn garbage_bytes_are_none() {
        assert_eq!(parse(b"\x00\x01\x02\x03\xff\xfe\xfd"), None);
        assert_eq!(parse(b""), None);
        assert_eq!(parse(b"this is not http at all\r\n\r\n"), None);
    }

    #[test]
    fn more_than_sixteen_headers_is_none() {
        // httparse fails with Error::TooManyHeaders once the fixed 16-slot
        // array is exhausted, so an over-wide block yields None.
        let mut raw = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        for i in 0..20 {
            raw.extend_from_slice(format!("X-Header-{i}: value\r\n").as_bytes());
        }
        raw.extend_from_slice(b"\r\n");
        assert_eq!(parse(&raw), None);
    }
}
