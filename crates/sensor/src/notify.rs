//! ntfy alert push: one blocking HTTP POST per alert.
//!
//! Delivery is best-effort by design: a push failure logs and moves on —
//! alerting must never stall packet capture. Pushes happen synchronously
//! on the sensor's status tick, so the hard-exit shutdown path is safe.

use events::{AlertEvent, Severity};
use std::time::Duration;

/// ntfy client bound to a server root and topic.
#[derive(Debug, Clone)]
pub struct Ntfy {
    url: String,
    topic: String,
    timeout: Duration,
}

/// ntfy priority mapped from alert severity.
pub fn ntfy_priority(severity: Severity) -> u8 {
    match severity {
        Severity::Low => 1,
        Severity::Medium => 3,
        Severity::High => 4,
    }
}

/// One-line push body: `src -> dst: message` (dst "-" when absent).
pub fn push_body(alert: &AlertEvent) -> String {
    format!(
        "{} -> {}: {}",
        alert.src,
        alert.dst.as_deref().unwrap_or("-"),
        alert.message
    )
}

impl Ntfy {
    /// Client for `<url>/<topic>` with a 5 s request timeout.
    pub fn new(url: &str, topic: &str) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            topic: topic.to_string(),
            timeout: Duration::from_secs(5),
        }
    }

    /// Full endpoint URL (tested without any network).
    pub fn endpoint(&self) -> String {
        format!("{}/{}", self.url, self.topic)
    }

    /// Publish one alert. `Ok(())` on any 2xx; errors are returned so the
    /// caller decides how loudly to log.
    pub fn publish(&self, alert: &AlertEvent) -> Result<(), String> {
        let payload = serde_json::json!({
            "topic": self.topic,
            "title": format!("socteam {}", alert.name),
            "message": push_body(alert),
            "priority": ntfy_priority(alert.severity),
            "tags": ["rotating_light"],
        });
        let response = ureq::post(&self.endpoint())
            .timeout(self.timeout)
            .send_json(payload)
            .map_err(|e| e.to_string())?;
        if (200..300).contains(&response.status()) {
            Ok(())
        } else {
            Err(format!("ntfy returned {}", response.status()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(severity: Severity) -> AlertEvent {
        AlertEvent {
            uid: "alert1".to_string(),
            ts: 100.0,
            name: "port-scan".to_string(),
            severity,
            src: "192.0.2.66".to_string(),
            dst: Some("198.51.100.7".to_string()),
            message: "15 distinct ports".to_string(),
            evidence: vec![],
        }
    }

    #[test]
    fn endpoint_joins_without_double_slash() {
        let ntfy = Ntfy::new("https://ntfy.sh/", "home-soc");
        assert_eq!(ntfy.endpoint(), "https://ntfy.sh/home-soc");
    }

    #[test]
    fn severity_maps_to_ntfy_priorities() {
        assert_eq!(ntfy_priority(Severity::Low), 1);
        assert_eq!(ntfy_priority(Severity::Medium), 3);
        assert_eq!(ntfy_priority(Severity::High), 4);
    }

    #[test]
    fn push_body_renders_src_dst_message() {
        assert_eq!(
            push_body(&alert(Severity::High)),
            "192.0.2.66 -> 198.51.100.7: 15 distinct ports"
        );
        let mut no_dst = alert(Severity::Low);
        no_dst.dst = None;
        assert_eq!(push_body(&no_dst), "192.0.2.66 -> -: 15 distinct ports");
    }

    #[test]
    fn publish_posts_to_a_local_stub() {
        // A one-shot HTTP stub: accept one connection, read the full
        // request (headers + Content-Length body — it may span several
        // TCP segments), answer 200, and assert the JSON body reached us.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let text = String::from_utf8_lossy(&request).to_string();
                if let Some(header_end) = text.find("\r\n\r\n") {
                    let body_start = header_end + 4;
                    let want = text
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .and_then(|v| v.trim().parse::<usize>().ok());
                    if let Some(len) = want
                        && request.len() >= body_start + len
                    {
                        break;
                    }
                }
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
            }
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
            stream.write_all(response.as_bytes()).unwrap();
            String::from_utf8_lossy(&request).to_string()
        });
        let ntfy = Ntfy::new(&format!("http://{addr}"), "home-soc");
        ntfy.publish(&alert(Severity::High)).unwrap();
        let request = server.join().unwrap();
        assert!(request.starts_with("POST /home-soc"), "bad path: {request}");
        assert!(request.contains("\"topic\":\"home-soc\""));
        assert!(request.contains("\"priority\":4"));
        assert!(request.contains("socteam port-scan"));
    }
}
