//! Alert delivery: ntfy push and/or SMTP email, dispatched to every
//! configured channel.
//!
//! Delivery is best-effort by design: a push failure logs and moves on —
//! alerting must never stall packet capture. Sends happen synchronously
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

/// SMTP mailer for one destination address (typically the carrier's
/// email-to-SMS gateway, so alerts arrive as text messages).
#[derive(Debug, Clone)]
pub struct SmtpMailer {
    host: String,
    username: String,
    password: String,
    from: String,
    to: String,
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

impl SmtpMailer {
    /// Mailer for `host` (e.g. `smtp.gmail.com:465`) authenticated as
    /// `username`/`password`, sending from `from` to `to`.
    pub fn new(host: &str, username: &str, password: &str, from: &str, to: &str) -> Self {
        Self {
            host: host.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            from: from.to_string(),
            to: to.to_string(),
        }
    }

    /// Destination address (tested without any network).
    pub fn recipient(&self) -> &str {
        &self.to
    }

    /// Subject line for one alert.
    pub fn subject(alert: &AlertEvent) -> String {
        format!("socteam {} [{}]", alert.name, severity_word(alert.severity))
    }

    /// Send one alert as a plain-text email.
    pub fn publish(&self, alert: &AlertEvent) -> Result<(), String> {
        use lettre::message::header::ContentType;
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::{Message, SmtpTransport, Transport};

        let email = Message::builder()
            .from(
                self.from
                    .parse()
                    .map_err(|e| format!("bad from addr: {e}"))?,
            )
            .to(self.to.parse().map_err(|e| format!("bad to addr: {e}"))?)
            .subject(Self::subject(alert))
            .header(ContentType::TEXT_PLAIN)
            .body(push_body(alert))
            .map_err(|e| e.to_string())?;
        let (server, port) = split_host_port(&self.host);
        let creds = Credentials::new(self.username.clone(), self.password.clone());
        let mailer = SmtpTransport::starttls_relay(&server)
            .map_err(|e| e.to_string())?
            .port(port)
            .credentials(creds)
            .build();
        mailer.send(&email).map_err(|e| e.to_string()).map(|_| ())
    }
}

/// One delivery channel.
#[derive(Debug, Clone)]
pub enum Channel {
    /// ntfy push (phone notification).
    Ntfy(Ntfy),
    /// SMTP email (use an email-to-SMS gateway to get texts).
    Mail(SmtpMailer),
}

/// Publishes each alert to every configured channel; per-channel
/// failures are reported and never abort the rest.
#[derive(Debug, Clone, Default)]
pub struct Dispatch {
    channels: Vec<Channel>,
}

impl Dispatch {
    /// An empty dispatch (everything disabled).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a channel.
    pub fn add(&mut self, channel: Channel) {
        self.channels.push(channel);
    }

    /// Number of configured channels.
    pub fn len(&self) -> usize {
        self.channels.len()
    }

    /// True when nothing is configured.
    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    /// Deliver one alert to every channel; returns one error line per
    /// failed channel (empty = fully delivered).
    pub fn publish(&self, alert: &AlertEvent) -> Vec<String> {
        self.channels
            .iter()
            .filter_map(|channel| match channel {
                Channel::Ntfy(ntfy) => ntfy.publish(alert).err(),
                Channel::Mail(mail) => mail.publish(alert).err(),
            })
            .collect()
    }
}

/// Lowercase severity word for subjects/lines.
fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
    }
}

/// Split `host:port` with a 465 (implicit TLS) default.
fn split_host_port(host: &str) -> (String, u16) {
    match host.rsplit_once(':') {
        Some((server, port)) => (server.to_string(), port.parse().unwrap_or(465)),
        None => (host.to_string(), 465),
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
    fn smtp_recipient_and_subject() {
        let mailer = SmtpMailer::new(
            "smtp.gmail.com:587",
            "sensor@example.com",
            "app-password",
            "sensor@example.com",
            "5551234567@vtext.com",
        );
        assert_eq!(mailer.recipient(), "5551234567@vtext.com");
        assert_eq!(
            SmtpMailer::subject(&alert(Severity::High)),
            "socteam port-scan [high]"
        );
    }

    #[test]
    fn dispatch_reports_failures_without_aborting() {
        // A mailer pointed at an unreachable localhost port: must fail,
        // and the dispatch must carry the error back.
        let mut dispatch = Dispatch::new();
        dispatch.add(Channel::Mail(SmtpMailer::new(
            "127.0.0.1:1",
            "u",
            "p",
            "from@example.com",
            "to@example.com",
        )));
        let errors = dispatch.publish(&alert(Severity::Low));
        assert_eq!(errors.len(), 1, "expected the mail failure reported");
    }

    #[test]
    fn empty_dispatch_is_a_noop() {
        let dispatch = Dispatch::new();
        assert!(dispatch.is_empty());
        assert!(dispatch.publish(&alert(Severity::Low)).is_empty());
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
