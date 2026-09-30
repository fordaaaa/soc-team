//! Optional TOML config for the sensor binary (`--config PATH`).
//!
//! Every field is optional and defaults to unset; explicit CLI flags
//! always override whatever the file says. Unknown keys are ignored so
//! newer config files stay readable by older binaries.

use serde::Deserialize;
use std::path::Path;

/// Top-level sensor config file.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SensorConfig {
    /// Capture source settings.
    pub sensor: SensorSection,
    /// Event-file retention caps.
    pub retention: RetentionSection,
    /// Alert delivery settings.
    pub alert: AlertSection,
    /// Live detection tuning.
    pub detect: DetectSection,
}

/// `[sensor]` section: capture source and output settings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SensorSection {
    /// Interface to capture on.
    pub iface: Option<String>,
    /// Pcap file to replay.
    pub pcap: Option<String>,
    /// Generate synthetic traffic instead of capturing.
    pub sim: Option<bool>,
    /// Target packets per second for sim traffic.
    pub pps: Option<u32>,
    /// Seed for sim traffic.
    pub seed: Option<u64>,
    /// Enable promiscuous capture.
    pub promiscuous: Option<bool>,
    /// Directory for NDJSON event output.
    pub events: Option<String>,
    /// Rotate event files at this many bytes.
    pub rotate_bytes: Option<u64>,
    /// Seconds between status lines.
    pub interval: Option<u64>,
}

/// `[retention]` section: event-directory caps.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RetentionSection {
    /// Delete oldest rotated event files beyond this total size.
    pub max_dir_bytes: Option<u64>,
    /// Delete rotated event files older than this many seconds.
    pub max_age_secs: Option<u64>,
}

/// `[alert]` section: delivery and self-monitoring.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AlertSection {
    /// ntfy server root (e.g. `https://ntfy.sh`); alerts POST to
    /// `<url>/<topic>`. Leave unset to disable push.
    pub ntfy_url: Option<String>,
    /// ntfy topic to publish alerts under.
    pub ntfy_topic: Option<String>,
    /// Self-watch: fire an alert after this many seconds with zero frames.
    pub blind_secs: Option<u64>,
    /// SMTP host for email alerts (e.g. `smtp.gmail.com:587`).
    pub mail_host: Option<String>,
    /// SMTP username (an app password for Gmail et al.).
    pub mail_user: Option<String>,
    /// SMTP password. Stored in plain text in this file — keep the file
    /// root-only (0600) and prefer a throwaway account.
    pub mail_pass: Option<String>,
    /// Envelope-from address for email alerts.
    pub mail_from: Option<String>,
    /// Destination address; use your carrier's email-to-SMS gateway
    /// (e.g. 5551234567@vtext.com) to receive alerts as texts.
    pub mail_to: Option<String>,
}

/// `[detect]` section: live detection tuning.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DetectSection {
    /// How much event history the live engine keeps, in seconds.
    pub live_window_secs: Option<f64>,
    /// Minimum seconds between repeat alerts for the same (name, src).
    pub cooldown_secs: Option<f64>,
}

impl SensorConfig {
    /// Read and parse a config file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_example() {
        let config: SensorConfig = toml::from_str(
            r#"
[sensor]
iface = "eth0"
events = "/var/lib/socteam"
interval = 5

[retention]
max_dir_bytes = 536870912
max_age_secs = 604800

[alert]
ntfy_url = "https://ntfy.sh"
ntfy_topic = "home-soc"
blind_secs = 900

[detect]
live_window_secs = 900.0
cooldown_secs = 600.0
"#,
        )
        .unwrap();
        assert_eq!(config.sensor.iface.as_deref(), Some("eth0"));
        assert_eq!(config.sensor.interval, Some(5));
        assert_eq!(config.retention.max_dir_bytes, Some(536_870_912));
        assert_eq!(config.alert.ntfy_topic.as_deref(), Some("home-soc"));
        assert_eq!(config.detect.live_window_secs, Some(900.0));
    }

    #[test]
    fn empty_file_yields_defaults() {
        let config: SensorConfig = toml::from_str("").unwrap();
        assert!(config.sensor.iface.is_none());
        assert!(config.retention.max_age_secs.is_none());
        assert!(config.alert.ntfy_url.is_none());
        assert!(config.detect.cooldown_secs.is_none());
    }

    #[test]
    fn unknown_keys_ignored() {
        let config: SensorConfig = toml::from_str(
            r#"
[sensor]
iface = "en0"
future_setting = true

[bogus_section]
x = 1
"#,
        )
        .unwrap();
        assert_eq!(config.sensor.iface.as_deref(), Some("en0"));
    }
}
