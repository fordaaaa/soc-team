//! Detection rule engine skeleton.
//!
//! YAML rules arrive in Phase 2.

/// A single detection rule.
pub trait Detection {
    /// Short rule name (e.g. `arp-spoof`).
    fn name(&self) -> &str;
    /// Human-readable description of what the rule detects.
    fn description(&self) -> &str;
}

/// Runs a set of [`Detection`] rules over the event stream.
#[derive(Debug, Default)]
pub struct RuleEngine {
    /// Placeholder until Phase 2 deserializes real YAML rules here.
    pub rules: Vec<String>,
}

impl RuleEngine {
    /// Create an engine with no rules.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Number of loaded rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True when no rules are loaded.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}
