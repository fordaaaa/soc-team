//! Event store skeleton.
//!
//! The DuckDB backend lands in Phase 1.

/// Embedded event/flow store.
pub trait EventStore {
    /// Insert one event (stub).
    fn insert(&mut self, event: &str);
    /// Query events (stub).
    fn query(&self, q: &str) -> Vec<String>;
}
