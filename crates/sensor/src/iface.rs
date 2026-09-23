//! Network interface helpers.

/// Return the names of all interfaces visible to `pnet::datalink`.
pub fn list_interfaces() -> Vec<String> {
    pnet::datalink::interfaces()
        .iter()
        .map(|i| i.name.clone())
        .collect()
}
