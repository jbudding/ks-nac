use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MabEntry {
    pub mac_address: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

impl MabEntry {
    pub fn is_in_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| g.eq_ignore_ascii_case(group))
    }
}

/// Strip all non-hex characters and lowercase — accepts any common MAC format.
pub fn normalize_mac(mac: &str) -> String {
    mac.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_lowercase()
}

/// Returns true if the string, after normalization, is exactly 12 hex digits.
pub fn is_mac_address(s: &str) -> bool {
    let n = normalize_mac(s);
    n.len() == 12
}
