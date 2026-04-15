use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MabEntry {
    pub mac_address: String,
    pub description: Option<String>,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MabUserList {
    mab_users: Vec<MabEntry>,
}

pub struct MabList {
    /// Key: normalized MAC address (12 lowercase hex chars, no separators)
    entries: HashMap<String, MabEntry>,
}

impl MabList {
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let list: MabUserList = serde_json::from_str(&content)?;
        let mut entries = HashMap::new();
        for entry in list.mab_users {
            let key = normalize_mac(&entry.mac_address);
            entries.insert(key, entry);
        }
        Ok(Self { entries })
    }

    pub fn lookup(&self, mac: &str) -> Option<&MabEntry> {
        let key = normalize_mac(mac);
        self.entries.get(&key)
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
