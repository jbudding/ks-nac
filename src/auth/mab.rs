use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::models::GroupStore;
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MabEntry {
    pub mac_address: String,
    pub description: Option<String>,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MabUserList {
    mab_users: Vec<MabFileEntry>,
}

/// Entry as stored in the JSON file (with optional group reference).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MabFileEntry {
    mac_address: String,
    #[serde(default)]
    description: Option<String>,
    /// Optional group name to inherit attributes from.
    #[serde(default)]
    group: Option<String>,
    /// Direct attributes (merged with group attributes, overriding on conflict).
    #[serde(default)]
    attributes: HashMap<String, String>,
}

pub struct MabList {
    /// Key: normalized MAC address (12 lowercase hex chars, no separators)
    entries: HashMap<String, MabEntry>,
    group_store: GroupStore,
}

impl MabList {
    /// Load MAB entries from file without group support.
    pub fn load_from_file(path: &str) -> Result<Self> {
        Self::load_with_groups(path, None)
    }

    /// Load MAB entries from file with optional group store for attribute inheritance.
    pub fn load_with_groups(path: &str, group_store: Option<GroupStore>) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let list: MabUserList = serde_json::from_str(&content)?;
        let group_store = group_store.unwrap_or_default();
        let mut entries = HashMap::new();

        for file_entry in list.mab_users {
            let mut attributes = HashMap::new();

            // First, apply group attributes if specified
            if let Some(ref group_name) = file_entry.group {
                if let Some(group) = group_store.get(group_name) {
                    for (k, v) in &group.attributes {
                        attributes.insert(k.clone(), v.clone());
                    }
                } else {
                    warn!(
                        mac = %file_entry.mac_address,
                        group = %group_name,
                        "MAB entry references unknown group"
                    );
                }
            }

            // Then, apply direct attributes (override group attributes)
            for (k, v) in file_entry.attributes {
                attributes.insert(k, v);
            }

            let entry = MabEntry {
                mac_address: file_entry.mac_address.clone(),
                description: file_entry.description,
                attributes,
            };

            let key = normalize_mac(&file_entry.mac_address);
            entries.insert(key, entry);
        }

        Ok(Self { entries, group_store })
    }

    pub fn lookup(&self, mac: &str) -> Option<&MabEntry> {
        let key = normalize_mac(mac);
        self.entries.get(&key)
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get a reference to the group store.
    pub fn group_store(&self) -> &GroupStore {
        &self.group_store
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
