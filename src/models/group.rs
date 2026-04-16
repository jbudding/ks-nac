use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use tracing::info;

/// A group defines a set of RADIUS attributes that can be shared by users or MAB entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct GroupFile {
    groups: Vec<Group>,
}

/// Store for user and MAB groups loaded from JSON configuration.
#[derive(Debug, Clone)]
pub struct GroupStore {
    groups: HashMap<String, Group>,
}

impl GroupStore {
    /// Create an empty group store.
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }

    /// Load groups from a JSON file.
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let file: GroupFile = serde_json::from_str(&content)?;
        let mut groups = HashMap::new();
        for group in file.groups {
            groups.insert(group.name.clone(), group);
        }
        Ok(Self { groups })
    }

    /// Get a group by name.
    pub fn get(&self, name: &str) -> Option<&Group> {
        self.groups.get(name)
    }

    /// Get the number of loaded groups.
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Get all group names.
    pub fn names(&self) -> Vec<&str> {
        self.groups.keys().map(|s| s.as_str()).collect()
    }

    /// Get all groups.
    pub fn iter(&self) -> impl Iterator<Item = &Group> {
        self.groups.values()
    }

    /// Resolve attributes for a group name, returning empty map if not found.
    pub fn resolve_attributes(&self, group_name: &str) -> HashMap<String, String> {
        self.groups
            .get(group_name)
            .map(|g| g.attributes.clone())
            .unwrap_or_default()
    }

    /// Log loaded groups to console.
    pub fn log_groups(&self) {
        if self.groups.is_empty() {
            return;
        }
        info!("Loaded {} group(s):", self.groups.len());
        for group in self.groups.values() {
            let desc = group.description.as_deref().unwrap_or("");
            let attr_count = group.attributes.len();
            info!(
                "  - {} ({} attributes){}",
                group.name,
                attr_count,
                if desc.is_empty() { String::new() } else { format!(" - {}", desc) }
            );
        }
    }
}

impl Default for GroupStore {
    fn default() -> Self {
        Self::new()
    }
}
