use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use tracing::info;

use crate::models::User;
use crate::auth::mab::{MabEntry, normalize_mac};

#[derive(Debug, Deserialize)]
struct LocalDbFile {
    #[serde(default)]
    entries: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Entry {
    User {
        username: String,
        password: String,
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(default)]
        groups: Vec<String>,
    },
    Mab {
        mac_address: String,
        #[serde(default)]
        description: Option<String>,
        #[serde(default)]
        groups: Vec<String>,
    },
}

fn default_true() -> bool { true }

/// Combined local database for users and MAB entries.
pub struct LocalDatabase {
    users: HashMap<String, User>,
    mab_entries: HashMap<String, MabEntry>,
}

impl LocalDatabase {
    /// Load from the consolidated database file.
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let file: LocalDbFile = serde_json::from_str(&content)?;

        let mut users = HashMap::new();
        let mut mab_entries = HashMap::new();

        for entry in file.entries {
            match entry {
                Entry::User { username, password, enabled, groups } => {
                    let user = User {
                        username: username.clone(),
                        password,
                        enabled,
                        groups,
                    };
                    users.insert(username.to_lowercase(), user);
                }
                Entry::Mab { mac_address, description, groups } => {
                    let key = normalize_mac(&mac_address);
                    let entry = MabEntry {
                        mac_address,
                        description,
                        groups,
                    };
                    mab_entries.insert(key, entry);
                }
            }
        }

        Ok(Self { users, mab_entries })
    }

    /// Authenticate a user by username and password.
    pub fn authenticate(&self, username: &str, password: &str) -> Option<&User> {
        self.users
            .get(&username.to_lowercase())
            .filter(|u| u.verify_password(password))
    }

    /// Get a user by username.
    pub fn get_user(&self, username: &str) -> Option<&User> {
        self.users.get(&username.to_lowercase())
    }

    /// Lookup a MAB entry by MAC address.
    pub fn lookup_mab(&self, mac: &str) -> Option<&MabEntry> {
        let key = normalize_mac(mac);
        self.mab_entries.get(&key)
    }

    /// Get the number of users.
    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    /// Get the number of MAB entries.
    pub fn mab_count(&self) -> usize {
        self.mab_entries.len()
    }

    /// Log database summary.
    pub fn log_summary(&self) {
        info!(
            users = self.users.len(),
            mab_entries = self.mab_entries.len(),
            "Local database loaded"
        );
    }
}
