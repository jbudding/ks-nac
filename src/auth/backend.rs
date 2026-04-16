use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use crate::models::{User, GroupStore};
use anyhow::Result;
use tracing::warn;

#[async_trait]
pub trait AuthBackend: Send + Sync {
    async fn authenticate(&self, username: &str, password: &str) -> Result<Option<User>>;
    async fn get_user(&self, username: &str) -> Result<Option<User>>;
}

pub struct MemoryBackend {
    users: HashMap<String, User>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        let mut users = HashMap::new();

        let mut test_user = User::new("testuser".to_string(), "testpass".to_string());
        test_user.add_attribute("Service-Type".to_string(), "Framed-User".to_string());
        users.insert("testuser".to_string(), test_user);

        Self { users }
    }

    pub fn add_user(&mut self, user: User) {
        self.users.insert(user.username.clone(), user);
    }
}

#[async_trait]
impl AuthBackend for MemoryBackend {
    async fn authenticate(&self, username: &str, password: &str) -> Result<Option<User>> {
        if let Some(user) = self.users.get(username) {
            if user.verify_password(password) {
                return Ok(Some(user.clone()));
            }
        }
        Ok(None)
    }

    async fn get_user(&self, username: &str) -> Result<Option<User>> {
        Ok(self.users.get(username).cloned())
    }
}

// ---------------------------------------------------------------------------
// JSON file backend
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct UserFile {
    users: Vec<UserEntry>,
}

#[derive(Deserialize)]
struct UserEntry {
    username: String,
    password: String,
    #[serde(default = "default_true")]
    enabled: bool,
    /// Optional group name to inherit attributes from.
    #[serde(default)]
    group: Option<String>,
    /// Direct attributes (merged with group attributes, overriding on conflict).
    #[serde(default)]
    attributes: HashMap<String, String>,
}

fn default_true() -> bool { true }

pub struct JsonBackend {
    users: HashMap<String, User>,
    group_store: GroupStore,
}

impl JsonBackend {
    /// Load users from file without group support.
    pub fn load_from_file(path: &str) -> Result<Self> {
        Self::load_with_groups(path, None)
    }

    /// Load users from file with optional group store for attribute inheritance.
    pub fn load_with_groups(path: &str, group_store: Option<GroupStore>) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let file: UserFile = serde_json::from_str(&content)?;
        let group_store = group_store.unwrap_or_default();
        let mut users = HashMap::new();

        for entry in file.users {
            let mut user = User::new(entry.username.clone(), entry.password);
            user.enabled = entry.enabled;

            // First, apply group attributes if specified
            if let Some(ref group_name) = entry.group {
                if let Some(group) = group_store.get(group_name) {
                    for (k, v) in &group.attributes {
                        user.add_attribute(k.clone(), v.clone());
                    }
                } else {
                    warn!(
                        username = %entry.username,
                        group = %group_name,
                        "User references unknown group"
                    );
                }
            }

            // Then, apply direct attributes (override group attributes)
            for (k, v) in entry.attributes {
                user.add_attribute(k, v);
            }

            users.insert(entry.username, user);
        }

        Ok(Self { users, group_store })
    }

    /// Get a reference to the group store.
    pub fn group_store(&self) -> &GroupStore {
        &self.group_store
    }
}

#[async_trait]
impl AuthBackend for JsonBackend {
    async fn authenticate(&self, username: &str, password: &str) -> Result<Option<User>> {
        if let Some(user) = self.users.get(username) {
            if user.verify_password(password) {
                return Ok(Some(user.clone()));
            }
        }
        Ok(None)
    }

    async fn get_user(&self, username: &str) -> Result<Option<User>> {
        Ok(self.users.get(username).cloned())
    }
}