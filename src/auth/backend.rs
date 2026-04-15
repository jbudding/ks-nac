use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use crate::models::User;
use anyhow::Result;

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
    #[serde(default)]
    attributes: HashMap<String, String>,
}

fn default_true() -> bool { true }

pub struct JsonBackend {
    users: HashMap<String, User>,
}

impl JsonBackend {
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let file: UserFile = serde_json::from_str(&content)?;
        let mut users = HashMap::new();
        for entry in file.users {
            let mut user = User::new(entry.username.clone(), entry.password);
            user.enabled = entry.enabled;
            for (k, v) in entry.attributes {
                user.add_attribute(k, v);
            }
            users.insert(entry.username, user);
        }
        Ok(Self { users })
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