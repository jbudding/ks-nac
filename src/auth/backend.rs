use async_trait::async_trait;
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