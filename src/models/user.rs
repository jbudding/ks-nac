use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
    pub enabled: bool,
    pub attributes: HashMap<String, String>,
}

impl User {
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password,
            enabled: true,
            attributes: HashMap::new(),
        }
    }

    pub fn verify_password(&self, password: &str) -> bool {
        self.enabled && self.password == password
    }

    pub fn add_attribute(&mut self, key: String, value: String) {
        self.attributes.insert(key, value);
    }
}