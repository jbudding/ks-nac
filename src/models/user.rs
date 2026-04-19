use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub groups: Vec<String>,
}

fn default_true() -> bool { true }

impl User {
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password,
            enabled: true,
            groups: Vec::new(),
        }
    }

    pub fn verify_password(&self, password: &str) -> bool {
        self.enabled && self.password == password
    }

    pub fn is_in_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| g.eq_ignore_ascii_case(group))
    }
}
