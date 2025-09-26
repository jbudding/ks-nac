use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub name: String,
    pub ip_address: IpAddr,
    pub shared_secret: String,
    pub nas_type: Option<String>,
    pub enabled: bool,
}

impl Client {
    pub fn new(name: String, ip_address: IpAddr, shared_secret: String) -> Self {
        Self {
            name,
            ip_address,
            shared_secret,
            nas_type: None,
            enabled: true,
        }
    }

    pub fn verify_secret(&self, secret: &str) -> bool {
        self.shared_secret == secret
    }
}