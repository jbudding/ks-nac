use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use crate::models::Client;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub server: ServerSettings,
    pub logging: LoggingConfig,
    pub clients: Vec<Client>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub bind_address: IpAddr,
    pub auth_port: u16,
    pub acct_port: u16,
    pub max_clients: usize,
    pub request_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server: ServerSettings {
                bind_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                auth_port: 1812,
                acct_port: 1813,
                max_clients: 1000,
                request_timeout: 30,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file: None,
            },
            clients: vec![],
        }
    }
}

impl ServerConfig {
    pub fn load_from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: ServerConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }
}