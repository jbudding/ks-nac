mod auth;
mod config;
mod handlers;
mod logging;
mod models;
mod radius;
mod rules;

use auth::{Authenticator, JsonBackend, MemoryBackend};
use config::ServerConfig;
use handlers::{AuthHandler, AcctHandler};
use logging::SessionLogger;
use models::{Client, GroupStore};
use rules::RulesEngine;

use anyhow::Result;
use clap::Parser;
use crate::radius::RadiusPacket;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{info, warn};
use tracing_subscriber;

#[derive(Parser)]
#[command(name = "radius-server")]
#[command(about = "A RADIUS server implementation in Rust")]
struct Args {
    #[arg(short, long, default_value = "config/config.yaml")]
    config: String,

    #[arg(short, long, default_value = "info")]
    log_level: String,
}

struct RadiusServer {
    config: ServerConfig,
    auth_handler: Arc<AuthHandler>,
    acct_handler: Arc<AcctHandler>,
    clients: HashMap<IpAddr, Client>,
    session_logger: Arc<SessionLogger>,
}

impl RadiusServer {
    pub async fn new(config_path: &str) -> Result<Self> {
        let config = match ServerConfig::load_from_file(config_path) {
            Ok(config) => config,
            Err(_) => {
                warn!("Could not load config file, using defaults");
                ServerConfig::default()
            }
        };

        // Load user groups
        let user_groups = match GroupStore::load_from_file("config/user_groups.json") {
            Ok(store) => {
                info!("User groups loaded: {} group(s)", store.len());
                store.log_groups();
                Some(store)
            }
            Err(e) => {
                warn!("Could not load user groups: {}", e);
                None
            }
        };

        // Load MAB groups
        let mab_groups = match GroupStore::load_from_file("config/mab_groups.json") {
            Ok(store) => {
                info!("MAB groups loaded: {} group(s)", store.len());
                store.log_groups();
                Some(store)
            }
            Err(e) => {
                warn!("Could not load MAB groups: {}", e);
                None
            }
        };

        let backend: Arc<dyn auth::AuthBackend> =
            match JsonBackend::load_with_groups("config/users.json", user_groups) {
                Ok(b) => {
                    info!("User database loaded from config/users.json");
                    Arc::new(b)
                }
                Err(e) => {
                    warn!("Could not load config/users.json ({}), using built-in test users", e);
                    Arc::new(MemoryBackend::new())
                }
            };
        // Load rules engine
        let rules_engine = match RulesEngine::load_from_file("config/rules.json") {
            Ok(engine) => {
                engine.log_rules();
                Some(engine)
            }
            Err(e) => {
                warn!("Could not load rules: {} (rules disabled)", e);
                None
            }
        };

        let authenticator = Arc::new(Authenticator::new(backend));
        let auth_handler = Arc::new(AuthHandler::new_with_rules(
            authenticator,
            "config/mab_users.json",
            "config/dictionaries.json",
            mab_groups,
            rules_engine,
        )?);
        let acct_handler = Arc::new(AcctHandler::new()?);

        // Create session logger
        let session_logger = Arc::new(
            SessionLogger::new("logs/session.log")
                .unwrap_or_else(|e| {
                    // Try creating logs directory and retry
                    let _ = std::fs::create_dir_all("logs");
                    SessionLogger::new("logs/session.log")
                        .expect(&format!("Failed to create session log: {}", e))
                })
        );
        session_logger.write_header_if_empty();
        info!("Session logging to {}", session_logger.path());

        let mut clients = HashMap::new();
        for client in &config.clients {
            clients.insert(client.ip_address, client.clone());
        }

        Ok(Self {
            config,
            auth_handler,
            acct_handler,
            clients,
            session_logger,
        })
    }

    pub async fn run(&self) -> Result<()> {
        info!("Starting RADIUS server");
        info!("Auth port: {}", self.config.server.auth_port);
        info!("Acct port: {}", self.config.server.acct_port);

        let auth_addr = SocketAddr::new(self.config.server.bind_address, self.config.server.auth_port);
        let acct_addr = SocketAddr::new(self.config.server.bind_address, self.config.server.acct_port);

        let auth_socket = Arc::new(UdpSocket::bind(auth_addr).await?);
        let acct_socket = Arc::new(UdpSocket::bind(acct_addr).await?);

        info!("RADIUS server listening on auth: {}, acct: {}", auth_addr, acct_addr);

        let auth_task = self.handle_auth_requests(auth_socket);
        let acct_task = self.handle_acct_requests(acct_socket);

        tokio::try_join!(auth_task, acct_task)?;

        Ok(())
    }

    async fn handle_auth_requests(&self, socket: Arc<UdpSocket>) -> Result<()> {
        let mut buf = [0u8; 4096];

        loop {
            let (len, addr) = socket.recv_from(&mut buf).await?;
            let data = buf[..len].to_vec();

            let client_ip = addr.ip();
            if let Some(client) = self.clients.get(&client_ip) {
                let auth_handler = self.auth_handler.clone();
                let client = client.clone();
                let socket = socket.clone();
                let session_logger = self.session_logger.clone();

                tokio::spawn(async move {
                    if let Err(e) = Self::process_auth_packet(&data, client, addr, auth_handler, socket, session_logger).await {
                        tracing::error!("Error processing auth packet: {}", e);
                    }
                });
            } else {
                warn!("Received packet from unknown client: {}", client_ip);
            }
        }
    }

    async fn handle_acct_requests(&self, socket: Arc<UdpSocket>) -> Result<()> {
        let mut buf = [0u8; 4096];

        loop {
            let (len, addr) = socket.recv_from(&mut buf).await?;
            let data = buf[..len].to_vec();

            let client_ip = addr.ip();
            if let Some(client) = self.clients.get(&client_ip) {
                let acct_handler = self.acct_handler.clone();
                let client = client.clone();
                let socket = socket.clone();

                tokio::spawn(async move {
                    if let Err(e) = Self::process_acct_packet(&data, client, addr, acct_handler, socket).await {
                        tracing::error!("Error processing acct packet: {}", e);
                    }
                });
            } else {
                warn!("Received packet from unknown client: {}", client_ip);
            }
        }
    }

    async fn process_auth_packet(
        data: &[u8],
        client: Client,
        addr: SocketAddr,
        auth_handler: Arc<AuthHandler>,
        socket: Arc<UdpSocket>,
        session_logger: Arc<SessionLogger>,
    ) -> Result<()> {
        use crate::radius::attributes::{CALLED_STATION_ID, CALLING_STATION_ID, FILTER_ID};

        let packet = RadiusPacket::from_bytes(data)?;
        let username = packet.get_string_attribute(1).unwrap_or_else(|| "<unknown>".to_string());
        let calling_station_id = packet.get_string_attribute(CALLING_STATION_ID);
        let called_station_id = packet.get_string_attribute(CALLED_STATION_ID);

        info!(
            src = %addr,
            code = ?packet.code,
            id = packet.identifier,
            username = %username,
            "auth request"
        );
        packet.log_attributes_with_dict(Some(auth_handler.dictionary()));
        let response = auth_handler.handle_request(&packet, &client, addr).await?;

        // Get result and filter-id from response
        let result = format!("{:?}", response.code);
        let filter_id = response.get_string_attribute(FILTER_ID);

        info!(
            src = %addr,
            id = response.identifier,
            code = ?response.code,
            "auth response"
        );

        // Log to session file
        session_logger.log_auth(
            &username,
            calling_station_id.as_deref(),
            called_station_id.as_deref(),
            &result,
            filter_id.as_deref(),
        );

        let response_data = response.to_bytes();
        socket.send_to(&response_data, addr).await?;
        Ok(())
    }

    async fn process_acct_packet(
        data: &[u8],
        client: Client,
        addr: SocketAddr,
        acct_handler: Arc<AcctHandler>,
        socket: Arc<UdpSocket>,
    ) -> Result<()> {
        let packet = RadiusPacket::from_bytes(data)?;
        let username = packet.get_string_attribute(1).unwrap_or_else(|| "<unknown>".to_string());
        info!(
            src = %addr,
            code = ?packet.code,
            id = packet.identifier,
            username = %username,
            "acct request"
        );
        packet.log_attributes_with_dict(Some(acct_handler.dictionary()));
        let response = acct_handler.handle_request(&packet, &client, addr).await?;
        info!(
            src = %addr,
            id = response.identifier,
            code = ?response.code,
            "acct response"
        );
        let response_data = response.to_bytes();
        socket.send_to(&response_data, addr).await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(args.log_level)
        .init();

    let server = RadiusServer::new(&args.config).await?;
    server.run().await?;

    Ok(())
}