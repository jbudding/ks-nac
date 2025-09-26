use crate::models::{Client, Session};
use crate::radius::{RadiusPacket, Code, Dictionary, attributes::*};
use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

pub struct AcctHandler {
    dictionary: Dictionary,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

impl AcctHandler {
    pub fn new() -> Result<Self> {
        let dictionary = Dictionary::new();
        Ok(Self {
            dictionary,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn handle_request(
        &self,
        packet: &RadiusPacket,
        client: &Client,
        addr: SocketAddr,
    ) -> Result<RadiusPacket> {
        match packet.code {
            Code::AccountingRequest => self.handle_accounting_request(packet, client, addr).await,
            _ => {
                warn!("Unsupported accounting packet type: {:?}", packet.code);
                Err(anyhow::anyhow!("Unsupported packet type"))
            }
        }
    }

    async fn handle_accounting_request(
        &self,
        packet: &RadiusPacket,
        client: &Client,
        addr: SocketAddr,
    ) -> Result<RadiusPacket> {
        let username = packet
            .get_string_attribute(USER_NAME)
            .ok_or_else(|| anyhow::anyhow!("Missing User-Name attribute"))?;

        let session_id = packet
            .get_string_attribute(ACCT_SESSION_ID)
            .ok_or_else(|| anyhow::anyhow!("Missing Acct-Session-Id attribute"))?;

        let status_type = packet
            .get_attribute(ACCT_STATUS_TYPE)
            .and_then(|attr| attr.as_u32())
            .unwrap_or(0);

        info!(
            "Accounting request for user: {} session: {} status: {} from {}",
            username, session_id, status_type, addr
        );

        match status_type {
            ACCT_STATUS_START => self.handle_session_start(&username, &session_id, addr).await?,
            ACCT_STATUS_STOP => self.handle_session_stop(&session_id).await?,
            ACCT_STATUS_INTERIM_UPDATE => self.handle_session_update(&session_id).await?,
            _ => warn!("Unknown accounting status type: {}", status_type),
        }

        self.create_accounting_response(packet, client)
    }

    async fn handle_session_start(&self, username: &str, session_id: &str, addr: SocketAddr) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = Session::new(username.to_string(), addr.ip(), addr.ip());
        sessions.insert(session_id.to_string(), session);
        info!("Session started for user: {} session: {}", username, session_id);
        Ok(())
    }

    async fn handle_session_stop(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(mut session) = sessions.remove(session_id) {
            session.terminate();
            info!("Session stopped: {}", session_id);
        }
        Ok(())
    }

    async fn handle_session_update(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            session.update_activity();
            info!("Session updated: {}", session_id);
        }
        Ok(())
    }

    fn create_accounting_response(&self, request: &RadiusPacket, client: &Client) -> Result<RadiusPacket> {
        let mut response = RadiusPacket::new(Code::AccountingResponse, request.identifier);
        response.calculate_response_authenticator(&request.authenticator, &client.shared_secret);
        Ok(response)
    }
}