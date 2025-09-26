use crate::auth::Authenticator;
use crate::models::Client;
use crate::radius::{RadiusPacket, Code, Dictionary, attributes::*};
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

pub struct AuthHandler {
    authenticator: Arc<Authenticator>,
    dictionary: Dictionary,
}

impl AuthHandler {
    pub fn new(authenticator: Arc<Authenticator>) -> Result<Self> {
        let dictionary = Dictionary::new();
        Ok(Self {
            authenticator,
            dictionary,
        })
    }

    pub async fn handle_request(
        &self,
        packet: &RadiusPacket,
        client: &Client,
        addr: SocketAddr,
    ) -> Result<RadiusPacket> {
        match packet.code {
            Code::AccessRequest => self.handle_access_request(packet, client, addr).await,
            _ => {
                warn!("Unsupported packet type: {:?}", packet.code);
                Err(anyhow::anyhow!("Unsupported packet type"))
            }
        }
    }

    async fn handle_access_request(
        &self,
        packet: &RadiusPacket,
        client: &Client,
        addr: SocketAddr,
    ) -> Result<RadiusPacket> {
        let username = packet
            .get_string_attribute(USER_NAME)
            .ok_or_else(|| anyhow::anyhow!("Missing User-Name attribute"))?;

        let password = packet
            .get_string_attribute(USER_PASSWORD)
            .ok_or_else(|| anyhow::anyhow!("Missing User-Password attribute"))?;

        info!("Authentication request for user: {} from {}", username, addr);

        match self.authenticator.authenticate(&username, &password).await? {
            Some(user) => {
                info!("User {} authenticated successfully", username);
                self.create_access_accept(packet, &user, client)
            }
            None => {
                warn!("Authentication failed for user: {}", username);
                self.create_access_reject(packet, client)
            }
        }
    }

    fn create_access_accept(&self, request: &RadiusPacket, user: &crate::models::User, client: &Client) -> Result<RadiusPacket> {
        let mut response = RadiusPacket::new(Code::AccessAccept, request.identifier);

        for (key, value) in &user.attributes {
            if let Some(attr_type) = self.dictionary.get_attribute_type(key) {
                response.add_string_attribute(attr_type, value);
            }
        }

        response.calculate_response_authenticator(&request.authenticator, &client.shared_secret);
        Ok(response)
    }

    fn create_access_reject(&self, request: &RadiusPacket, client: &Client) -> Result<RadiusPacket> {
        let mut response = RadiusPacket::new(Code::AccessReject, request.identifier);
        response.calculate_response_authenticator(&request.authenticator, &client.shared_secret);
        Ok(response)
    }
}