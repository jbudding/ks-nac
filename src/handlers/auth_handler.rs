use crate::auth::{Authenticator, MabList, MabEntry, is_mac_address};
use crate::models::Client;
use crate::radius::{RadiusPacket, Code, Dictionary, attributes::*};
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn, debug};

pub struct AuthHandler {
    authenticator: Arc<Authenticator>,
    dictionary: Dictionary,
    mab_list: Option<MabList>,
}

impl AuthHandler {
    pub fn new(authenticator: Arc<Authenticator>) -> Result<Self> {
        Self::new_with_mab(authenticator, "config/mab_users.json")
    }

    pub fn new_with_mab(authenticator: Arc<Authenticator>, mab_path: &str) -> Result<Self> {
        let dictionary = Dictionary::new();
        let mab_list = match MabList::load_from_file(mab_path) {
            Ok(list) => {
                info!("MAB user list loaded from {}", mab_path);
                Some(list)
            }
            Err(e) => {
                warn!("Could not load MAB user list from {}: {}", mab_path, e);
                None
            }
        };
        Ok(Self {
            authenticator,
            dictionary,
            mab_list,
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

        // EAP-based auth (attribute 79) is not supported; reject cleanly
        if packet.get_attribute(EAP_MESSAGE).is_some() {
            warn!(
                src = %addr,
                username = %username,
                "EAP authentication not supported, rejecting"
            );
            return self.create_access_reject(packet, client);
        }

        // MAB: if User-Name looks like a MAC address, check the MAB list
        if is_mac_address(&username) {
            return self.handle_mab_request(packet, client, addr, &username);
        }

        let password = match packet.decrypt_user_password(&client.shared_secret) {
            Some(p) => p,
            None => {
                debug!(
                    src = %addr,
                    username = %username,
                    "No supported auth attribute (User-Password/EAP-Message), rejecting"
                );
                return self.create_access_reject(packet, client);
            }
        };

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

    fn handle_mab_request(
        &self,
        packet: &RadiusPacket,
        client: &Client,
        addr: SocketAddr,
        mac: &str,
    ) -> Result<RadiusPacket> {
        match &self.mab_list {
            Some(list) => match list.lookup(mac) {
                Some(entry) => {
                    info!(
                        src = %addr,
                        mac = %mac,
                        "MAB accept"
                    );
                    self.create_mab_accept(packet, entry, client)
                }
                None => {
                    warn!(
                        src = %addr,
                        mac = %mac,
                        "MAB reject: MAC not in list"
                    );
                    self.create_access_reject(packet, client)
                }
            },
            None => {
                warn!(
                    src = %addr,
                    mac = %mac,
                    "MAB reject: no MAB list loaded"
                );
                self.create_access_reject(packet, client)
            }
        }
    }

    fn create_mab_accept(&self, request: &RadiusPacket, entry: &MabEntry, client: &Client) -> Result<RadiusPacket> {
        let mut response = RadiusPacket::new(Code::AccessAccept, request.identifier);

        for (key, value) in &entry.attributes {
            if let Some(attr_type) = self.dictionary.get_attribute_type(key) {
                response.add_string_attribute(attr_type, value);
            }
        }

        response.calculate_response_authenticator(&request.authenticator, &client.shared_secret);
        Ok(response)
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
