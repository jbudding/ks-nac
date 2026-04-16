use crate::auth::{
    Authenticator, MabList, MabEntry, is_mac_address,
    EapPacket, TtlsSession, create_tls_config,
    EAP_REQUEST, EAP_RESPONSE, EAP_SUCCESS, EAP_FAILURE, EAP_TYPE_IDENTITY, EAP_TYPE_TTLS,
};
use crate::models::{Client, GroupStore};
use crate::radius::{RadiusPacket, Code, Dictionary, attributes::*};
use anyhow::Result;
use rustls::server::ServerConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn, debug};

pub struct AuthHandler {
    authenticator: Arc<Authenticator>,
    dictionary: Dictionary,
    mab_list: Option<MabList>,
    /// In-flight EAP-TTLS sessions keyed by State attribute bytes.
    ttls_sessions: Arc<Mutex<HashMap<Vec<u8>, TtlsSession>>>,
    /// TLS server configuration.
    tls_config: Arc<ServerConfig>,
}

impl AuthHandler {
    pub fn new(authenticator: Arc<Authenticator>) -> Result<Self> {
        Self::new_with_mab(authenticator, "config/mab_users.json")
    }

    pub fn new_with_mab(authenticator: Arc<Authenticator>, mab_path: &str) -> Result<Self> {
        Self::new_with_config(authenticator, mab_path, "config/dictionaries.json")
    }

    pub fn new_with_config(authenticator: Arc<Authenticator>, mab_path: &str, dict_config_path: &str) -> Result<Self> {
        Self::new_with_groups(authenticator, mab_path, dict_config_path, None)
    }

    pub fn new_with_groups(
        authenticator: Arc<Authenticator>,
        mab_path: &str,
        dict_config_path: &str,
        mab_groups: Option<GroupStore>,
    ) -> Result<Self> {
        let dictionary = Dictionary::load(dict_config_path);
        info!("Loaded {} vendor dictionaries", dictionary.vendor_ids().len());

        let mab_list = match MabList::load_with_groups(mab_path, mab_groups) {
            Ok(list) => {
                info!("MAB user list loaded: {} entries from {}", list.len(), mab_path);
                Some(list)
            }
            Err(e) => {
                warn!("Could not load MAB user list from {}: {}", mab_path, e);
                None
            }
        };

        let tls_config = create_tls_config()?;
        info!("EAP-TTLS TLS configuration initialized");
        Ok(Self {
            authenticator,
            dictionary,
            mab_list,
            ttls_sessions: Arc::new(Mutex::new(HashMap::new())),
            tls_config,
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

        // --- EAP path ---
        if let Some(eap_data) = packet.get_concatenated_attribute(EAP_MESSAGE) {
            return self
                .handle_eap_request(packet, client, addr, &username, &eap_data)
                .await;
        }

        // --- MAB path ---
        if is_mac_address(&username) {
            return self.handle_mab_request(packet, client, addr, &username);
        }

        // --- PAP path ---
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

    // -------------------------------------------------------------------------
    // EAP-TTLS state machine
    // -------------------------------------------------------------------------

    async fn handle_eap_request(
        &self,
        packet: &RadiusPacket,
        client: &Client,
        addr: SocketAddr,
        username: &str,
        eap_data: &[u8],
    ) -> Result<RadiusPacket> {
        let eap = match EapPacket::from_bytes(eap_data) {
            Some(p) => p,
            None => {
                warn!(src = %addr, username = %username, "Malformed EAP packet, rejecting");
                return self.create_eap_reject(packet, client, 0);
            }
        };

        match (eap.code, eap.eap_type()) {
            // EAP-Response/Identity → start EAP-TTLS
            (EAP_RESPONSE, Some(EAP_TYPE_IDENTITY)) => {
                let identity = eap.identity().unwrap_or_else(|| username.to_string());
                debug!(src = %addr, identity = %identity, "EAP Identity received, starting TTLS");
                self.start_ttls(packet, client, &identity, eap.identifier).await
            }

            // EAP-Response/TTLS → process TLS handshake or inner auth
            (EAP_RESPONSE, Some(EAP_TYPE_TTLS)) => {
                self.process_ttls(packet, client, addr, username, &eap).await
            }

            _ => {
                warn!(
                    src = %addr,
                    username = %username,
                    eap_code = eap.code,
                    eap_type = ?eap.eap_type(),
                    "Unsupported EAP type, rejecting"
                );
                self.create_eap_reject(packet, client, eap.identifier)
            }
        }
    }

    async fn start_ttls(
        &self,
        request: &RadiusPacket,
        client: &Client,
        identity: &str,
        eap_id: u8,
    ) -> Result<RadiusPacket> {
        let next_eap_id = eap_id.wrapping_add(1);

        // Generate State token for session correlation
        let state: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();

        // Create new TTLS session
        let session = TtlsSession::new(self.tls_config.clone(), next_eap_id)?;

        {
            let mut sessions = self.ttls_sessions.lock().await;
            // Remove any stale sessions for this identity
            sessions.retain(|_, s| s.inner_username.as_deref() != Some(identity));
            sessions.insert(state.clone(), session);
        }

        // Build EAP-Request/TTLS Start
        let eap_ttls_start = TtlsSession::start_packet(next_eap_id);
        let eap_pkt = EapPacket {
            code: EAP_REQUEST,
            identifier: next_eap_id,
            data: eap_ttls_start,
        };

        debug!(identity = %identity, "Sending EAP-TTLS Start");

        let mut response = RadiusPacket::new(Code::AccessChallenge, request.identifier);
        response.add_attribute(EAP_MESSAGE, eap_pkt.to_bytes());
        response.add_attribute(STATE, state);
        response.finalize_with_message_authenticator(&request.authenticator, &client.shared_secret);
        Ok(response)
    }

    async fn process_ttls(
        &self,
        packet: &RadiusPacket,
        client: &Client,
        addr: SocketAddr,
        username: &str,
        eap: &EapPacket,
    ) -> Result<RadiusPacket> {
        let state_bytes = match packet.get_attribute(STATE) {
            Some(attr) => attr.value.clone(),
            None => {
                warn!(src = %addr, username = %username, "EAP-TTLS response missing State attribute");
                return self.create_eap_reject(packet, client, eap.identifier);
            }
        };

        // Get mutable session
        let mut sessions = self.ttls_sessions.lock().await;
        let session = match sessions.get_mut(&state_bytes) {
            Some(s) => s,
            None => {
                warn!(src = %addr, username = %username, "EAP-TTLS: unknown session State");
                return self.create_eap_reject(packet, client, eap.identifier);
            }
        };

        // Check for retransmit - same RADIUS id means client didn't get our response
        if session.last_radius_id == Some(packet.identifier) {
            if let Some(ref cached) = session.cached_response {
                debug!(src = %addr, "EAP-TTLS: retransmit detected, replaying cached response");
                let mut response = RadiusPacket::new(Code::AccessChallenge, packet.identifier);
                response.add_attribute(EAP_MESSAGE, cached.clone());
                response.add_attribute(STATE, state_bytes);
                drop(sessions);
                response.finalize_with_message_authenticator(&packet.authenticator, &client.shared_secret);
                return Ok(response);
            }
        }
        session.last_radius_id = Some(packet.identifier);

        // Extract TTLS data (skip EAP type byte)
        let ttls_data = if eap.data.len() > 1 { &eap.data[1..] } else { &[] };

        // Process TLS data
        let response_data = match session.process(ttls_data) {
            Ok(Some(data)) => data,
            Ok(None) => {
                // Inner auth complete - extract credentials and derive keys
                let inner_creds = session.inner_username.clone()
                    .zip(session.inner_password.clone());
                let key_material = session.derive_msk().ok();

                // Clean up session
                sessions.remove(&state_bytes);
                drop(sessions);

                // Verify credentials against backend
                if let (Some((inner_user, inner_pass)), Some(keys)) = (inner_creds, key_material) {
                    let auth_result = self.authenticator.authenticate(&inner_user, &inner_pass).await?;
                    if let Some(user) = auth_result {
                        info!(src = %addr, username = %inner_user, "EAP-TTLS authentication succeeded");
                        return self.create_eap_accept_with_msk(packet, &user, client, eap.identifier, &keys.msk);
                    }
                }

                warn!(src = %addr, username = %username, "EAP-TTLS inner auth failed");
                return self.create_eap_reject(packet, client, eap.identifier);
            }
            Err(e) => {
                warn!(src = %addr, username = %username, "EAP-TTLS error: {}", e);
                drop(sessions);
                return self.create_eap_reject(packet, client, eap.identifier);
            }
        };

        let next_eap_id = eap.identifier.wrapping_add(1);
        session.eap_id = next_eap_id;

        // Build EAP-Request/TTLS with TLS data
        let eap_pkt = EapPacket {
            code: EAP_REQUEST,
            identifier: next_eap_id,
            data: response_data,
        };

        let eap_bytes = eap_pkt.to_bytes();
        session.cached_response = Some(eap_bytes.clone());

        // Keep the same State throughout the TTLS session
        drop(sessions);

        debug!(src = %addr, "EAP-TTLS: continuing handshake");

        let mut response = RadiusPacket::new(Code::AccessChallenge, packet.identifier);
        response.add_attribute(EAP_MESSAGE, eap_bytes);
        response.add_attribute(STATE, state_bytes);
        response.finalize_with_message_authenticator(&packet.authenticator, &client.shared_secret);
        Ok(response)
    }

    fn create_eap_accept_with_msk(
        &self,
        request: &RadiusPacket,
        user: &crate::models::User,
        client: &Client,
        eap_id: u8,
        msk: &[u8; 64],
    ) -> Result<RadiusPacket> {
        let mut response = RadiusPacket::new(Code::AccessAccept, request.identifier);

        let eap_success = EapPacket::success(eap_id);
        response.add_attribute(EAP_MESSAGE, eap_success.to_bytes());

        // Add MS-MPPE-Recv-Key (first 32 bytes of MSK) as VSA
        let recv_key = self.encrypt_mppe_key(&msk[0..32], &request.authenticator, &client.shared_secret);
        response.add_attribute(VENDOR_SPECIFIC, self.build_mppe_vsa(MS_MPPE_RECV_KEY, &recv_key));

        // Add MS-MPPE-Send-Key (last 32 bytes of MSK) as VSA
        let send_key = self.encrypt_mppe_key(&msk[32..64], &request.authenticator, &client.shared_secret);
        response.add_attribute(VENDOR_SPECIFIC, self.build_mppe_vsa(MS_MPPE_SEND_KEY, &send_key));

        let filter_id = user.attributes.get("Filter-Id");
        for (key, value) in &user.attributes {
            if let Some(attr_type) = self.dictionary.get_attribute_type(key) {
                response.add_string_attribute(attr_type, value);
            } else {
                warn!(attribute = %key, "Unknown attribute in user, skipping");
            }
        }
        if let Some(filter) = filter_id {
            info!(filter_id = %filter, "Returning Filter-Id in EAP accept");
        }

        response.finalize_with_message_authenticator(&request.authenticator, &client.shared_secret);
        Ok(response)
    }

    /// Build a Microsoft vendor-specific attribute for MPPE keys.
    fn build_mppe_vsa(&self, vendor_type: u8, encrypted_key: &[u8]) -> Vec<u8> {
        let mut vsa = Vec::new();
        // Vendor-Id (4 bytes): Microsoft = 311
        vsa.extend_from_slice(&VENDOR_MICROSOFT.to_be_bytes());
        // Vendor-Type (1 byte)
        vsa.push(vendor_type);
        // Vendor-Length (1 byte): type + length + data
        vsa.push((2 + encrypted_key.len()) as u8);
        // Encrypted key data
        vsa.extend_from_slice(encrypted_key);
        vsa
    }

    /// Encrypt MPPE key per RFC 2548 §2.4.2
    fn encrypt_mppe_key(&self, key: &[u8], authenticator: &[u8; 16], secret: &str) -> Vec<u8> {
        let mut result = Vec::new();

        // Salt: 2 bytes, high bit of first byte must be 1
        let salt: [u8; 2] = [rand::random::<u8>() | 0x80, rand::random()];
        result.extend_from_slice(&salt);

        // Plaintext: Key-Length (1 byte) + Key + Padding to 16-byte boundary
        let mut plaintext = vec![key.len() as u8];
        plaintext.extend_from_slice(key);
        while plaintext.len() % 16 != 0 {
            plaintext.push(0);
        }

        // Encrypt in 16-byte blocks
        let secret_bytes = secret.as_bytes();
        let mut prev_block: Vec<u8> = Vec::new();
        prev_block.extend_from_slice(secret_bytes);
        prev_block.extend_from_slice(authenticator);
        prev_block.extend_from_slice(&salt);

        for chunk in plaintext.chunks(16) {
            let hash = md5::compute(&prev_block);
            let encrypted: Vec<u8> = chunk.iter().zip(hash.0.iter()).map(|(p, h)| p ^ h).collect();
            result.extend_from_slice(&encrypted);

            prev_block.clear();
            prev_block.extend_from_slice(secret_bytes);
            prev_block.extend_from_slice(&encrypted);
        }

        result
    }

    fn create_eap_reject(
        &self,
        request: &RadiusPacket,
        client: &Client,
        eap_id: u8,
    ) -> Result<RadiusPacket> {
        let mut response = RadiusPacket::new(Code::AccessReject, request.identifier);
        let eap_failure = EapPacket::failure(eap_id);
        response.add_attribute(EAP_MESSAGE, eap_failure.to_bytes());
        response.finalize_with_message_authenticator(&request.authenticator, &client.shared_secret);
        Ok(response)
    }

    // -------------------------------------------------------------------------
    // MAB
    // -------------------------------------------------------------------------

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
                    info!(src = %addr, mac = %mac, "MAB accept");
                    self.create_mab_accept(packet, entry, client)
                }
                None => {
                    warn!(src = %addr, mac = %mac, "MAB reject: MAC not in list");
                    self.create_access_reject(packet, client)
                }
            },
            None => {
                warn!(src = %addr, mac = %mac, "MAB reject: no MAB list loaded");
                self.create_access_reject(packet, client)
            }
        }
    }

    fn create_mab_accept(&self, request: &RadiusPacket, entry: &MabEntry, client: &Client) -> Result<RadiusPacket> {
        let mut response = RadiusPacket::new(Code::AccessAccept, request.identifier);
        let filter_id = entry.attributes.get("Filter-Id");
        for (key, value) in &entry.attributes {
            if let Some(attr_type) = self.dictionary.get_attribute_type(key) {
                response.add_string_attribute(attr_type, value);
            } else {
                warn!(attribute = %key, "Unknown attribute in MAB entry, skipping");
            }
        }
        if let Some(filter) = filter_id {
            info!(filter_id = %filter, "Returning Filter-Id in MAB accept");
        }
        response.calculate_response_authenticator(&request.authenticator, &client.shared_secret);
        Ok(response)
    }

    // -------------------------------------------------------------------------
    // PAP
    // -------------------------------------------------------------------------

    fn create_access_accept(&self, request: &RadiusPacket, user: &crate::models::User, client: &Client) -> Result<RadiusPacket> {
        let mut response = RadiusPacket::new(Code::AccessAccept, request.identifier);
        let filter_id = user.attributes.get("Filter-Id");
        for (key, value) in &user.attributes {
            if let Some(attr_type) = self.dictionary.get_attribute_type(key) {
                response.add_string_attribute(attr_type, value);
            } else {
                warn!(attribute = %key, "Unknown attribute in user, skipping");
            }
        }
        if let Some(filter) = filter_id {
            info!(filter_id = %filter, "Returning Filter-Id in user accept");
        }
        response.calculate_response_authenticator(&request.authenticator, &client.shared_secret);
        Ok(response)
    }

    fn create_access_reject(&self, request: &RadiusPacket, client: &Client) -> Result<RadiusPacket> {
        let mut response = RadiusPacket::new(Code::AccessReject, request.identifier);
        response.calculate_response_authenticator(&request.authenticator, &client.shared_secret);
        Ok(response)
    }

    /// Get a reference to the dictionary for attribute logging.
    pub fn dictionary(&self) -> &Dictionary {
        &self.dictionary
    }
}
