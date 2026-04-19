use crate::auth::{
    LocalDatabase, MabEntry, is_mac_address,
    EapPacket, TtlsSession, create_tls_config,
    EAP_REQUEST, EAP_RESPONSE, EAP_TYPE_IDENTITY, EAP_TYPE_TTLS,
};
use crate::models::Client;
use crate::radius::{RadiusPacket, Code, Dictionary, attributes::*};
use crate::rules::{RulesEngine, RuleResult};
use crate::rules::condition::EvalContext;
use anyhow::Result;
use rustls::server::ServerConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn, debug};

pub struct AuthHandler {
    local_db: Arc<LocalDatabase>,
    dictionary: Dictionary,
    /// In-flight EAP-TTLS sessions keyed by State attribute bytes.
    ttls_sessions: Arc<Mutex<HashMap<Vec<u8>, TtlsSession>>>,
    /// TLS server configuration.
    tls_config: Arc<ServerConfig>,
    /// Rules engine for policy evaluation.
    rules_engine: Option<RulesEngine>,
}

impl AuthHandler {
    pub fn new(
        local_db: Arc<LocalDatabase>,
        dict_config_path: &str,
        rules_engine: Option<RulesEngine>,
    ) -> Result<Self> {
        let dictionary = Dictionary::load(dict_config_path);
        info!("Loaded {} vendor dictionaries", dictionary.vendor_ids().len());

        let tls_config = create_tls_config()?;
        info!("EAP-TTLS TLS configuration initialized");

        if let Some(ref engine) = rules_engine {
            info!("Rules engine loaded: {} rule(s)", engine.enabled_rule_count());
        }

        Ok(Self {
            local_db,
            dictionary,
            ttls_sessions: Arc::new(Mutex::new(HashMap::new())),
            tls_config,
            rules_engine,
        })
    }

    pub async fn handle_request(
        &self,
        packet: &RadiusPacket,
        client: &Client,
        addr: SocketAddr,
    ) -> Result<(RadiusPacket, Option<String>, &'static str)> {
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
    ) -> Result<(RadiusPacket, Option<String>, &'static str)> {
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
                return Ok((self.create_reject(packet, client)?, None, "PAP"));
            }
        };

        match self.local_db.authenticate(&username, &password) {
            Some(user) => {
                info!(src = %addr, username = %username, "PAP authenticated");

                // Evaluate rules with user's groups
                let (should_accept, rule_filter_id, rule_attrs, rule_name) =
                    self.evaluate_rules(packet, &username, &user.groups, false);

                if should_accept {
                    info!(src = %addr, username = %username, "PAP accept");
                    let response = self.create_accept(packet, client, rule_filter_id, rule_attrs)?;
                    Ok((response, rule_name, "PAP"))
                } else {
                    warn!(src = %addr, username = %username, "PAP reject (rules)");
                    Ok((self.create_reject(packet, client)?, rule_name, "PAP"))
                }
            }
            None => {
                warn!(src = %addr, username = %username, "PAP reject (auth failed)");
                Ok((self.create_reject(packet, client)?, None, "PAP"))
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
    ) -> Result<(RadiusPacket, Option<String>, &'static str)> {
        let eap = match EapPacket::from_bytes(eap_data) {
            Some(p) => p,
            None => {
                warn!(src = %addr, username = %username, "Malformed EAP packet, rejecting");
                return Ok((self.create_eap_reject(packet, client, 0)?, None, "EAP-TTLS"));
            }
        };

        match (eap.code, eap.eap_type()) {
            // EAP-Response/Identity -> start EAP-TTLS
            (EAP_RESPONSE, Some(EAP_TYPE_IDENTITY)) => {
                let identity = eap.identity().unwrap_or_else(|| username.to_string());
                debug!(src = %addr, identity = %identity, "EAP Identity received, starting TTLS");
                Ok((self.start_ttls(packet, client, &identity, eap.identifier).await?, None, "EAP-TTLS"))
            }

            // EAP-Response/TTLS -> process TLS handshake or inner auth
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
                Ok((self.create_eap_reject(packet, client, eap.identifier)?, None, "EAP-TTLS"))
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
    ) -> Result<(RadiusPacket, Option<String>, &'static str)> {
        let state_bytes = match packet.get_attribute(STATE) {
            Some(attr) => attr.value.clone(),
            None => {
                warn!(src = %addr, username = %username, "EAP-TTLS response missing State attribute");
                return Ok((self.create_eap_reject(packet, client, eap.identifier)?, None, "EAP-TTLS"));
            }
        };

        // Get mutable session
        let mut sessions = self.ttls_sessions.lock().await;
        let session = match sessions.get_mut(&state_bytes) {
            Some(s) => s,
            None => {
                warn!(src = %addr, username = %username, "EAP-TTLS: unknown session State");
                return Ok((self.create_eap_reject(packet, client, eap.identifier)?, None, "EAP-TTLS"));
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
                return Ok((response, None, "EAP-TTLS"));
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
                    if let Some(user) = self.local_db.authenticate(&inner_user, &inner_pass) {
                        info!(src = %addr, username = %inner_user, "EAP-TTLS authenticated");

                        // Evaluate rules with user's groups
                        let (should_accept, rule_filter_id, rule_attrs, rule_name) =
                            self.evaluate_rules(packet, &inner_user, &user.groups, false);

                        if should_accept {
                            info!(src = %addr, username = %inner_user, "EAP-TTLS accept");
                            let response = self.create_eap_accept_with_msk(
                                packet, client, eap.identifier, &keys.msk,
                                rule_filter_id, rule_attrs,
                            )?;
                            return Ok((response, rule_name, "EAP-TTLS"));
                        } else {
                            warn!(src = %addr, username = %inner_user, "EAP-TTLS reject (rules)");
                            return Ok((self.create_eap_reject(packet, client, eap.identifier)?, rule_name, "EAP-TTLS"));
                        }
                    }
                }

                warn!(src = %addr, username = %username, "EAP-TTLS reject (auth failed)");
                return Ok((self.create_eap_reject(packet, client, eap.identifier)?, None, "EAP-TTLS"));
            }
            Err(e) => {
                warn!(src = %addr, username = %username, "EAP-TTLS error: {}", e);
                drop(sessions);
                return Ok((self.create_eap_reject(packet, client, eap.identifier)?, None, "EAP-TTLS"));
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
        Ok((response, None, "EAP-TTLS"))
    }

    fn create_eap_accept_with_msk(
        &self,
        request: &RadiusPacket,
        client: &Client,
        eap_id: u8,
        msk: &[u8; 64],
        rule_filter_id: Option<String>,
        rule_attributes: HashMap<String, String>,
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

        // Add rule attributes
        for (key, value) in &rule_attributes {
            if let Some(attr_type) = self.dictionary.get_attribute_type(key) {
                response.add_string_attribute(attr_type, value);
            }
        }

        // Add rule-specified Filter-Id
        if let Some(ref filter_id) = rule_filter_id {
            response.add_string_attribute(FILTER_ID, filter_id);
            info!(filter_id = %filter_id, "Returning Filter-Id in EAP accept");
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

    /// Encrypt MPPE key per RFC 2548 section 2.4.2
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
    ) -> Result<(RadiusPacket, Option<String>, &'static str)> {
        let entry = self.local_db.lookup_mab(mac);
        let groups: Vec<String> = entry.map(|e| e.groups.clone()).unwrap_or_default();

        if entry.is_some() {
            info!(src = %addr, mac = %mac, "MAB entry found");
        } else {
            debug!(src = %addr, mac = %mac, "MAB entry not found, using empty groups");
        }

        // Evaluate rules with MAB entry's groups
        let (should_accept, rule_filter_id, rule_attrs, rule_name) =
            self.evaluate_rules(packet, mac, &groups, true);

        if should_accept {
            info!(src = %addr, mac = %mac, "MAB accept");
            let response = self.create_accept(packet, client, rule_filter_id, rule_attrs)?;
            Ok((response, rule_name, "MAB"))
        } else {
            warn!(src = %addr, mac = %mac, "MAB reject (rules)");
            Ok((self.create_reject(packet, client)?, rule_name, "MAB"))
        }
    }

    // -------------------------------------------------------------------------
    // Response helpers
    // -------------------------------------------------------------------------

    fn create_accept(
        &self,
        request: &RadiusPacket,
        client: &Client,
        rule_filter_id: Option<String>,
        rule_attributes: HashMap<String, String>,
    ) -> Result<RadiusPacket> {
        let mut response = RadiusPacket::new(Code::AccessAccept, request.identifier);

        // Add rule attributes
        for (key, value) in &rule_attributes {
            if let Some(attr_type) = self.dictionary.get_attribute_type(key) {
                response.add_string_attribute(attr_type, value);
            }
        }

        // Add rule-specified Filter-Id
        if let Some(ref filter_id) = rule_filter_id {
            response.add_string_attribute(FILTER_ID, filter_id);
            info!(filter_id = %filter_id, "Returning Filter-Id");
        }

        response.calculate_response_authenticator(&request.authenticator, &client.shared_secret);
        Ok(response)
    }

    fn create_reject(&self, request: &RadiusPacket, client: &Client) -> Result<RadiusPacket> {
        let mut response = RadiusPacket::new(Code::AccessReject, request.identifier);
        response.calculate_response_authenticator(&request.authenticator, &client.shared_secret);
        Ok(response)
    }

    /// Get a reference to the dictionary for attribute logging.
    pub fn dictionary(&self) -> &Dictionary {
        &self.dictionary
    }

    /// Evaluate rules for an authenticated request.
    /// Returns (should_accept, filter_id, additional_attributes, rule_name).
    fn evaluate_rules(
        &self,
        packet: &RadiusPacket,
        username: &str,
        user_groups: &[String],
        is_mab: bool,
    ) -> (bool, Option<String>, HashMap<String, String>, Option<String>) {
        let rules_engine = match &self.rules_engine {
            Some(engine) => engine,
            None => return (true, None, HashMap::new(), None), // No rules = accept
        };

        // Build evaluation context from packet attributes
        let calling_station_id = packet.get_string_attribute(CALLING_STATION_ID);
        let called_station_id = packet.get_string_attribute(CALLED_STATION_ID);
        let nas_ip_address = packet.get_string_attribute(NAS_IP_ADDRESS);
        let nas_identifier = packet.get_string_attribute(NAS_IDENTIFIER);

        // Build attributes map from packet
        let mut attributes = HashMap::new();
        for attr in &packet.attributes {
            if let Some(name) = self.dictionary.get_attribute_name(attr.attr_type) {
                if let Some(s) = attr.as_string() {
                    attributes.insert(name.clone(), s);
                }
            }
        }

        let ctx = EvalContext {
            username,
            calling_station_id: calling_station_id.as_deref(),
            called_station_id: called_station_id.as_deref(),
            nas_ip_address: nas_ip_address.as_deref(),
            nas_identifier: nas_identifier.as_deref(),
            attributes: &attributes,
            user_groups,
            is_mab,
        };

        match rules_engine.evaluate(&ctx) {
            RuleResult::Accept { rule_name, filter_id, attributes } => {
                info!(rule = %rule_name, "Rules: ACCEPT");
                (true, filter_id, attributes, Some(rule_name))
            }
            RuleResult::Reject { rule_name } => {
                info!(rule = %rule_name, "Rules: REJECT");
                (false, None, HashMap::new(), Some(rule_name))
            }
            RuleResult::Default => {
                // No rules matched - reject (config should have a catch-all rule)
                warn!("No rules matched, rejecting (add a default rule with 'always' condition)");
                (false, None, HashMap::new(), None)
            }
        }
    }
}
