use anyhow::{anyhow, Result};
use rustls::server::{Acceptor, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConnection, SideData};
use std::io::{Read, Write};
use std::sync::Arc;
use tracing::{debug, warn};

// EAP-TTLS type
pub const EAP_TYPE_TTLS: u8 = 21;
// Inner EAP types
pub const EAP_TYPE_GTC: u8 = 6;
// Diameter AVP codes
const AVP_USER_NAME: u32 = 1;
const AVP_USER_PASSWORD: u32 = 2;
const AVP_EAP_MESSAGE: u32 = 79;

// EAP-TTLS flags
const TTLS_FLAG_LENGTH: u8 = 0x80;
const TTLS_FLAG_MORE: u8 = 0x40;
const TTLS_FLAG_START: u8 = 0x20;

// Maximum EAP fragment size (conservative for RADIUS)
const MAX_EAP_FRAGMENT: usize = 1024;

/// TLS key material for MSK derivation.
/// EAP-TTLS uses the TLS PRF to derive the MSK.
pub struct KeyMaterial {
    pub msk: [u8; 64],
}

/// EAP-TTLS session state.
pub struct TtlsSession {
    /// TLS server connection.
    tls: ServerConnection,
    /// Buffer for incoming TLS data (fragments from client).
    incoming: Vec<u8>,
    /// Buffer for outgoing TLS data (to be fragmented to client).
    outgoing: Vec<u8>,
    /// Offset into outgoing buffer for fragmentation.
    out_offset: usize,
    /// Expected total length of incoming fragmented message.
    incoming_total: Option<usize>,
    /// Whether TLS handshake is complete.
    handshake_complete: bool,
    /// Username from inner authentication.
    pub inner_username: Option<String>,
    /// Password from inner authentication.
    pub inner_password: Option<String>,
    /// Whether inner authentication data received.
    pub inner_auth_done: bool,
    /// EAP identifier for next request.
    pub eap_id: u8,
    /// Inner EAP identifier for tunneled EAP.
    inner_eap_id: u8,
    /// Whether we've sent GTC challenge.
    gtc_challenge_sent: bool,
    /// Last RADIUS packet id processed (for retransmit detection).
    pub last_radius_id: Option<u8>,
    /// Cached response for retransmits.
    pub cached_response: Option<Vec<u8>>,
}

impl TtlsSession {
    pub fn new(config: Arc<ServerConfig>, eap_id: u8) -> Result<Self> {
        let tls = ServerConnection::new(config)
            .map_err(|e| anyhow!("Failed to create TLS connection: {}", e))?;

        Ok(Self {
            tls,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            out_offset: 0,
            incoming_total: None,
            handshake_complete: false,
            inner_username: None,
            inner_password: None,
            inner_auth_done: false,
            eap_id,
            inner_eap_id: 0,
            gtc_challenge_sent: false,
            last_radius_id: None,
            cached_response: None,
        })
    }

    /// Process incoming EAP-TTLS data from client.
    /// Returns None if more fragments needed, or Some(response_data) to send.
    pub fn process(&mut self, eap_data: &[u8]) -> Result<Option<Vec<u8>>> {
        if eap_data.is_empty() {
            return Err(anyhow!("Empty EAP-TTLS data"));
        }

        let flags = eap_data[0];
        let mut offset = 1;

        // Check for length field (4 bytes after flags)
        if flags & TTLS_FLAG_LENGTH != 0 {
            if eap_data.len() < 5 {
                return Err(anyhow!("EAP-TTLS: length flag set but packet too short"));
            }
            let total_len = u32::from_be_bytes([
                eap_data[1], eap_data[2], eap_data[3], eap_data[4]
            ]) as usize;
            self.incoming_total = Some(total_len);
            offset = 5;
        }

        // Append TLS data to incoming buffer
        if offset < eap_data.len() {
            self.incoming.extend_from_slice(&eap_data[offset..]);
        }

        // If more fragments expected, send ACK (empty TTLS response)
        if flags & TTLS_FLAG_MORE != 0 {
            debug!("EAP-TTLS: received fragment, waiting for more");
            return Ok(Some(vec![EAP_TYPE_TTLS, 0])); // ACK
        }

        // All fragments received, process TLS data
        self.process_tls_data()
    }

    fn process_tls_data(&mut self) -> Result<Option<Vec<u8>>> {
        // If we still have pending outgoing fragments, send the next one
        if self.out_offset < self.outgoing.len() {
            return self.build_response();
        }

        // Feed data to TLS
        if !self.incoming.is_empty() {
            let mut rd = &self.incoming[..];
            match self.tls.read_tls(&mut rd) {
                Ok(n) => debug!("TLS read {} bytes", n),
                Err(e) => return Err(anyhow!("TLS read error: {}", e)),
            }
            let consumed = self.incoming.len() - rd.len();
            self.incoming.drain(..consumed);
        }

        // Process TLS state
        let state = self.tls.process_new_packets();
        let mut sent_inner_response = false;

        match state {
            Ok(io_state) => {
                debug!("TLS state: plaintext={}, peer_closed={}",
                    io_state.plaintext_bytes_to_read(),
                    io_state.peer_has_closed());

                // Check if handshake just completed
                if !self.handshake_complete && !self.tls.is_handshaking() {
                    self.handshake_complete = true;
                    debug!("TLS handshake complete");
                }

                // Read any plaintext (inner authentication data)
                if io_state.plaintext_bytes_to_read() > 0 {
                    sent_inner_response = self.read_inner_auth()?;
                }
            }
            Err(e) => {
                warn!("TLS error: {}", e);
                return Err(anyhow!("TLS error: {}", e));
            }
        }

        // Get any new TLS data to send (including inner EAP responses)
        self.outgoing.clear();
        self.out_offset = 0;
        let _ = self.tls.write_tls(&mut self.outgoing);

        // If we have data to send or sent an inner response, build response
        if !self.outgoing.is_empty() || sent_inner_response {
            return self.build_response();
        }

        // Check if inner auth is complete
        if self.inner_auth_done {
            return Ok(None);
        }

        // No data to send, return empty TTLS
        Ok(Some(vec![EAP_TYPE_TTLS, 0]))
    }

    /// Read inner authentication data (Diameter AVPs for TTLS).
    /// Returns true if we sent a response that needs to go out.
    fn read_inner_auth(&mut self) -> Result<bool> {
        let mut buf = vec![0u8; 4096];
        let mut reader = self.tls.reader();

        match reader.read(&mut buf) {
            Ok(n) if n > 0 => {
                debug!("Inner auth data: {} bytes", n);
                // Parse TTLS inner auth (Diameter AVP format)
                self.parse_diameter_avps(&buf[..n])
            }
            Ok(_) => Ok(false),
            Err(e) => {
                debug!("Inner read error (may be normal): {}", e);
                Ok(false)
            }
        }
    }

    /// Parse Diameter AVPs from inner authentication.
    /// Returns true if we need to send a response via TLS.
    fn parse_diameter_avps(&mut self, data: &[u8]) -> Result<bool> {
        let mut pos = 0;
        let mut username: Option<String> = None;
        let mut password: Option<String> = None;
        let mut inner_eap: Option<Vec<u8>> = None;

        while pos + 8 <= data.len() {
            let avp_code = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
            let _avp_flags = data[pos + 4];
            let avp_len = u32::from_be_bytes([0, data[pos+5], data[pos+6], data[pos+7]]) as usize;

            if avp_len < 8 || pos + avp_len > data.len() {
                break;
            }

            let value_start = pos + 8;
            let value_len = avp_len - 8;
            let value = &data[value_start..value_start + value_len];

            match avp_code {
                AVP_USER_NAME => {
                    username = String::from_utf8(value.to_vec()).ok();
                    debug!("Inner User-Name: {:?}", username);
                }
                AVP_USER_PASSWORD => {
                    password = String::from_utf8(value.to_vec()).ok();
                    debug!("Inner User-Password received");
                }
                AVP_EAP_MESSAGE => {
                    debug!("Inner EAP-Message: {} bytes", value.len());
                    inner_eap = Some(value.to_vec());
                }
                _ => {
                    debug!("Unknown AVP code: {}", avp_code);
                }
            }

            // AVPs are padded to 4-byte boundary
            let padded_len = (avp_len + 3) & !3;
            pos += padded_len;
        }

        // Handle PAP (plain username/password)
        if let (Some(u), Some(p)) = (username.clone(), password) {
            self.inner_username = Some(u);
            self.inner_password = Some(p);
            self.inner_auth_done = true;
            return Ok(false);
        }

        // Handle inner EAP
        if let Some(eap_data) = inner_eap {
            return self.process_inner_eap(&eap_data, username);
        }

        Ok(false)
    }

    /// Process inner EAP message and generate response.
    fn process_inner_eap(&mut self, eap_data: &[u8], username: Option<String>) -> Result<bool> {
        if eap_data.len() < 4 {
            return Err(anyhow!("Inner EAP packet too short"));
        }

        let code = eap_data[0];
        let id = eap_data[1];
        let eap_type = if eap_data.len() > 4 { Some(eap_data[4]) } else { None };

        debug!("Inner EAP: code={}, id={}, type={:?}", code, id, eap_type);

        match (code, eap_type) {
            // EAP-Response/Identity - send GTC challenge
            (2, Some(1)) => {
                // Extract identity from EAP packet
                if eap_data.len() > 5 {
                    let identity = String::from_utf8_lossy(&eap_data[5..]).to_string();
                    self.inner_username = Some(identity.clone());
                    debug!("Inner EAP Identity: {}", identity);
                } else if let Some(u) = username {
                    self.inner_username = Some(u);
                }

                // Send EAP-Request/GTC
                self.inner_eap_id = id.wrapping_add(1);
                let gtc_request = self.build_gtc_request();
                self.send_inner_eap_avp(&gtc_request)?;
                self.gtc_challenge_sent = true;
                Ok(true)
            }

            // EAP-Response/GTC - extract password
            (2, Some(EAP_TYPE_GTC)) => {
                if !self.gtc_challenge_sent {
                    return Err(anyhow!("GTC response without challenge"));
                }
                // Password is the GTC response data
                if eap_data.len() > 5 {
                    let password = String::from_utf8_lossy(&eap_data[5..]).to_string();
                    self.inner_password = Some(password);
                    self.inner_auth_done = true;
                    debug!("Inner EAP-GTC password received");
                }
                Ok(false)
            }

            _ => {
                debug!("Unsupported inner EAP: code={}, type={:?}", code, eap_type);
                Err(anyhow!("Unsupported inner EAP type"))
            }
        }
    }

    /// Build EAP-Request/GTC packet.
    fn build_gtc_request(&self) -> Vec<u8> {
        let challenge = b"Password: ";
        let length = (5 + challenge.len()) as u16;

        let mut pkt = Vec::new();
        pkt.push(1); // EAP-Request
        pkt.push(self.inner_eap_id);
        pkt.extend_from_slice(&length.to_be_bytes());
        pkt.push(EAP_TYPE_GTC);
        pkt.extend_from_slice(challenge);
        pkt
    }

    /// Send an EAP message as a Diameter AVP through the TLS tunnel.
    fn send_inner_eap_avp(&mut self, eap_data: &[u8]) -> Result<()> {
        // Build Diameter AVP for EAP-Message (code 79)
        let avp_len = 8 + eap_data.len();
        let mut avp = Vec::new();
        avp.extend_from_slice(&AVP_EAP_MESSAGE.to_be_bytes()); // AVP code
        avp.push(0x40); // Flags: Mandatory
        avp.push(((avp_len >> 16) & 0xff) as u8); // Length (3 bytes)
        avp.push(((avp_len >> 8) & 0xff) as u8);
        avp.push((avp_len & 0xff) as u8);
        avp.extend_from_slice(eap_data);

        // Pad to 4-byte boundary
        while avp.len() % 4 != 0 {
            avp.push(0);
        }

        // Write to TLS
        use std::io::Write;
        self.tls.writer().write_all(&avp)?;

        Ok(())
    }

    /// Build EAP-TTLS response, fragmenting if needed.
    fn build_response(&mut self) -> Result<Option<Vec<u8>>> {
        if self.outgoing.is_empty() && self.out_offset == 0 {
            // No TLS data to send
            if self.inner_auth_done {
                // Inner auth complete, signal success
                return Ok(None); // Caller will send EAP-Success
            }
            return Ok(Some(vec![EAP_TYPE_TTLS, 0])); // Empty response
        }

        let remaining = self.outgoing.len() - self.out_offset;
        let is_first = self.out_offset == 0;
        let needs_fragment = remaining > MAX_EAP_FRAGMENT;

        let mut response = Vec::new();
        response.push(EAP_TYPE_TTLS);

        let mut flags: u8 = 0;

        // Add length field on first fragment
        if is_first && needs_fragment {
            flags |= TTLS_FLAG_LENGTH;
        }

        // More fragments flag
        if needs_fragment {
            flags |= TTLS_FLAG_MORE;
        }

        response.push(flags);

        // Add total length if first fragment
        if is_first && needs_fragment {
            let total = self.outgoing.len() as u32;
            response.extend_from_slice(&total.to_be_bytes());
        }

        // Add TLS data
        let chunk_size = remaining.min(MAX_EAP_FRAGMENT);
        response.extend_from_slice(&self.outgoing[self.out_offset..self.out_offset + chunk_size]);
        self.out_offset += chunk_size;

        Ok(Some(response))
    }

    /// Continue sending fragments after client ACK.
    pub fn continue_fragments(&mut self) -> Result<Option<Vec<u8>>> {
        if self.out_offset < self.outgoing.len() {
            return self.build_response();
        }
        Ok(None)
    }

    /// Generate EAP-TTLS Start packet.
    pub fn start_packet(eap_id: u8) -> Vec<u8> {
        vec![EAP_TYPE_TTLS, TTLS_FLAG_START]
    }

    /// Derive MSK from TLS key material.
    pub fn derive_msk(&self) -> Result<KeyMaterial> {
        // EAP-TTLS MSK derivation uses TLS exporter (RFC 5705)
        // Label: "ttls keying material"
        let mut msk = [0u8; 64];

        self.tls.export_keying_material(
            &mut msk,
            b"ttls keying material",
            None,
        ).map_err(|e| anyhow!("MSK derivation failed: {}", e))?;

        Ok(KeyMaterial { msk })
    }

    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete
    }
}

/// Create TLS server config with a self-signed certificate.
pub fn create_tls_config() -> Result<Arc<ServerConfig>> {
    // Generate a self-signed certificate for testing
    let subject_alt_names = vec!["localhost".to_string(), "radius.local".to_string()];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)
        .map_err(|e| anyhow!("Certificate generation failed: {}", e))?;

    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| anyhow!("TLS config error: {}", e))?;

    Ok(Arc::new(config))
}

/// Load TLS config from certificate and key files.
pub fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>> {
    use std::fs::File;
    use std::io::BufReader;

    let cert_file = File::open(cert_path)
        .map_err(|e| anyhow!("Failed to open cert file: {}", e))?;
    let key_file = File::open(key_path)
        .map_err(|e| anyhow!("Failed to open key file: {}", e))?;

    let mut cert_reader = BufReader::new(cert_file);
    let mut key_reader = BufReader::new(key_file);

    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("Failed to parse certs: {}", e))?;

    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| anyhow!("Failed to parse key: {}", e))?
        .ok_or_else(|| anyhow!("No private key found"))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("TLS config error: {}", e))?;

    Ok(Arc::new(config))
}
