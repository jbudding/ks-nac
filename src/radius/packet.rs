use anyhow::Result;
use super::dictionary::Dictionary;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    AccessRequest = 1,
    AccessAccept = 2,
    AccessReject = 3,
    AccountingRequest = 4,
    AccountingResponse = 5,
    AccessChallenge = 11,
}

impl From<u8> for Code {
    fn from(value: u8) -> Self {
        match value {
            1 => Code::AccessRequest,
            2 => Code::AccessAccept,
            3 => Code::AccessReject,
            4 => Code::AccountingRequest,
            5 => Code::AccountingResponse,
            11 => Code::AccessChallenge,
            _ => Code::AccessReject,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RadiusAttribute {
    pub attr_type: u8,
    pub value: Vec<u8>,
}

/// Parsed Vendor-Specific Attribute sub-attribute.
#[derive(Debug, Clone)]
pub struct VsaSubAttribute {
    pub vendor_id: u32,
    pub attr_type: u8,
    pub value: Vec<u8>,
}

impl VsaSubAttribute {
    pub fn as_string(&self) -> Option<String> {
        String::from_utf8(self.value.clone()).ok()
    }

    pub fn as_u32(&self) -> Option<u32> {
        if self.value.len() == 4 {
            Some(u32::from_be_bytes([
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
            ]))
        } else {
            None
        }
    }
}

impl RadiusAttribute {
    pub fn new(attr_type: u8, value: Vec<u8>) -> Self {
        Self { attr_type, value }
    }

    pub fn as_string(&self) -> Option<String> {
        String::from_utf8(self.value.clone()).ok()
    }

    pub fn as_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        if self.value.len() == 4 {
            Some(std::net::Ipv4Addr::new(
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
            ))
        } else {
            None
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        if self.value.len() == 4 {
            Some(u32::from_be_bytes([
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
            ]))
        } else {
            None
        }
    }

    /// Parse a Vendor-Specific attribute (type 26) into sub-attributes.
    /// VSA format: 4-byte vendor ID, followed by sub-attributes (type, length, value).
    pub fn parse_vsa(&self) -> Option<Vec<VsaSubAttribute>> {
        if self.attr_type != 26 || self.value.len() < 6 {
            return None;
        }

        let vendor_id = u32::from_be_bytes([
            self.value[0],
            self.value[1],
            self.value[2],
            self.value[3],
        ]);

        let mut sub_attrs = Vec::new();
        let mut pos = 4;

        while pos + 2 <= self.value.len() {
            let sub_type = self.value[pos];
            let sub_len = self.value[pos + 1] as usize;

            if sub_len < 2 || pos + sub_len > self.value.len() {
                break;
            }

            let sub_value = self.value[pos + 2..pos + sub_len].to_vec();
            sub_attrs.push(VsaSubAttribute {
                vendor_id,
                attr_type: sub_type,
                value: sub_value,
            });

            pos += sub_len;
        }

        Some(sub_attrs)
    }
}

#[derive(Debug, Clone)]
pub struct RadiusPacket {
    pub code: Code,
    pub identifier: u8,
    pub authenticator: [u8; 16],
    pub attributes: Vec<RadiusAttribute>,
}

impl RadiusPacket {
    pub fn new(code: Code, identifier: u8) -> Self {
        Self {
            code,
            identifier,
            authenticator: [0; 16],
            attributes: Vec::new(),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            return Err(anyhow::anyhow!("Packet too short"));
        }

        let code = Code::from(data[0]);
        let identifier = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < length || length < 20 {
            return Err(anyhow::anyhow!("Invalid packet length"));
        }

        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&data[4..20]);

        let mut attributes = Vec::new();
        let mut pos = 20;

        while pos < length {
            if pos + 2 > length {
                break;
            }

            let attr_type = data[pos];
            let attr_length = data[pos + 1] as usize;

            if attr_length < 2 || pos + attr_length > length {
                break;
            }

            let value = data[pos + 2..pos + attr_length].to_vec();
            attributes.push(RadiusAttribute::new(attr_type, value));

            pos += attr_length;
        }

        Ok(Self {
            code,
            identifier,
            authenticator,
            attributes,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        packet.push(self.code as u8);
        packet.push(self.identifier);

        let length = 20 + self.attributes.iter().map(|a| 2 + a.value.len()).sum::<usize>();
        packet.extend_from_slice(&(length as u16).to_be_bytes());

        packet.extend_from_slice(&self.authenticator);

        for attr in &self.attributes {
            packet.push(attr.attr_type);
            packet.push((2 + attr.value.len()) as u8);
            packet.extend_from_slice(&attr.value);
        }

        packet
    }

    pub fn add_attribute(&mut self, attr_type: u8, value: Vec<u8>) {
        // RADIUS attributes have max 253 bytes of value (255 - 2 for type+length)
        // For EAP-Message (79), split across multiple attributes per RFC 2869
        const MAX_ATTR_VALUE: usize = 253;

        if value.len() <= MAX_ATTR_VALUE {
            self.attributes.push(RadiusAttribute::new(attr_type, value));
        } else {
            // Split into multiple attributes
            for chunk in value.chunks(MAX_ATTR_VALUE) {
                self.attributes.push(RadiusAttribute::new(attr_type, chunk.to_vec()));
            }
        }
    }

    pub fn add_string_attribute(&mut self, attr_type: u8, value: &str) {
        self.add_attribute(attr_type, value.as_bytes().to_vec());
    }

    pub fn add_ipv4_attribute(&mut self, attr_type: u8, ip: std::net::Ipv4Addr) {
        self.add_attribute(attr_type, ip.octets().to_vec());
    }

    pub fn add_u32_attribute(&mut self, attr_type: u8, value: u32) {
        self.add_attribute(attr_type, value.to_be_bytes().to_vec());
    }

    pub fn get_attribute(&self, attr_type: u8) -> Option<&RadiusAttribute> {
        self.attributes.iter().find(|a| a.attr_type == attr_type)
    }

    /// Get all attributes of a type and concatenate their values.
    /// Used for EAP-Message which may span multiple attributes.
    pub fn get_concatenated_attribute(&self, attr_type: u8) -> Option<Vec<u8>> {
        let values: Vec<&[u8]> = self.attributes
            .iter()
            .filter(|a| a.attr_type == attr_type)
            .map(|a| a.value.as_slice())
            .collect();

        if values.is_empty() {
            None
        } else {
            Some(values.concat())
        }
    }

    pub fn get_string_attribute(&self, attr_type: u8) -> Option<String> {
        self.get_attribute(attr_type)?.as_string()
    }

    /// Log all attributes in the packet for debugging.
    pub fn log_attributes(&self) {
        self.log_attributes_with_dict(None);
    }

    /// Log all attributes in the packet for debugging, using dictionary for VSA names.
    pub fn log_attributes_with_dict(&self, dict: Option<&Dictionary>) {
        use tracing::debug;
        for attr in &self.attributes {
            if attr.attr_type == 26 {
                // Vendor-Specific attribute - parse and log sub-attributes
                if let Some(sub_attrs) = attr.parse_vsa() {
                    for sub in &sub_attrs {
                        let vendor_name = dict
                            .and_then(|d| d.get_vendor_name(sub.vendor_id))
                            .map(|s| s.as_str())
                            .unwrap_or("Unknown-Vendor");
                        let attr_name = dict
                            .and_then(|d| d.get_vsa_name(sub.vendor_id, sub.attr_type))
                            .unwrap_or("Unknown-VSA");

                        let value_display = format_vsa_value(sub, dict);

                        debug!(
                            vendor_id = sub.vendor_id,
                            vendor = %vendor_name,
                            attr_type = sub.attr_type,
                            attr_name = %attr_name,
                            value = %value_display,
                            len = sub.value.len(),
                            "vsa"
                        );
                    }
                } else {
                    // Couldn't parse VSA, log raw
                    debug!(
                        attr_type = attr.attr_type,
                        attr_name = "Vendor-Specific",
                        value = %format!("{:02x?}", attr.value),
                        len = attr.value.len(),
                        "attribute (malformed VSA)"
                    );
                }
            } else {
                let value_display = if attr.attr_type == 2 {
                    // User-Password - don't log the actual value
                    "[encrypted]".to_string()
                } else if let Some(s) = attr.as_string() {
                    // Printable string
                    format!("\"{}\"", s)
                } else if attr.value.len() == 4 {
                    // Might be an IP or integer
                    format!("{:?} (0x{:08x})", attr.value, u32::from_be_bytes([
                        attr.value[0], attr.value[1], attr.value[2], attr.value[3]
                    ]))
                } else {
                    // Hex dump for binary data
                    format!("{:02x?}", attr.value)
                };
                debug!(
                    attr_type = attr.attr_type,
                    attr_name = %attr_type_name(attr.attr_type),
                    value = %value_display,
                    len = attr.value.len(),
                    "attribute"
                );
            }
        }
    }

    /// Decrypt a PAP User-Password attribute (RFC 2865 §5.2).
    /// The value is XOR-obfuscated in 16-byte blocks:
    ///   plain[i] = cipher[i] XOR MD5(secret + cipher_block[i-1])
    /// with block 0 seeded from the Request-Authenticator.
    pub fn decrypt_user_password(&self, secret: &str) -> Option<String> {
        let attr = self.get_attribute(crate::radius::attributes::USER_PASSWORD)?;
        let cipher = &attr.value;
        if cipher.is_empty() || cipher.len() % 16 != 0 {
            return None;
        }

        let secret_bytes = secret.as_bytes();
        let mut plain = Vec::with_capacity(cipher.len());
        let mut prev: [u8; 16] = self.authenticator;

        for (i, chunk) in cipher.chunks(16).enumerate() {
            let mut hasher = md5::Context::new();
            hasher.consume(secret_bytes);
            hasher.consume(&prev);
            let hash = hasher.compute();

            for (c, h) in chunk.iter().zip(hash.0.iter()) {
                plain.push(c ^ h);
            }

            // Next block seeds from this ciphertext chunk
            prev.copy_from_slice(&cipher[i * 16..(i + 1) * 16]);
        }

        // Strip trailing null padding
        let trimmed = match plain.iter().rposition(|&b| b != 0) {
            Some(last) => &plain[..=last],
            None => &[],
        };
        String::from_utf8(trimmed.to_vec()).ok()
    }

    pub fn set_authenticator(&mut self, authenticator: [u8; 16]) {
        self.authenticator = authenticator;
    }

    /// Compute HMAC-MD5(key=secret, msg=data) — RFC 2104.
    pub fn hmac_md5(secret: &[u8], data: &[u8]) -> [u8; 16] {
        let mut k = [0u8; 64];
        if secret.len() <= 64 {
            k[..secret.len()].copy_from_slice(secret);
        } else {
            let h = md5::compute(secret);
            k[..16].copy_from_slice(&h.0);
        }
        let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();

        let mut inner = ipad;
        inner.extend_from_slice(data);
        let inner_hash = md5::compute(&inner);

        let mut outer = opad;
        outer.extend_from_slice(&inner_hash.0);
        md5::compute(&outer).0
    }

    /// Build a response packet, set the Response-Authenticator, and append a
    /// valid Message-Authenticator attribute (type 80, RFC 3579 §3.2).
    ///
    /// Call this instead of `calculate_response_authenticator` whenever the
    /// packet will be sent in response to an EAP exchange (Access-Challenge,
    /// Access-Accept, Access-Reject carrying EAP-Message).
    pub fn finalize_with_message_authenticator(
        &mut self,
        request_authenticator: &[u8; 16],
        secret: &str,
    ) {
        // Add a placeholder Message-Authenticator (16 zeros).
        self.add_attribute(crate::radius::attributes::MESSAGE_AUTHENTICATOR, vec![0u8; 16]);

        // Per RFC 3579 §3.2: when computing Message-Authenticator for a response,
        // the authenticator field MUST contain the Request-Authenticator.
        self.authenticator = *request_authenticator;
        let packet_bytes = self.to_bytes();
        let mac = Self::hmac_md5(secret.as_bytes(), &packet_bytes);

        // Replace the placeholder with the real MAC.
        if let Some(attr) = self
            .attributes
            .iter_mut()
            .rev()
            .find(|a| a.attr_type == crate::radius::attributes::MESSAGE_AUTHENTICATOR)
        {
            attr.value = mac.to_vec();
        }

        // Now compute the actual Response-Authenticator.
        self.calculate_response_authenticator(request_authenticator, secret);
    }

    pub fn calculate_response_authenticator(&mut self, request_authenticator: &[u8; 16], secret: &str) {
        let mut packet_data = self.to_bytes();
        packet_data[4..20].copy_from_slice(request_authenticator);

        let mut hasher = md5::Context::new();
        hasher.consume(&packet_data);
        hasher.consume(secret.as_bytes());
        let hash = hasher.compute();

        self.authenticator = hash.0;
    }
}

/// Get human-readable name for common RADIUS attribute types.
fn attr_type_name(attr_type: u8) -> &'static str {
    match attr_type {
        1 => "User-Name",
        2 => "User-Password",
        3 => "CHAP-Password",
        4 => "NAS-IP-Address",
        5 => "NAS-Port",
        6 => "Service-Type",
        7 => "Framed-Protocol",
        8 => "Framed-IP-Address",
        12 => "Framed-MTU",
        24 => "State",
        25 => "Class",
        26 => "Vendor-Specific",
        27 => "Session-Timeout",
        28 => "Idle-Timeout",
        30 => "Called-Station-Id",
        31 => "Calling-Station-Id",
        32 => "NAS-Identifier",
        40 => "Acct-Status-Type",
        44 => "Acct-Session-Id",
        61 => "NAS-Port-Type",
        79 => "EAP-Message",
        80 => "Message-Authenticator",
        87 => "NAS-Port-Id",
        _ => "Unknown",
    }
}

/// Format a VSA sub-attribute value for display.
fn format_vsa_value(sub: &VsaSubAttribute, dict: Option<&Dictionary>) -> String {
    // Try to resolve named value from dictionary
    if let Some(d) = dict {
        if let Some(attr_name) = d.get_vsa_name(sub.vendor_id, sub.attr_type) {
            if let Some(val) = sub.as_u32() {
                if let Some(value_name) = d.get_vsa_value_name(sub.vendor_id, attr_name, val) {
                    return format!("{} ({})", value_name, val);
                }
            }
        }
    }

    // Fall back to type-based formatting
    if let Some(s) = sub.as_string() {
        if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            return format!("\"{}\"", s);
        }
    }

    if sub.value.len() == 4 {
        let val = u32::from_be_bytes([
            sub.value[0], sub.value[1], sub.value[2], sub.value[3]
        ]);
        return format!("{}", val);
    }

    format!("{:02x?}", sub.value)
}