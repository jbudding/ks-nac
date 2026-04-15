use std::collections::HashMap;
use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    AccessRequest = 1,
    AccessAccept = 2,
    AccessReject = 3,
    AccountingRequest = 4,
    AccountingResponse = 5,
}

impl From<u8> for Code {
    fn from(value: u8) -> Self {
        match value {
            1 => Code::AccessRequest,
            2 => Code::AccessAccept,
            3 => Code::AccessReject,
            4 => Code::AccountingRequest,
            5 => Code::AccountingResponse,
            _ => Code::AccessReject,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RadiusAttribute {
    pub attr_type: u8,
    pub value: Vec<u8>,
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
        self.attributes.push(RadiusAttribute::new(attr_type, value));
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

    pub fn get_string_attribute(&self, attr_type: u8) -> Option<String> {
        self.get_attribute(attr_type)?.as_string()
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