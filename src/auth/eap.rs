use rand::Rng;

// EAP codes (RFC 3748 §4)
pub const EAP_REQUEST: u8 = 1;
pub const EAP_RESPONSE: u8 = 2;
pub const EAP_SUCCESS: u8 = 3;
pub const EAP_FAILURE: u8 = 4;

// EAP types
pub const EAP_TYPE_IDENTITY: u8 = 1;
pub const EAP_TYPE_MD5_CHALLENGE: u8 = 4;

/// Parsed EAP packet.
#[derive(Debug, Clone)]
pub struct EapPacket {
    pub code: u8,
    pub identifier: u8,
    /// Payload — everything after the 4-byte header.
    pub data: Vec<u8>,
}

impl EapPacket {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        let code = bytes[0];
        let identifier = bytes[1];
        let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if length < 4 || bytes.len() < length {
            return None;
        }
        let data = bytes[4..length].to_vec();
        Some(Self { code, identifier, data })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let length = (4 + self.data.len()) as u16;
        let mut out = vec![self.code, self.identifier];
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// EAP type field (first byte of data), meaningful for Request/Response.
    pub fn eap_type(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Identity string from an EAP-Response/Identity packet.
    pub fn identity(&self) -> Option<String> {
        if self.code == EAP_RESPONSE && self.data.first() == Some(&EAP_TYPE_IDENTITY) {
            String::from_utf8(self.data[1..].to_vec()).ok()
        } else {
            None
        }
    }

    /// Build an EAP-Request/MD5-Challenge.
    pub fn md5_challenge_request(identifier: u8, challenge: &[u8; 16]) -> Self {
        let mut data = vec![EAP_TYPE_MD5_CHALLENGE, 16u8]; // type + value-size
        data.extend_from_slice(challenge);
        // server name omitted
        Self { code: EAP_REQUEST, identifier, data }
    }

    /// Extract the 16-byte MD5 hash from an EAP-Response/MD5-Challenge.
    pub fn parse_md5_response(&self) -> Option<[u8; 16]> {
        if self.code != EAP_RESPONSE {
            return None;
        }
        if self.data.len() < 2 || self.data[0] != EAP_TYPE_MD5_CHALLENGE {
            return None;
        }
        let value_size = self.data[1] as usize;
        if value_size != 16 || self.data.len() < 2 + value_size {
            return None;
        }
        let mut val = [0u8; 16];
        val.copy_from_slice(&self.data[2..18]);
        Some(val)
    }

    pub fn success(identifier: u8) -> Self {
        Self { code: EAP_SUCCESS, identifier, data: vec![] }
    }

    pub fn failure(identifier: u8) -> Self {
        Self { code: EAP_FAILURE, identifier, data: vec![] }
    }
}

/// Verify an EAP-MD5 response value.
/// Expected: MD5(eap_id || password || challenge)
pub fn verify_md5_response(
    eap_id: u8,
    password: &str,
    challenge: &[u8; 16],
    response: &[u8; 16],
) -> bool {
    let mut ctx = md5::Context::new();
    ctx.consume([eap_id]);
    ctx.consume(password.as_bytes());
    ctx.consume(challenge);
    ctx.compute().0 == *response
}

/// Generate a cryptographically random 16-byte challenge.
pub fn generate_challenge() -> [u8; 16] {
    rand::thread_rng().gen()
}

/// Pending EAP-MD5 session stored between the challenge and the response.
#[derive(Debug, Clone)]
pub struct EapSession {
    pub username: String,
    pub challenge: [u8; 16],
    pub eap_id: u8,
}
