use std::collections::HashMap;
use std::fs;
use serde::Deserialize;
use tracing::{info, warn};

/// VSA attribute definition.
#[derive(Debug, Clone, Deserialize)]
pub struct VsaAttribute {
    pub code: u8,
    pub name: String,
    #[serde(rename = "type")]
    pub attr_type: String,
}

/// Vendor dictionary loaded from JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct VendorDictionary {
    pub vendor_name: String,
    pub vendor_id: u32,
    pub attributes: Vec<VsaAttribute>,
    #[serde(default)]
    pub values: HashMap<String, HashMap<String, u32>>,
}

/// Dictionary configuration file.
#[derive(Debug, Clone, Deserialize)]
pub struct DictionaryConfig {
    pub dictionaries: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Dictionary {
    /// Standard RADIUS attributes (type -> name).
    attributes: HashMap<u8, String>,
    /// Named values for attributes.
    values: HashMap<String, u32>,
    /// Vendor dictionaries keyed by vendor ID.
    vendors: HashMap<u32, VendorDictionary>,
    /// Vendor ID to name mapping.
    vendor_names: HashMap<u32, String>,
}

impl Dictionary {
    pub fn new() -> Self {
        let mut dict = Self {
            attributes: HashMap::new(),
            values: HashMap::new(),
            vendors: HashMap::new(),
            vendor_names: HashMap::new(),
        };
        dict.load_standard_attributes();
        dict
    }

    /// Load dictionary with VSA dictionaries from config file.
    pub fn load(config_path: &str) -> Self {
        let mut dict = Self::new();

        if let Err(e) = dict.load_dictionaries(config_path) {
            warn!("Failed to load dictionary config from {}: {}", config_path, e);
        }

        dict
    }

    /// Load VSA dictionaries from config file.
    fn load_dictionaries(&mut self, config_path: &str) -> anyhow::Result<()> {
        let config_data = fs::read_to_string(config_path)?;
        let config: DictionaryConfig = serde_json::from_str(&config_data)?;

        for dict_path in &config.dictionaries {
            if let Err(e) = self.load_vendor_dictionary(dict_path) {
                warn!("Failed to load dictionary {}: {}", dict_path, e);
            }
        }

        Ok(())
    }

    /// Load a single vendor dictionary from JSON file.
    pub fn load_vendor_dictionary(&mut self, path: &str) -> anyhow::Result<()> {
        let data = fs::read_to_string(path)?;
        let vendor_dict: VendorDictionary = serde_json::from_str(&data)?;

        info!(
            vendor = %vendor_dict.vendor_name,
            vendor_id = vendor_dict.vendor_id,
            attributes = vendor_dict.attributes.len(),
            "Loaded VSA dictionary"
        );

        self.vendor_names.insert(vendor_dict.vendor_id, vendor_dict.vendor_name.clone());
        self.vendors.insert(vendor_dict.vendor_id, vendor_dict);

        Ok(())
    }

    fn load_standard_attributes(&mut self) {
        use crate::radius::attributes::*;

        self.attributes.insert(USER_NAME, "User-Name".to_string());
        self.attributes.insert(USER_PASSWORD, "User-Password".to_string());
        self.attributes.insert(CHAP_PASSWORD, "CHAP-Password".to_string());
        self.attributes.insert(NAS_IP_ADDRESS, "NAS-IP-Address".to_string());
        self.attributes.insert(NAS_PORT, "NAS-Port".to_string());
        self.attributes.insert(SERVICE_TYPE, "Service-Type".to_string());
        self.attributes.insert(FRAMED_PROTOCOL, "Framed-Protocol".to_string());
        self.attributes.insert(FRAMED_IP_ADDRESS, "Framed-IP-Address".to_string());
        self.attributes.insert(FRAMED_IP_NETMASK, "Framed-IP-Netmask".to_string());
        self.attributes.insert(FRAMED_ROUTING, "Framed-Routing".to_string());
        self.attributes.insert(FILTER_ID, "Filter-Id".to_string());
        self.attributes.insert(FRAMED_MTU, "Framed-MTU".to_string());
        self.attributes.insert(FRAMED_COMPRESSION, "Framed-Compression".to_string());
        self.attributes.insert(LOGIN_IP_HOST, "Login-IP-Host".to_string());
        self.attributes.insert(LOGIN_SERVICE, "Login-Service".to_string());
        self.attributes.insert(LOGIN_TCP_PORT, "Login-TCP-Port".to_string());
        self.attributes.insert(REPLY_MESSAGE, "Reply-Message".to_string());
        self.attributes.insert(CALLBACK_NUMBER, "Callback-Number".to_string());
        self.attributes.insert(CALLBACK_ID, "Callback-Id".to_string());
        self.attributes.insert(FRAMED_ROUTE, "Framed-Route".to_string());
        self.attributes.insert(FRAMED_IPX_NETWORK, "Framed-IPX-Network".to_string());
        self.attributes.insert(STATE, "State".to_string());
        self.attributes.insert(CLASS, "Class".to_string());
        self.attributes.insert(VENDOR_SPECIFIC, "Vendor-Specific".to_string());
        self.attributes.insert(SESSION_TIMEOUT, "Session-Timeout".to_string());
        self.attributes.insert(IDLE_TIMEOUT, "Idle-Timeout".to_string());
        self.attributes.insert(TERMINATION_ACTION, "Termination-Action".to_string());
        self.attributes.insert(CALLED_STATION_ID, "Called-Station-Id".to_string());
        self.attributes.insert(CALLING_STATION_ID, "Calling-Station-Id".to_string());
        self.attributes.insert(NAS_IDENTIFIER, "NAS-Identifier".to_string());
        self.attributes.insert(PROXY_STATE, "Proxy-State".to_string());
        self.attributes.insert(LOGIN_LAT_SERVICE, "Login-LAT-Service".to_string());
        self.attributes.insert(LOGIN_LAT_NODE, "Login-LAT-Node".to_string());
        self.attributes.insert(LOGIN_LAT_GROUP, "Login-LAT-Group".to_string());
        self.attributes.insert(FRAMED_APPLETALK_LINK, "Framed-AppleTalk-Link".to_string());
        self.attributes.insert(FRAMED_APPLETALK_NETWORK, "Framed-AppleTalk-Network".to_string());
        self.attributes.insert(FRAMED_APPLETALK_ZONE, "Framed-AppleTalk-Zone".to_string());
        self.attributes.insert(ACCT_STATUS_TYPE, "Acct-Status-Type".to_string());
        self.attributes.insert(ACCT_DELAY_TIME, "Acct-Delay-Time".to_string());
        self.attributes.insert(ACCT_INPUT_OCTETS, "Acct-Input-Octets".to_string());
        self.attributes.insert(ACCT_OUTPUT_OCTETS, "Acct-Output-Octets".to_string());
        self.attributes.insert(ACCT_SESSION_ID, "Acct-Session-Id".to_string());
        self.attributes.insert(ACCT_AUTHENTIC, "Acct-Authentic".to_string());
        self.attributes.insert(ACCT_SESSION_TIME, "Acct-Session-Time".to_string());
        self.attributes.insert(ACCT_INPUT_PACKETS, "Acct-Input-Packets".to_string());
        self.attributes.insert(ACCT_OUTPUT_PACKETS, "Acct-Output-Packets".to_string());
        self.attributes.insert(ACCT_TERMINATE_CAUSE, "Acct-Terminate-Cause".to_string());
        self.attributes.insert(ACCT_MULTI_SESSION_ID, "Acct-Multi-Session-Id".to_string());
        self.attributes.insert(ACCT_LINK_COUNT, "Acct-Link-Count".to_string());
        self.attributes.insert(EAP_MESSAGE, "EAP-Message".to_string());
        self.attributes.insert(MESSAGE_AUTHENTICATOR, "Message-Authenticator".to_string());

        // Service-Type values
        self.values.insert("Login-User".to_string(), SERVICE_TYPE_LOGIN);
        self.values.insert("Framed-User".to_string(), SERVICE_TYPE_FRAMED);
        self.values.insert("Callback-Login-User".to_string(), SERVICE_TYPE_CALLBACK_LOGIN);
        self.values.insert("Callback-Framed-User".to_string(), SERVICE_TYPE_CALLBACK_FRAMED);
        self.values.insert("Outbound-User".to_string(), SERVICE_TYPE_OUTBOUND);
        self.values.insert("Administrative-User".to_string(), SERVICE_TYPE_ADMINISTRATIVE);
        self.values.insert("NAS-Prompt-User".to_string(), SERVICE_TYPE_NAS_PROMPT);
        self.values.insert("Authenticate-Only".to_string(), SERVICE_TYPE_AUTHENTICATE_ONLY);
        self.values.insert("Callback-NAS-Prompt".to_string(), SERVICE_TYPE_CALLBACK_NAS_PROMPT);
    }

    pub fn get_attribute_name(&self, attr_type: u8) -> Option<&String> {
        self.attributes.get(&attr_type)
    }

    pub fn get_attribute_type(&self, name: &str) -> Option<u8> {
        self.attributes.iter()
            .find_map(|(k, v)| if v == name { Some(*k) } else { None })
    }

    pub fn get_value(&self, name: &str) -> Option<u32> {
        self.values.get(name).copied()
    }

    /// Get vendor name by ID.
    pub fn get_vendor_name(&self, vendor_id: u32) -> Option<&String> {
        self.vendor_names.get(&vendor_id)
    }

    /// Get VSA attribute name.
    pub fn get_vsa_name(&self, vendor_id: u32, attr_code: u8) -> Option<&str> {
        self.vendors.get(&vendor_id)
            .and_then(|v| v.attributes.iter().find(|a| a.code == attr_code))
            .map(|a| a.name.as_str())
    }

    /// Get VSA attribute code by name.
    pub fn get_vsa_code(&self, vendor_id: u32, name: &str) -> Option<u8> {
        self.vendors.get(&vendor_id)
            .and_then(|v| v.attributes.iter().find(|a| a.name == name))
            .map(|a| a.code)
    }

    /// Get VSA value name.
    pub fn get_vsa_value_name(&self, vendor_id: u32, attr_name: &str, value: u32) -> Option<&str> {
        self.vendors.get(&vendor_id)
            .and_then(|v| v.values.get(attr_name))
            .and_then(|vals| vals.iter().find(|(_, &v)| v == value))
            .map(|(name, _)| name.as_str())
    }

    /// Check if vendor is loaded.
    pub fn has_vendor(&self, vendor_id: u32) -> bool {
        self.vendors.contains_key(&vendor_id)
    }

    /// Get all loaded vendor IDs.
    pub fn vendor_ids(&self) -> Vec<u32> {
        self.vendors.keys().copied().collect()
    }
}