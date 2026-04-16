use std::collections::HashMap;
use std::fs;
use std::path::Path;
use serde::Deserialize;
use tracing::{info, warn, debug};

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
    /// JSON format dictionary files.
    #[serde(default)]
    pub dictionaries: Vec<String>,
    /// FreeRADIUS format dictionary files.
    #[serde(default)]
    pub freeradius_dictionaries: Vec<String>,
    /// Directory to scan for dictionary.* files (FreeRADIUS format).
    #[serde(default)]
    pub freeradius_dictionary_dir: Option<String>,
}

/// Error type for FreeRADIUS dictionary parsing.
#[derive(Debug)]
pub struct DictionaryParseError {
    pub file: String,
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for DictionaryParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.file, self.line, self.message)
    }
}

impl std::error::Error for DictionaryParseError {}

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

        // Load JSON format dictionaries
        for dict_path in &config.dictionaries {
            if let Err(e) = self.load_vendor_dictionary(dict_path) {
                warn!("Failed to load JSON dictionary {}: {}", dict_path, e);
            }
        }

        // Load FreeRADIUS format dictionaries
        for dict_path in &config.freeradius_dictionaries {
            if let Err(e) = self.load_freeradius_dictionary(dict_path) {
                warn!("Failed to load FreeRADIUS dictionary {}: {}", dict_path, e);
            }
        }

        // Scan directory for dictionary.* files
        if let Some(ref dir) = config.freeradius_dictionary_dir {
            if let Err(e) = self.scan_freeradius_directory(dir) {
                warn!("Failed to scan FreeRADIUS dictionary directory {}: {}", dir, e);
            }
        }

        Ok(())
    }

    /// Scan a directory for dictionary.* files and load them.
    pub fn scan_freeradius_directory(&mut self, dir: &str) -> anyhow::Result<()> {
        let path = Path::new(dir);
        if !path.is_dir() {
            return Err(anyhow::anyhow!("Not a directory: {}", dir));
        }

        let entries = fs::read_dir(path)?;
        let mut loaded = 0;

        for entry in entries {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            // Only process files starting with "dictionary."
            if file_name_str.starts_with("dictionary.") && entry.file_type()?.is_file() {
                let file_path = entry.path();
                let file_path_str = file_path.to_string_lossy();

                match self.load_freeradius_dictionary(&file_path_str) {
                    Ok(()) => loaded += 1,
                    Err(e) => warn!("Failed to load {}: {}", file_path_str, e),
                }
            }
        }

        info!(dir = %dir, count = loaded, "Scanned FreeRADIUS dictionary directory");
        Ok(())
    }

    /// Load a FreeRADIUS format dictionary file.
    pub fn load_freeradius_dictionary(&mut self, path: &str) -> anyhow::Result<()> {
        let content = fs::read_to_string(path)?;
        self.parse_freeradius_dictionary(path, &content)
    }

    /// Parse FreeRADIUS dictionary content with syntax validation.
    fn parse_freeradius_dictionary(&mut self, file_path: &str, content: &str) -> anyhow::Result<()> {
        let mut current_vendor: Option<(String, u32)> = None;
        let mut vendors_found: HashMap<String, u32> = HashMap::new();
        let mut vendor_attributes: HashMap<u32, Vec<VsaAttribute>> = HashMap::new();
        let mut vendor_values: HashMap<u32, HashMap<String, HashMap<String, u32>>> = HashMap::new();

        for (line_num, line) in content.lines().enumerate() {
            let line_number = line_num + 1;
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse tokens
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.is_empty() {
                continue;
            }

            match tokens[0].to_uppercase().as_str() {
                "VENDOR" => {
                    if tokens.len() < 3 {
                        return Err(DictionaryParseError {
                            file: file_path.to_string(),
                            line: line_number,
                            message: "VENDOR requires name and id".to_string(),
                        }.into());
                    }
                    let vendor_name = tokens[1].to_string();
                    let vendor_id: u32 = tokens[2].parse().map_err(|_| DictionaryParseError {
                        file: file_path.to_string(),
                        line: line_number,
                        message: format!("Invalid vendor ID: {}", tokens[2]),
                    })?;
                    vendors_found.insert(vendor_name.clone(), vendor_id);
                    debug!(vendor = %vendor_name, id = vendor_id, "Found VENDOR");
                }
                "BEGIN-VENDOR" => {
                    if tokens.len() < 2 {
                        return Err(DictionaryParseError {
                            file: file_path.to_string(),
                            line: line_number,
                            message: "BEGIN-VENDOR requires vendor name".to_string(),
                        }.into());
                    }
                    let vendor_name = tokens[1];
                    let vendor_id = vendors_found.get(vendor_name).copied().ok_or_else(|| {
                        DictionaryParseError {
                            file: file_path.to_string(),
                            line: line_number,
                            message: format!("Unknown vendor: {} (VENDOR not defined before BEGIN-VENDOR)", vendor_name),
                        }
                    })?;
                    current_vendor = Some((vendor_name.to_string(), vendor_id));
                }
                "END-VENDOR" => {
                    if tokens.len() < 2 {
                        return Err(DictionaryParseError {
                            file: file_path.to_string(),
                            line: line_number,
                            message: "END-VENDOR requires vendor name".to_string(),
                        }.into());
                    }
                    let vendor_name = tokens[1];
                    if let Some((ref current_name, _)) = current_vendor {
                        if current_name != vendor_name {
                            return Err(DictionaryParseError {
                                file: file_path.to_string(),
                                line: line_number,
                                message: format!("END-VENDOR {} does not match BEGIN-VENDOR {}", vendor_name, current_name),
                            }.into());
                        }
                    }
                    current_vendor = None;
                }
                "ATTRIBUTE" => {
                    if tokens.len() < 4 {
                        return Err(DictionaryParseError {
                            file: file_path.to_string(),
                            line: line_number,
                            message: "ATTRIBUTE requires name, code, and type".to_string(),
                        }.into());
                    }
                    let attr_name = tokens[1].to_string();
                    let attr_code: u8 = tokens[2].parse().map_err(|_| DictionaryParseError {
                        file: file_path.to_string(),
                        line: line_number,
                        message: format!("Invalid attribute code: {}", tokens[2]),
                    })?;
                    let attr_type = Self::normalize_type(tokens[3]);

                    if let Some((_, vendor_id)) = current_vendor {
                        vendor_attributes.entry(vendor_id).or_default().push(VsaAttribute {
                            code: attr_code,
                            name: attr_name,
                            attr_type,
                        });
                    }
                    // Attributes outside vendor blocks are standard RADIUS attributes (ignored for VSA loading)
                }
                "VALUE" => {
                    if tokens.len() < 4 {
                        return Err(DictionaryParseError {
                            file: file_path.to_string(),
                            line: line_number,
                            message: "VALUE requires attribute-name, value-name, and number".to_string(),
                        }.into());
                    }
                    let attr_name = tokens[1].to_string();
                    let value_name = tokens[2].to_string();
                    let value_num: u32 = tokens[3].parse().map_err(|_| DictionaryParseError {
                        file: file_path.to_string(),
                        line: line_number,
                        message: format!("Invalid value number: {}", tokens[3]),
                    })?;

                    if let Some((_, vendor_id)) = current_vendor {
                        vendor_values
                            .entry(vendor_id)
                            .or_default()
                            .entry(attr_name)
                            .or_default()
                            .insert(value_name, value_num);
                    }
                }
                "ALIAS" | "$INCLUDE" | "FLAGS" | "STRUCT" | "MEMBER" | "DEFINE" | "PROTOCOL" | "ENUM" => {
                    // Skip these directives (not relevant for basic VSA loading)
                    debug!(line = line_number, directive = tokens[0], "Skipping directive");
                }
                _ => {
                    // Unknown directive - warn but continue
                    debug!(
                        file = file_path,
                        line = line_number,
                        directive = tokens[0],
                        "Unknown directive, skipping"
                    );
                }
            }
        }

        // Check for unclosed vendor block
        if let Some((vendor_name, _)) = current_vendor {
            return Err(DictionaryParseError {
                file: file_path.to_string(),
                line: content.lines().count(),
                message: format!("Missing END-VENDOR for {}", vendor_name),
            }.into());
        }

        // Register all found vendors
        for (vendor_name, vendor_id) in &vendors_found {
            let attributes = vendor_attributes.remove(vendor_id).unwrap_or_default();
            let values = vendor_values.remove(vendor_id).unwrap_or_default();

            if !attributes.is_empty() {
                info!(
                    vendor = %vendor_name,
                    vendor_id = vendor_id,
                    attributes = attributes.len(),
                    values = values.len(),
                    "Loaded FreeRADIUS VSA dictionary"
                );

                let vendor_dict = VendorDictionary {
                    vendor_name: vendor_name.clone(),
                    vendor_id: *vendor_id,
                    attributes,
                    values,
                };

                self.vendor_names.insert(*vendor_id, vendor_name.clone());
                self.vendors.insert(*vendor_id, vendor_dict);
            }
        }

        Ok(())
    }

    /// Normalize FreeRADIUS type names to internal types.
    fn normalize_type(type_str: &str) -> String {
        match type_str.to_lowercase().as_str() {
            "uint32" | "integer" | "integer32" => "integer".to_string(),
            "uint16" | "short" => "short".to_string(),
            "uint8" | "byte" => "byte".to_string(),
            "ipaddr" | "ipv4addr" => "ipaddr".to_string(),
            "ipv6addr" => "ipv6addr".to_string(),
            "ipv6prefix" => "ipv6prefix".to_string(),
            "octets" | "tlv" => "octets".to_string(),
            "string" | "text" => "string".to_string(),
            "ether" => "ether".to_string(),
            "date" | "time" => "date".to_string(),
            _ => type_str.to_string(),
        }
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