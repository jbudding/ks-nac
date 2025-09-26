use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Dictionary {
    attributes: HashMap<u8, String>,
    values: HashMap<String, u32>,
}

impl Dictionary {
    pub fn new() -> Self {
        let mut dict = Self {
            attributes: HashMap::new(),
            values: HashMap::new(),
        };
        dict.load_standard_attributes();
        dict
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

        // Service-Type values
        self.values.insert("Login-User".to_string(), crate::radius::attributes::SERVICE_TYPE_LOGIN);
        self.values.insert("Framed-User".to_string(), crate::radius::attributes::SERVICE_TYPE_FRAMED);
        self.values.insert("Callback-Login-User".to_string(), crate::radius::attributes::SERVICE_TYPE_CALLBACK_LOGIN);
        self.values.insert("Callback-Framed-User".to_string(), crate::radius::attributes::SERVICE_TYPE_CALLBACK_FRAMED);
        self.values.insert("Outbound-User".to_string(), crate::radius::attributes::SERVICE_TYPE_OUTBOUND);
        self.values.insert("Administrative-User".to_string(), crate::radius::attributes::SERVICE_TYPE_ADMINISTRATIVE);
        self.values.insert("NAS-Prompt-User".to_string(), crate::radius::attributes::SERVICE_TYPE_NAS_PROMPT);
        self.values.insert("Authenticate-Only".to_string(), crate::radius::attributes::SERVICE_TYPE_AUTHENTICATE_ONLY);
        self.values.insert("Callback-NAS-Prompt".to_string(), crate::radius::attributes::SERVICE_TYPE_CALLBACK_NAS_PROMPT);
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
}