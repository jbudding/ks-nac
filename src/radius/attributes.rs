// Standard RADIUS attribute types
pub const USER_NAME: u8 = 1;
pub const USER_PASSWORD: u8 = 2;
pub const CHAP_PASSWORD: u8 = 3;
pub const NAS_IP_ADDRESS: u8 = 4;
pub const NAS_PORT: u8 = 5;
pub const SERVICE_TYPE: u8 = 6;
pub const FRAMED_PROTOCOL: u8 = 7;
pub const FRAMED_IP_ADDRESS: u8 = 8;
pub const FRAMED_IP_NETMASK: u8 = 9;
pub const FRAMED_ROUTING: u8 = 10;
pub const FILTER_ID: u8 = 11;
pub const FRAMED_MTU: u8 = 12;
pub const FRAMED_COMPRESSION: u8 = 13;
pub const LOGIN_IP_HOST: u8 = 14;
pub const LOGIN_SERVICE: u8 = 15;
pub const LOGIN_TCP_PORT: u8 = 16;
pub const REPLY_MESSAGE: u8 = 18;
pub const CALLBACK_NUMBER: u8 = 19;
pub const CALLBACK_ID: u8 = 20;
pub const FRAMED_ROUTE: u8 = 22;
pub const FRAMED_IPX_NETWORK: u8 = 23;
pub const STATE: u8 = 24;
pub const CLASS: u8 = 25;
pub const VENDOR_SPECIFIC: u8 = 26;
pub const SESSION_TIMEOUT: u8 = 27;
pub const IDLE_TIMEOUT: u8 = 28;
pub const TERMINATION_ACTION: u8 = 29;
pub const CALLED_STATION_ID: u8 = 30;
pub const CALLING_STATION_ID: u8 = 31;
pub const NAS_IDENTIFIER: u8 = 32;
pub const PROXY_STATE: u8 = 33;
pub const LOGIN_LAT_SERVICE: u8 = 34;
pub const LOGIN_LAT_NODE: u8 = 35;
pub const LOGIN_LAT_GROUP: u8 = 36;
pub const FRAMED_APPLETALK_LINK: u8 = 37;
pub const FRAMED_APPLETALK_NETWORK: u8 = 38;
pub const FRAMED_APPLETALK_ZONE: u8 = 39;

// Accounting attributes
pub const ACCT_STATUS_TYPE: u8 = 40;
pub const ACCT_DELAY_TIME: u8 = 41;
pub const ACCT_INPUT_OCTETS: u8 = 42;
pub const ACCT_OUTPUT_OCTETS: u8 = 43;
pub const ACCT_SESSION_ID: u8 = 44;
pub const ACCT_AUTHENTIC: u8 = 45;
pub const ACCT_SESSION_TIME: u8 = 46;
pub const ACCT_INPUT_PACKETS: u8 = 47;
pub const ACCT_OUTPUT_PACKETS: u8 = 48;
pub const ACCT_TERMINATE_CAUSE: u8 = 49;
pub const ACCT_MULTI_SESSION_ID: u8 = 50;
pub const ACCT_LINK_COUNT: u8 = 51;

// Service-Type values
pub const SERVICE_TYPE_LOGIN: u32 = 1;
pub const SERVICE_TYPE_FRAMED: u32 = 2;
pub const SERVICE_TYPE_CALLBACK_LOGIN: u32 = 3;
pub const SERVICE_TYPE_CALLBACK_FRAMED: u32 = 4;
pub const SERVICE_TYPE_OUTBOUND: u32 = 5;
pub const SERVICE_TYPE_ADMINISTRATIVE: u32 = 6;
pub const SERVICE_TYPE_NAS_PROMPT: u32 = 7;
pub const SERVICE_TYPE_AUTHENTICATE_ONLY: u32 = 8;
pub const SERVICE_TYPE_CALLBACK_NAS_PROMPT: u32 = 9;

// EAP attributes
pub const EAP_MESSAGE: u8 = 79;
pub const MESSAGE_AUTHENTICATOR: u8 = 80;

// Microsoft Vendor-Specific attributes (Vendor-ID 311)
pub const VENDOR_MICROSOFT: u32 = 311;
pub const MS_MPPE_SEND_KEY: u8 = 16;
pub const MS_MPPE_RECV_KEY: u8 = 17;

// Acct-Status-Type values
pub const ACCT_STATUS_START: u32 = 1;
pub const ACCT_STATUS_STOP: u32 = 2;
pub const ACCT_STATUS_INTERIM_UPDATE: u32 = 3;
pub const ACCT_STATUS_ACCOUNTING_ON: u32 = 7;
pub const ACCT_STATUS_ACCOUNTING_OFF: u32 = 8;