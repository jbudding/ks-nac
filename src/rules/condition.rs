use serde::Deserialize;
use std::collections::HashMap;
use regex::Regex;
use tracing::debug;

/// A condition that can be evaluated against request attributes.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    /// Match if username equals the specified value.
    UsernameEquals { value: String },
    /// Match if username matches a regex pattern.
    UsernameMatches { pattern: String },
    /// Match if username ends with suffix (e.g., domain).
    UsernameEndsWith { suffix: String },
    /// Match if username starts with prefix.
    UsernameStartsWith { prefix: String },

    /// Match if calling-station-id equals the specified value.
    CallingStationIdEquals { value: String },
    /// Match if calling-station-id matches a regex pattern.
    CallingStationIdMatches { pattern: String },
    /// Match if calling-station-id starts with prefix (OUI match).
    CallingStationIdStartsWith { prefix: String },

    /// Match if called-station-id equals the specified value.
    CalledStationIdEquals { value: String },
    /// Match if called-station-id matches a regex pattern.
    CalledStationIdMatches { pattern: String },
    /// Match if called-station-id contains the specified value.
    CalledStationIdContains { value: String },

    /// Match if NAS-IP-Address equals the specified value.
    NasIpAddressEquals { value: String },
    /// Match if NAS-Identifier equals the specified value.
    NasIdentifierEquals { value: String },
    /// Match if NAS-Identifier matches a regex pattern.
    NasIdentifierMatches { pattern: String },

    /// Match if a specific attribute has a specific value.
    AttributeEquals { name: String, value: String },
    /// Match if a specific attribute exists.
    AttributeExists { name: String },

    /// Match if the user belongs to a specific group.
    UserInGroup { group: String },

    /// Match if this is a MAB (MAC Authentication Bypass) request.
    IsMab,

    /// Match if all sub-conditions are true (AND).
    All { conditions: Vec<Condition> },
    /// Match if any sub-condition is true (OR).
    Any { conditions: Vec<Condition> },
    /// Negate the result of a condition.
    Not { condition: Box<Condition> },

    /// Always matches.
    Always,
}

/// Context for evaluating conditions.
pub struct EvalContext<'a> {
    pub username: &'a str,
    pub calling_station_id: Option<&'a str>,
    pub called_station_id: Option<&'a str>,
    pub nas_ip_address: Option<&'a str>,
    pub nas_identifier: Option<&'a str>,
    pub attributes: &'a HashMap<String, String>,
    pub user_group: Option<&'a str>,
    pub is_mab: bool,
}

impl Condition {
    /// Evaluate this condition against the given context.
    pub fn evaluate(&self, ctx: &EvalContext) -> bool {
        match self {
            Condition::UsernameEquals { value } => {
                ctx.username.eq_ignore_ascii_case(value)
            }
            Condition::UsernameMatches { pattern } => {
                match Regex::new(pattern) {
                    Ok(re) => re.is_match(ctx.username),
                    Err(_) => {
                        debug!(pattern = %pattern, "Invalid regex pattern");
                        false
                    }
                }
            }
            Condition::UsernameEndsWith { suffix } => {
                ctx.username.to_lowercase().ends_with(&suffix.to_lowercase())
            }
            Condition::UsernameStartsWith { prefix } => {
                ctx.username.to_lowercase().starts_with(&prefix.to_lowercase())
            }

            Condition::CallingStationIdEquals { value } => {
                ctx.calling_station_id
                    .map(|c| normalize_mac(c) == normalize_mac(value))
                    .unwrap_or(false)
            }
            Condition::CallingStationIdMatches { pattern } => {
                match (Regex::new(pattern), ctx.calling_station_id) {
                    (Ok(re), Some(c)) => re.is_match(c),
                    _ => false,
                }
            }
            Condition::CallingStationIdStartsWith { prefix } => {
                ctx.calling_station_id
                    .map(|c| normalize_mac(c).starts_with(&normalize_mac(prefix)))
                    .unwrap_or(false)
            }

            Condition::CalledStationIdEquals { value } => {
                ctx.called_station_id
                    .map(|c| c.eq_ignore_ascii_case(value))
                    .unwrap_or(false)
            }
            Condition::CalledStationIdMatches { pattern } => {
                match (Regex::new(pattern), ctx.called_station_id) {
                    (Ok(re), Some(c)) => re.is_match(c),
                    _ => false,
                }
            }
            Condition::CalledStationIdContains { value } => {
                ctx.called_station_id
                    .map(|c| c.to_lowercase().contains(&value.to_lowercase()))
                    .unwrap_or(false)
            }

            Condition::NasIpAddressEquals { value } => {
                ctx.nas_ip_address
                    .map(|n| n == value)
                    .unwrap_or(false)
            }
            Condition::NasIdentifierEquals { value } => {
                ctx.nas_identifier
                    .map(|n| n.eq_ignore_ascii_case(value))
                    .unwrap_or(false)
            }
            Condition::NasIdentifierMatches { pattern } => {
                match (Regex::new(pattern), ctx.nas_identifier) {
                    (Ok(re), Some(n)) => re.is_match(n),
                    _ => false,
                }
            }

            Condition::AttributeEquals { name, value } => {
                ctx.attributes.get(name)
                    .map(|v| v.eq_ignore_ascii_case(value))
                    .unwrap_or(false)
            }
            Condition::AttributeExists { name } => {
                ctx.attributes.contains_key(name)
            }

            Condition::UserInGroup { group } => {
                ctx.user_group
                    .map(|g| g.eq_ignore_ascii_case(group))
                    .unwrap_or(false)
            }

            Condition::IsMab => ctx.is_mab,

            Condition::All { conditions } => {
                conditions.iter().all(|c| c.evaluate(ctx))
            }
            Condition::Any { conditions } => {
                conditions.iter().any(|c| c.evaluate(ctx))
            }
            Condition::Not { condition } => {
                !condition.evaluate(ctx)
            }

            Condition::Always => true,
        }
    }
}

/// Normalize MAC address for comparison (lowercase, no separators).
fn normalize_mac(mac: &str) -> String {
    mac.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_lowercase()
}
