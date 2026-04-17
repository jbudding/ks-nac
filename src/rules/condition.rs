use serde::Deserialize;
use std::collections::HashMap;
use regex::Regex;
use tracing::debug;

/// Comparison operators for attribute matching.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    /// Exact match (case-insensitive).
    Equals,
    /// Substring match (case-insensitive).
    Contains,
    /// Prefix match (case-insensitive).
    StartsWith,
    /// Suffix match (case-insensitive).
    EndsWith,
    /// Regular expression match.
    Regex,
}

/// A condition that can be evaluated against request attributes.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    /// Match a RADIUS attribute using an operator.
    Attribute {
        attribute: String,
        operator: Operator,
        value: String,
    },

    /// Match if a specific attribute exists.
    AttributeExists { attribute: String },

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
            Condition::Attribute { attribute, operator, value } => {
                let attr_value = get_attribute_value(ctx, attribute);
                let (matched, actual_display) = match &attr_value {
                    Some(actual) => (evaluate_operator(operator, actual, value, attribute), actual.clone()),
                    None => (false, "-".to_string()),
                };
                debug!(
                    attribute = %attribute,
                    operator = ?operator,
                    expected = %value,
                    actual = %actual_display,
                    matched = %matched,
                    "Condition: attribute"
                );
                matched
            }

            Condition::AttributeExists { attribute } => {
                let exists = get_attribute_value(ctx, attribute).is_some();
                debug!(
                    attribute = %attribute,
                    exists = %exists,
                    "Condition: attribute_exists"
                );
                exists
            }

            Condition::UserInGroup { group } => {
                let matched = ctx.user_group
                    .map(|g| g.eq_ignore_ascii_case(group))
                    .unwrap_or(false);
                debug!(
                    group = %group,
                    actual = %ctx.user_group.unwrap_or("-"),
                    matched = %matched,
                    "Condition: user_in_group"
                );
                matched
            }

            Condition::IsMab => {
                debug!(is_mab = %ctx.is_mab, "Condition: is_mab");
                ctx.is_mab
            }

            Condition::All { conditions } => {
                let count = conditions.len();
                for (i, c) in conditions.iter().enumerate() {
                    if !c.evaluate(ctx) {
                        debug!(
                            total = count,
                            failed_at = i + 1,
                            matched = false,
                            "Condition: all (short-circuit)"
                        );
                        return false;
                    }
                }
                debug!(total = count, matched = true, "Condition: all");
                true
            }
            Condition::Any { conditions } => {
                let count = conditions.len();
                for (i, c) in conditions.iter().enumerate() {
                    if c.evaluate(ctx) {
                        debug!(
                            total = count,
                            matched_at = i + 1,
                            matched = true,
                            "Condition: any (short-circuit)"
                        );
                        return true;
                    }
                }
                debug!(total = count, matched = false, "Condition: any");
                false
            }
            Condition::Not { condition } => {
                let inner = condition.evaluate(ctx);
                let matched = !inner;
                debug!(inner = %inner, matched = %matched, "Condition: not");
                matched
            }

            Condition::Always => {
                debug!("Condition: always | matched=true");
                true
            }
        }
    }
}

/// Get the value of a RADIUS attribute from the context.
fn get_attribute_value<'a>(ctx: &'a EvalContext, attribute: &str) -> Option<String> {
    // Handle well-known attributes with dedicated fields
    match attribute {
        "User-Name" => Some(ctx.username.to_string()),
        "Calling-Station-Id" => ctx.calling_station_id.map(|s| s.to_string()),
        "Called-Station-Id" => ctx.called_station_id.map(|s| s.to_string()),
        "NAS-IP-Address" => ctx.nas_ip_address.map(|s| s.to_string()),
        "NAS-Identifier" => ctx.nas_identifier.map(|s| s.to_string()),
        // Fall back to attributes map for any other attribute
        _ => ctx.attributes.get(attribute).cloned(),
    }
}

/// Evaluate an operator against actual and expected values.
fn evaluate_operator(operator: &Operator, actual: &str, expected: &str, attribute: &str) -> bool {
    // Normalize MAC addresses for Calling-Station-Id comparisons
    let (actual_normalized, expected_normalized) = if attribute == "Calling-Station-Id" {
        (normalize_mac(actual), normalize_mac(expected))
    } else {
        (actual.to_lowercase(), expected.to_lowercase())
    };

    match operator {
        Operator::Equals => actual_normalized == expected_normalized,
        Operator::Contains => actual_normalized.contains(&expected_normalized),
        Operator::StartsWith => actual_normalized.starts_with(&expected_normalized),
        Operator::EndsWith => actual_normalized.ends_with(&expected_normalized),
        Operator::Regex => {
            match Regex::new(expected) {
                Ok(re) => re.is_match(actual),
                Err(_) => {
                    debug!(pattern = %expected, "Invalid regex pattern");
                    false
                }
            }
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
