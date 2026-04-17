use crate::rules::condition::{Condition, EvalContext};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use tracing::{info, debug};

/// Action to take when a rule matches.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// Accept the request with optional attributes.
    Accept {
        #[serde(default)]
        filter_id: Option<String>,
        #[serde(default)]
        attributes: HashMap<String, String>,
    },
    /// Reject the request.
    Reject,
    /// Continue to the next rule (no action taken).
    Continue,
}

/// A single rule with a condition and action.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    /// Name of the rule for logging.
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
    /// Whether the rule is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Condition to evaluate.
    pub condition: Condition,
    /// Action to take if condition matches.
    pub action: Action,
}

fn default_true() -> bool { true }

/// Rules configuration file format.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RulesConfig {
    /// List of rules to evaluate in order.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Result of evaluating rules.
#[derive(Debug, Clone)]
pub enum RuleResult {
    /// Accept with attributes to add to the response.
    Accept {
        rule_name: String,
        filter_id: Option<String>,
        attributes: HashMap<String, String>,
    },
    /// Reject the request.
    Reject {
        rule_name: String,
    },
    /// No rule matched, use default action.
    Default,
}

/// The rules engine that evaluates authentication requests.
#[derive(Debug, Clone)]
pub struct RulesEngine {
    config: RulesConfig,
}

impl RulesEngine {
    /// Create a new rules engine with default config (reject all).
    pub fn new() -> Self {
        Self {
            config: RulesConfig::default(),
        }
    }

    /// Load rules from a JSON configuration file.
    pub fn load_from_file(path: &str) -> Result<Self, anyhow::Error> {
        let content = fs::read_to_string(path)?;
        let config: RulesConfig = serde_json::from_str(&content)?;

        let enabled_count = config.rules.iter().filter(|r| r.enabled).count();
        info!(
            total = config.rules.len(),
            enabled = enabled_count,
            "Loaded rules configuration"
        );

        Ok(Self { config })
    }

    /// Get the number of rules.
    pub fn rule_count(&self) -> usize {
        self.config.rules.len()
    }

    /// Get the number of enabled rules.
    pub fn enabled_rule_count(&self) -> usize {
        self.config.rules.iter().filter(|r| r.enabled).count()
    }

    /// Evaluate rules against the given context.
    pub fn evaluate(&self, ctx: &EvalContext) -> RuleResult {
        debug!(username = %ctx.username, "Starting rules evaluation");

        for rule in &self.config.rules {
            if !rule.enabled {
                debug!(rule = %rule.name, "Rule skipped (disabled)");
                continue;
            }

            debug!(rule = %rule.name, "Evaluating rule");
            let matched = rule.condition.evaluate(ctx);
            debug!(rule = %rule.name, matched = %matched, "Rule evaluation complete");

            if matched {
                match &rule.action {
                    Action::Accept { filter_id, attributes } => {
                        info!(rule = %rule.name, filter_id = ?filter_id, "Rule accepted request");
                        return RuleResult::Accept {
                            rule_name: rule.name.clone(),
                            filter_id: filter_id.clone(),
                            attributes: attributes.clone(),
                        };
                    }
                    Action::Reject => {
                        info!(rule = %rule.name, "Rule rejected request");
                        return RuleResult::Reject {
                            rule_name: rule.name.clone(),
                        };
                    }
                    Action::Continue => {
                        debug!(rule = %rule.name, "Rule matched with action=continue, proceeding to next rule");
                        continue;
                    }
                }
            }
        }

        debug!("No rules matched, using default action");
        RuleResult::Default
    }

    /// Log the loaded rules summary.
    pub fn log_rules(&self) {
        if self.config.rules.is_empty() {
            info!("No rules configured");
            return;
        }

        info!("Loaded {} rule(s):", self.config.rules.len());
        for rule in &self.config.rules {
            let status = if rule.enabled { "enabled" } else { "disabled" };
            let desc = rule.description.as_deref().unwrap_or("");
            info!(
                "  - {} [{}]{}",
                rule.name,
                status,
                if desc.is_empty() { String::new() } else { format!(" - {}", desc) }
            );
        }
    }
}

impl Default for RulesEngine {
    fn default() -> Self {
        Self::new()
    }
}
