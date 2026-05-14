use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrafficAction {
    #[default]
    Bypass,
    Inspect,
    Block,
    LogMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveDataAction {
    Allow,
    #[default]
    Tokenize,
    Redact,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficFilterPolicy {
    #[serde(default)]
    pub default_action: SensitiveDataAction,
    #[serde(default)]
    pub types: BTreeMap<String, SensitiveDataAction>,
}

impl Default for TrafficFilterPolicy {
    fn default() -> Self {
        Self {
            default_action: SensitiveDataAction::Tokenize,
            types: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TrafficDirectionPolicy {
    #[serde(default)]
    pub filter: TrafficFilterPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficInboundPolicy {
    #[serde(default = "default_resolve_references")]
    pub resolve_references: bool,
    #[serde(default)]
    pub protect_sensitive_data: bool,
    #[serde(default)]
    pub filter: TrafficFilterPolicy,
}

impl Default for TrafficInboundPolicy {
    fn default() -> Self {
        Self {
            resolve_references: true,
            protect_sensitive_data: false,
            filter: TrafficFilterPolicy::default(),
        }
    }
}

fn default_resolve_references() -> bool {
    true
}
