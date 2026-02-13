// Phase 3: Derived operations on encrypted PII
//
// These operations decrypt internally, compute, and return only non-identifying results.
// The LLM never sees the raw PII values.
//
// Stub implementation — returns "not yet implemented" for all operations.

use dam_core::{DamError, DamResult, PiiRef};
use dam_vault::VaultStore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedOp {
    Proximity,
    SameDomain,
    SamePerson,
    Age,
    CountryCode,
    PostalArea,
    TimeSince,
    FormatForAction,
    CountByType,
    SearchVault,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedResult {
    pub operation: String,
    pub result: serde_json::Value,
}

#[allow(dead_code)]
pub struct DerivedEngine {
    vault: Arc<VaultStore>,
}

impl DerivedEngine {
    pub fn new(vault: Arc<VaultStore>) -> Self {
        Self { vault }
    }

    pub fn execute(
        &self,
        _operation: DerivedOp,
        _refs: &[PiiRef],
        _params: serde_json::Value,
    ) -> DamResult<DerivedResult> {
        Err(DamError::Other(
            "derived operations are not yet implemented (Phase 3)".to_string(),
        ))
    }
}
