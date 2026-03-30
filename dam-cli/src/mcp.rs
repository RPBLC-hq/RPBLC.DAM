use dam_consent::{ConsentAction, ConsentStore};
use dam_log::LogStore;
use dam_vault::VaultStore;
use rmcp::model::*;
use rmcp::{Error as McpError, ServerHandler, tool};
use serde_json::json;
use std::sync::Arc;

const SERVER_INSTRUCTIONS: &str = "\
DAM protects sensitive data in conversations. \
When you see typed tokens like [email:a3f71b] in text, those are DAM vault references. \
Use dam_resolve_token to get the original value ONLY when you need to act on it (e.g., sending an email). \
Always provide a purpose when resolving — it's logged for audit. \
Use dam_grant_consent to allow specific data types through to specific destinations. \
Use dam_get_stats to understand what data is being detected and where. \
Never guess or reconstruct values from tokens.";

#[derive(Clone)]
pub struct DamMcpServer {
    vault: Arc<VaultStore>,
    consent: Arc<ConsentStore>,
    log: Arc<LogStore>,
}

impl DamMcpServer {
    pub fn new(vault: Arc<VaultStore>, consent: Arc<ConsentStore>, log: Arc<LogStore>) -> Self {
        Self {
            vault,
            consent,
            log,
        }
    }
}

#[tool(tool_box)]
impl DamMcpServer {
    /// Resolve a DAM token to its original value. Requires a purpose for audit logging.
    #[tool(
        name = "dam_resolve_token",
        description = "Resolve a DAM token (e.g., email:a3f71b) to its original value. Provide a purpose for the audit trail."
    )]
    fn resolve_token(
        &self,
        #[tool(param)] token: String,
        #[tool(param)] purpose: String,
    ) -> Result<CallToolResult, McpError> {
        let inner = token.strip_prefix('[').unwrap_or(&token);
        let inner = inner.strip_suffix(']').unwrap_or(inner);

        let parsed: dam_core::Token = match inner.parse() {
            Ok(t) => t,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Invalid token: {e}"
                ))]));
            }
        };

        match self.vault.retrieve(&parsed) {
            Ok(value) => {
                // Log the resolution with purpose
                let _ = self.log.log_event(
                    parsed.data_type.tag(),
                    "mcp_resolve",
                    &format!("resolved:{purpose}"),
                    "mcp",
                    &format!("{}...", &value.chars().take(4).collect::<String>()),
                );
                Ok(CallToolResult::success(vec![Content::text(
                    json!({
                        "value": value,
                        "data_type": parsed.data_type.tag(),
                        "token": inner,
                        "purpose": purpose,
                    })
                    .to_string(),
                )]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Resolution failed: {e}"
            ))])),
        }
    }

    /// List tokens stored in the vault (metadata only, no decryption).
    #[tool(
        name = "dam_list_tokens",
        description = "List tokens in the vault. Returns metadata only (type, creation time). No decryption."
    )]
    fn list_tokens(
        &self,
        #[tool(param)] data_type: Option<String>,
        #[tool(param)] limit: Option<u32>,
    ) -> Result<CallToolResult, McpError> {
        let filter = data_type
            .as_deref()
            .and_then(dam_core::SensitiveDataType::from_tag);
        let entries = match self.vault.list(filter) {
            Ok(e) => e,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: {e}"
                ))]));
            }
        };

        let limit = limit.unwrap_or(50) as usize;
        let entries: Vec<_> = entries.into_iter().take(limit).collect();
        let result: Vec<_> = entries
            .iter()
            .map(|e| {
                json!({
                    "token": e.ref_id,
                    "data_type": e.data_type,
                    "created_at": e.created_at,
                })
            })
            .collect();

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "count": result.len(),
                "entries": result,
            })
            .to_string(),
        )]))
    }

    /// Grant consent — allow a data type or specific token to pass through to a destination.
    #[tool(
        name = "dam_grant_consent",
        description = "Grant consent to let sensitive data pass through DAM. By default, all data is redacted. Use this to allow specific types or tokens to specific destinations."
    )]
    fn grant_consent(
        &self,
        #[tool(param)] data_type: String,
        #[tool(param)] token: Option<String>,
        #[tool(param)] destination: String,
        #[tool(param)] ttl: Option<String>,
    ) -> Result<CallToolResult, McpError> {
        let ttl_secs = match parse_ttl_mcp(ttl.as_deref()) {
            Ok(t) => t,
            Err(e) => return Ok(CallToolResult::error(vec![Content::text(e)])),
        };

        let token_key = token.as_ref().map(|t| {
            let inner = t.strip_prefix('[').unwrap_or(t);
            inner.strip_suffix(']').unwrap_or(inner)
        });

        match self.consent.grant(
            &data_type,
            token_key,
            &destination,
            ConsentAction::Pass,
            ttl_secs,
        ) {
            Ok(rule) => {
                let expiry = match rule.expires_at {
                    Some(ts) => format!("expires at {ts}"),
                    None => "permanent".to_string(),
                };
                Ok(CallToolResult::success(vec![Content::text(
                    json!({
                        "rule_id": rule.id,
                        "data_type": rule.data_type,
                        "token": rule.token_key,
                        "destination": rule.destination,
                        "action": "pass",
                        "expiry": expiry,
                    })
                    .to_string(),
                )]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error: {e}"
            ))])),
        }
    }

    /// Deny — explicitly block a data type or token from passing through.
    #[tool(
        name = "dam_deny_consent",
        description = "Explicitly deny a data type or token from passing through, even if a broader rule allows it."
    )]
    fn deny_consent(
        &self,
        #[tool(param)] data_type: String,
        #[tool(param)] token: Option<String>,
        #[tool(param)] destination: String,
    ) -> Result<CallToolResult, McpError> {
        let token_key = token.as_ref().map(|t| {
            let inner = t.strip_prefix('[').unwrap_or(t);
            inner.strip_suffix(']').unwrap_or(inner)
        });

        match self.consent.grant(
            &data_type,
            token_key,
            &destination,
            ConsentAction::Redact,
            None,
        ) {
            Ok(rule) => Ok(CallToolResult::success(vec![Content::text(
                json!({
                    "rule_id": rule.id,
                    "data_type": rule.data_type,
                    "destination": rule.destination,
                    "action": "redact",
                    "expiry": "permanent",
                })
                .to_string(),
            )])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error: {e}"
            ))])),
        }
    }

    /// Revoke a consent rule by its ID.
    #[tool(
        name = "dam_revoke_consent",
        description = "Revoke (remove) a consent rule by its ID."
    )]
    fn revoke_consent(&self, #[tool(param)] rule_id: String) -> Result<CallToolResult, McpError> {
        match self.consent.revoke(&rule_id) {
            Ok(true) => Ok(CallToolResult::success(vec![Content::text(
                json!({
                    "revoked": true,
                    "rule_id": rule_id,
                })
                .to_string(),
            )])),
            Ok(false) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Rule not found: {rule_id}"
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error: {e}"
            ))])),
        }
    }

    /// List all active consent rules.
    #[tool(
        name = "dam_list_consent",
        description = "List all active consent rules (non-expired)."
    )]
    fn list_consent(&self) -> Result<CallToolResult, McpError> {
        match self.consent.list() {
            Ok(rules) => {
                let result: Vec<_> = rules
                    .iter()
                    .map(|r| {
                        json!({
                            "rule_id": r.id,
                            "data_type": r.data_type,
                            "token": r.token_key,
                            "destination": r.destination,
                            "action": r.action.as_str(),
                            "expires_at": r.expires_at,
                        })
                    })
                    .collect();
                Ok(CallToolResult::success(vec![Content::text(
                    json!({
                        "count": result.len(),
                        "rules": result,
                    })
                    .to_string(),
                )]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error: {e}"
            ))])),
        }
    }

    /// Get detection statistics — counts by type and destination, with pass/redact breakdown.
    #[tool(
        name = "dam_get_stats",
        description = "Get detection statistics: counts by data type, how many were redacted vs passed through, and top destinations."
    )]
    fn get_stats(&self) -> Result<CallToolResult, McpError> {
        match self.log.stats() {
            Ok(stats) => {
                let result: Vec<_> = stats
                    .iter()
                    .map(|s| {
                        json!({
                            "data_type": s.data_type,
                            "total": s.count,
                            "redacted": s.redacted,
                            "passed": s.passed,
                            "top_destinations": s.top_destinations,
                        })
                    })
                    .collect();
                Ok(CallToolResult::success(vec![Content::text(
                    json!({
                        "stats": result,
                    })
                    .to_string(),
                )]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error: {e}"
            ))])),
        }
    }
}

#[tool(tool_box)]
impl ServerHandler for DamMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(SERVER_INSTRUCTIONS.to_string()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

fn parse_ttl_mcp(ttl: Option<&str>) -> Result<Option<u64>, String> {
    match ttl {
        None => Ok(Some(86400)), // default 24h
        Some("permanent") | Some("perm") | Some("forever") => Ok(None),
        Some(s) => {
            let (num_str, multiplier) = if let Some(n) = s.strip_suffix('m') {
                (n, 60u64)
            } else if let Some(n) = s.strip_suffix('h') {
                (n, 3600u64)
            } else if let Some(n) = s.strip_suffix('d') {
                (n, 86400u64)
            } else {
                (s, 1u64)
            };
            let num: u64 = num_str.parse().map_err(|_| format!("Invalid TTL: '{s}'"))?;
            Ok(Some(num * multiplier))
        }
    }
}
