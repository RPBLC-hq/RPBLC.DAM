use dam_core::PiiRef;
use dam_detect::DetectionPipeline;
use dam_resolve::Resolver;
use dam_vault::{AuditLog, ConsentManager, VaultStore};
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::model::*;
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{Error as McpError, ServerHandler, tool};
use std::sync::Arc;

const SERVER_INSTRUCTIONS: &str = "\
DAM protects PII in conversations. \
ALWAYS use dam_scan on user input and external data before processing. \
Work with typed references like [email:a3f71bc9] instead of raw PII values. \
Use dam_resolve only when executing actions that require real values (e.g., sending an email, making a call). \
If dam_resolve returns a consent error, inform the user and ask them to grant consent via dam_consent. \
Never reconstruct or guess PII from references. \
Use dam_status to check vault statistics. \
Use dam_vault_search to find specific entries by type or label.";

/// The DAM MCP server exposing PII protection tools.
#[derive(Clone)]
pub struct DamMcpServer {
    vault: Arc<VaultStore>,
    pipeline: Arc<DetectionPipeline>,
    resolver: Arc<Resolver>,
}

#[tool(tool_box)]
impl DamMcpServer {
    pub fn new(
        vault: Arc<VaultStore>,
        pipeline: Arc<DetectionPipeline>,
        resolver: Arc<Resolver>,
    ) -> Self {
        Self {
            vault,
            pipeline,
            resolver,
        }
    }

    /// Scan text for PII. Returns redacted text with typed references.
    #[tool(
        name = "dam_scan",
        description = "Scan text for PII. Returns redacted text with typed references like [email:a3f71bc9] replacing real values. Always use this on user input and external data before processing."
    )]
    fn scan(
        &self,
        #[tool(param)] text: String,
        #[tool(param)] source: Option<String>,
    ) -> Result<CallToolResult, McpError> {
        let result = self
            .pipeline
            .scan(&text, source.as_deref())
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut response = format!("Redacted text:\n{}\n", result.redacted_text);

        if result.detections.is_empty() {
            response.push_str("\nNo PII detected.");
        } else {
            response.push_str(&format!("\nDetections ({}):\n", result.detections.len()));
            for d in &result.detections {
                response.push_str(&format!(
                    "  {} -> {} (confidence: {:.0}%)\n",
                    d.pii_ref.display(),
                    d.pii_type,
                    d.confidence * 100.0
                ));
            }
        }

        Ok(CallToolResult::success(vec![Content::text(response)]))
    }

    /// Resolve PII references for action execution with consent check.
    #[tool(
        name = "dam_resolve",
        description = "Resolve PII references for action execution. Requires consent. Only use when executing actions that need real values. If consent is denied, ask the user to grant it via dam_consent."
    )]
    fn resolve(
        &self,
        #[tool(param)] text: String,
        #[tool(param)] accessor: String,
        #[tool(param)] purpose: String,
    ) -> Result<CallToolResult, McpError> {
        let result = self
            .resolver
            .resolve_text(&text, &accessor, &purpose)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut response = format!("Resolved text:\n{}\n", result.resolved_text);

        if !result.denied.is_empty() {
            response.push_str("\nDenied references:\n");
            for d in &result.denied {
                response.push_str(&format!("  {} -- {}\n", d.pii_ref.display(), d.reason));
            }
            response.push_str(
                "\nTo grant consent, use dam_consent with the reference, accessor, and purpose.",
            );
        }

        Ok(CallToolResult::success(vec![Content::text(response)]))
    }

    /// Grant or revoke consent for a tool to access a PII reference.
    #[tool(
        name = "dam_consent",
        description = "Grant or revoke consent for a tool to access a PII reference. Use this when dam_resolve returns a consent error."
    )]
    fn consent(
        &self,
        #[tool(param)] ref_id: String,
        #[tool(param)] accessor: String,
        #[tool(param)] purpose: String,
        #[tool(param)] action: String,
    ) -> Result<CallToolResult, McpError> {
        let to_err = |e: dam_core::DamError| McpError::internal_error(e.to_string(), None);

        match action.as_str() {
            "grant" => {
                ConsentManager::grant_consent(
                    self.vault.conn(),
                    &ref_id,
                    &accessor,
                    &purpose,
                    None,
                )
                .map_err(to_err)?;

                AuditLog::record_locked(
                    self.vault.conn(),
                    &ref_id,
                    &accessor,
                    &purpose,
                    "consent_grant",
                    true,
                    None,
                )
                .map_err(to_err)?;

                Ok(CallToolResult::success(vec![Content::text(format!(
                    "Consent granted: {accessor} can now access [{ref_id}] for purpose '{purpose}'."
                ))]))
            }
            "revoke" => {
                ConsentManager::revoke_consent(self.vault.conn(), &ref_id, &accessor, &purpose)
                    .map_err(to_err)?;

                AuditLog::record_locked(
                    self.vault.conn(),
                    &ref_id,
                    &accessor,
                    &purpose,
                    "consent_revoke",
                    true,
                    None,
                )
                .map_err(to_err)?;

                Ok(CallToolResult::success(vec![Content::text(format!(
                    "Consent revoked: {accessor} can no longer access [{ref_id}] for purpose '{purpose}'."
                ))]))
            }
            _ => Ok(CallToolResult::error(vec![Content::text(
                "Invalid action. Use 'grant' or 'revoke'.".to_string(),
            )])),
        }
    }

    /// Search the vault for PII entries by type.
    #[tool(
        name = "dam_vault_search",
        description = "Search the vault for PII entries by type. Returns references only (no decrypted values)."
    )]
    fn vault_search(
        &self,
        #[tool(param)] pii_type: Option<String>,
    ) -> Result<CallToolResult, McpError> {
        let to_err = |e: dam_core::DamError| McpError::internal_error(e.to_string(), None);

        let type_filter = pii_type
            .as_deref()
            .map(|t| t.parse::<dam_core::PiiType>())
            .transpose()
            .map_err(to_err)?;

        let entries = self.vault.list_entries(type_filter).map_err(to_err)?;

        if entries.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text(
                "No entries found.".to_string(),
            )]));
        }

        let mut response = format!("Found {} entries:\n", entries.len());
        for entry in &entries {
            let created = chrono::DateTime::from_timestamp(entry.created_at, 0)
                .map(|dt: chrono::DateTime<chrono::Utc>| dt.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| entry.created_at.to_string());

            response.push_str(&format!(
                "  [{}] type={} created={} source={} label={}\n",
                entry.ref_id,
                entry.pii_type,
                created,
                entry.source.as_deref().unwrap_or("-"),
                entry.label.as_deref().unwrap_or("-"),
            ));
        }

        Ok(CallToolResult::success(vec![Content::text(response)]))
    }

    /// Get vault statistics.
    #[tool(
        name = "dam_status",
        description = "Get vault statistics: entry counts by type, recent activity."
    )]
    fn status(&self) -> Result<CallToolResult, McpError> {
        let to_err = |e: dam_core::DamError| McpError::internal_error(e.to_string(), None);

        let total = self.vault.entry_count().map_err(to_err)?;
        let by_type = self.vault.entry_counts_by_type().map_err(to_err)?;

        let mut response = format!("DAM Vault Status\n\nTotal entries: {total}\n");

        if !by_type.is_empty() {
            response.push_str("\nBy type:\n");
            for (pii_type, count) in &by_type {
                response.push_str(&format!("  {pii_type}: {count}\n"));
            }
        }

        let recent_audit = AuditLog::query(self.vault.conn(), None, 5).map_err(to_err)?;

        if !recent_audit.is_empty() {
            response.push_str("\nRecent activity:\n");
            for entry in &recent_audit {
                let ts = chrono::DateTime::from_timestamp(entry.ts, 0)
                    .map(|dt: chrono::DateTime<chrono::Utc>| dt.format("%H:%M:%S").to_string())
                    .unwrap_or_else(|| entry.ts.to_string());
                let status = if entry.granted { "granted" } else { "denied" };
                response.push_str(&format!(
                    "  [{ts}] {status}: {} {} by {} for {}\n",
                    entry.ref_id, entry.action, entry.accessor, entry.purpose
                ));
            }
        }

        Ok(CallToolResult::success(vec![Content::text(response)]))
    }

    /// Temporarily reveal a PII value (bypasses consent, audited).
    #[tool(
        name = "dam_reveal",
        description = "CAUTION: Temporarily reveal a PII value. This bypasses consent and exposes the real value in the LLM context. Only use when the user explicitly requests to see a value. Always audited."
    )]
    fn reveal(
        &self,
        #[tool(param)] ref_id: String,
        #[tool(param)] reason: String,
    ) -> Result<CallToolResult, McpError> {
        let to_err = |e: dam_core::DamError| McpError::internal_error(e.to_string(), None);
        let pii_ref = PiiRef::from_key(&ref_id).map_err(to_err)?;
        let value = self.resolver.reveal(&pii_ref, &reason).map_err(to_err)?;

        let response = format!(
            "WARNING: REVEALED VALUE (this turn only)\n\n\
             Reference: [{ref_id}]\n\
             Value: {value}\n\n\
             This value is now in the LLM context window and may be:\n\
             - Logged by the LLM provider\n\
             - Included in training data\n\
             - Accessible to other tools in this session\n\n\
             Reason: {reason}\n\
             This reveal has been recorded in the audit trail."
        );

        Ok(CallToolResult::success(vec![Content::text(response)]))
    }

    /// Compare or compute on PII references without revealing values (Phase 3 stub).
    #[tool(
        name = "dam_compare",
        description = "Compare or compute on PII references without revealing values. Phase 3 feature - currently a stub."
    )]
    fn compare(
        &self,
        #[tool(param)] operation: String,
        #[tool(param)] ref_a: String,
        #[tool(param)] ref_b: Option<String>,
    ) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(format!(
            "dam_compare is not yet implemented (Phase 3).\n\
             Operation: {operation}\n\
             Ref A: {ref_a}\n\
             Ref B: {}\n\n\
             This will compute on encrypted PII without revealing values.",
            ref_b.as_deref().unwrap_or("(none)")
        ))]))
    }
}

impl ServerHandler for DamMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(SERVER_INSTRUCTIONS.into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "dam".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            ..Default::default()
        }
    }

    fn list_tools(
        &self,
        _request: PaginatedRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        let tools = Self::tool_box();
        async move {
            Ok(ListToolsResult {
                tools: tools.list(),
                next_cursor: None,
            })
        }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParam,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, McpError>> + Send + '_ {
        let tool_box = Self::tool_box();
        async move {
            let ctx = ToolCallContext::new(self, request, context);
            tool_box.call(ctx).await
        }
    }
}
