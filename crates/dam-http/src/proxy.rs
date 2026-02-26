use crate::anthropic::{
    ContentBlock, MessageContent, MessagesRequest, MessagesResponse, ResponseBlock,
};
use crate::openai::{ChatContent, ChatMessage, ChatRequest, ChatResponse, ContentPart};
use crate::resolve::resolve_text;
use crate::responses::{ResponsesRequest, ResponsesResponse};
use dam_core::{
    DamConfig,
    reference::replace_refs,
};
use dam_detect::{DetectionPipeline, ScanResult};
use dam_vault::{ConsentManager, VaultStore};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// After scanning, check consent for each detection. For consented refs, replace the
/// `[type:id]` token back with the original value.
fn collect_scan_refs(scan_result: &ScanResult, refs: &mut HashSet<String>) {
    for detection in &scan_result.detections {
        refs.insert(detection.pii_ref.key());
    }
}

fn apply_consent_passthrough(
    vault: &VaultStore,
    scan_result: &ScanResult,
    enabled: bool,
) -> Result<String, dam_core::DamError> {
    if !enabled || scan_result.detections.is_empty() {
        return Ok(scan_result.redacted_text.clone());
    }

    let mut consented: HashMap<String, String> = HashMap::new();
    for detection in &scan_result.detections {
        let ref_key = detection.pii_ref.key();
        if ConsentManager::check_consent(vault.conn(), &ref_key, "http-proxy", "*")? {
            consented.insert(ref_key, detection.value.clone());
        }
    }

    if consented.is_empty() {
        return Ok(scan_result.redacted_text.clone());
    }

    Ok(replace_refs(&scan_result.redacted_text, |pii_ref| {
        consented.get(&pii_ref.key()).cloned()
    }))
}

/// Recursively scan a JSON value for PII strings and replace them.
pub(crate) fn scan_json_value(
    pipeline: &DetectionPipeline,
    vault: &VaultStore,
    value: &mut Value,
    consent_passthrough: bool,
    refs: &mut HashSet<String>,
) -> Result<(), dam_core::DamError> {
    match value {
        Value::String(s) => {
            let result = pipeline.scan(s, Some("http-proxy"))?;
            collect_scan_refs(&result, refs);
            *s = apply_consent_passthrough(vault, &result, consent_passthrough)?;
        }
        Value::Array(arr) => {
            for item in arr {
                scan_json_value(pipeline, vault, item, consent_passthrough, refs)?;
            }
        }
        Value::Object(map) => {
            for val in map.values_mut() {
                scan_json_value(pipeline, vault, val, consent_passthrough, refs)?;
            }
        }
        _ => {} // Numbers, booleans, null - skip
    }
    Ok(())
}

/// Scan user messages in a request for PII and replace with vault references.
///
/// Scans user messages, system field, model field, and all extra fields (metadata, etc.).
/// Assistant messages are skipped as they already contain references from previous turns.
/// PII with granted consent passes through un-redacted.
pub fn redact_request(
    pipeline: &DetectionPipeline,
    vault: &VaultStore,
    request: &mut MessagesRequest,
    consent_passthrough: bool,
) -> Result<HashSet<String>, dam_core::DamError> {
    let mut refs = HashSet::new();
    // Intentionally do NOT scan model identifiers.

    // Scan system message if present
    if let Some(ref mut system) = request.system {
        let result = pipeline.scan(system, Some("http-proxy"))?;
        collect_scan_refs(&result, &mut refs);
        *system = apply_consent_passthrough(vault, &result, consent_passthrough)?;
    }

    // Scan all extra fields (metadata, etc.)
    for value in request.extra.values_mut() {
        scan_json_value(pipeline, vault, value, consent_passthrough, &mut refs)?;
    }

    // Scan user messages
    for message in &mut request.messages {
        if message.role != "user" {
            continue;
        }

        match &mut message.content {
            MessageContent::Text(text) => {
                let result = pipeline.scan(text, Some("http-proxy"))?;
                collect_scan_refs(&result, &mut refs);
                *text = apply_consent_passthrough(vault, &result, consent_passthrough)?;
            }
            MessageContent::Blocks(blocks) => {
                for block in blocks {
                    if let ContentBlock::Text { text, .. } = block {
                        let result = pipeline.scan(text, Some("http-proxy"))?;
                        collect_scan_refs(&result, &mut refs);
                        *text = apply_consent_passthrough(vault, &result, consent_passthrough)?;
                    }
                }
            }
        }
    }
    Ok(refs)
}

/// Resolve PII references in a non-streaming Anthropic response.
pub fn resolve_response(
    vault: &Arc<VaultStore>,
    response: &mut MessagesResponse,
    allowed_refs: &HashSet<String>,
) {
    for block in &mut response.content {
        if let ResponseBlock::Text { text, .. } = block {
            *text = resolve_text(vault, text, Some(allowed_refs));
        }
    }
}

/// Recursively resolve PII references in a JSON value.
pub(crate) fn resolve_json_value(
    vault: &Arc<VaultStore>,
    value: &mut Value,
    allowed_refs: &HashSet<String>,
) {
    match value {
        Value::String(s) => {
            *s = resolve_text(vault, s, Some(allowed_refs));
        }
        Value::Array(arr) => {
            for item in arr {
                resolve_json_value(vault, item, allowed_refs);
            }
        }
        Value::Object(map) => {
            for val in map.values_mut() {
                resolve_json_value(vault, val, allowed_refs);
            }
        }
        _ => {}
    }
}

/// Scan an OpenAI ChatMessage for PII and replace with vault references.
fn redact_chat_message(
    pipeline: &DetectionPipeline,
    vault: &VaultStore,
    message: &mut ChatMessage,
    consent_passthrough: bool,
    refs: &mut HashSet<String>,
) -> Result<(), dam_core::DamError> {
    if let Some(ref mut content) = message.content {
        match content {
            ChatContent::Text(text) => {
                let result = pipeline.scan(text, Some("http-proxy"))?;
                collect_scan_refs(&result, refs);
                *text = apply_consent_passthrough(vault, &result, consent_passthrough)?;
            }
            ChatContent::Parts(parts) => {
                for part in parts {
                    if let ContentPart::Text { text, .. } = part {
                        let result = pipeline.scan(text, Some("http-proxy"))?;
                        collect_scan_refs(&result, refs);
                        *text = apply_consent_passthrough(vault, &result, consent_passthrough)?;
                    }
                }
            }
        }
    }
    // Scan extra fields (e.g. name, tool_call arguments)
    for value in message.extra.values_mut() {
        scan_json_value(pipeline, vault, value, consent_passthrough, refs)?;
    }
    Ok(())
}

/// Scan user and system messages in an OpenAI ChatRequest for PII.
///
/// Scans user messages, system messages, and all extra fields.
/// Assistant and tool messages are skipped.
/// PII with granted consent passes through un-redacted.
pub fn redact_chat_request(
    pipeline: &DetectionPipeline,
    vault: &VaultStore,
    request: &mut ChatRequest,
    consent_passthrough: bool,
) -> Result<HashSet<String>, dam_core::DamError> {
    let mut refs = HashSet::new();
    // Scan all extra fields
    for value in request.extra.values_mut() {
        scan_json_value(pipeline, vault, value, consent_passthrough, &mut refs)?;
    }

    // Scan user and system messages
    for message in &mut request.messages {
        match message.role.as_str() {
            "user" | "system" => {
                redact_chat_message(pipeline, vault, message, consent_passthrough, &mut refs)?;
            }
            _ => {} // Skip assistant, tool messages
        }
    }
    Ok(refs)
}

/// Resolve PII references in a non-streaming OpenAI ChatResponse.
pub fn resolve_chat_response(
    vault: &Arc<VaultStore>,
    response: &mut ChatResponse,
    allowed_refs: &HashSet<String>,
) {
    for choice in &mut response.choices {
        if let Some(ref mut content) = choice.message.content {
            *content = resolve_text(vault, content, Some(allowed_refs));
        }
        // Resolve refs in choice extras (e.g. tool_calls arguments)
        for value in choice.message.extra.values_mut() {
            resolve_json_value(vault, value, allowed_refs);
        }
        for value in choice.extra.values_mut() {
            resolve_json_value(vault, value, allowed_refs);
        }
    }
}

/// Scan an OpenAI Responses API request for PII and replace with vault references.
///
/// Scans `instructions`, `input` (recursively), and all extra fields.
/// The `model` field is not scanned (per existing convention).
/// PII with granted consent passes through un-redacted.
pub fn redact_responses_request(
    pipeline: &DetectionPipeline,
    vault: &VaultStore,
    request: &mut ResponsesRequest,
    consent_passthrough: bool,
) -> Result<HashSet<String>, dam_core::DamError> {
    let mut refs = HashSet::new();
    // Scan instructions if present
    if let Some(ref mut instructions) = request.instructions {
        let result = pipeline.scan(instructions, Some("http-proxy"))?;
        collect_scan_refs(&result, &mut refs);
        *instructions = apply_consent_passthrough(vault, &result, consent_passthrough)?;
    }

    // Scan input recursively
    scan_json_value(pipeline, vault, &mut request.input, consent_passthrough, &mut refs)?;

    // Scan all extra fields
    for value in request.extra.values_mut() {
        scan_json_value(pipeline, vault, value, consent_passthrough, &mut refs)?;
    }

    Ok(refs)
}

/// Resolve PII references in a non-streaming OpenAI Responses API response.
pub fn resolve_responses_response(
    vault: &Arc<VaultStore>,
    response: &mut ResponsesResponse,
    allowed_refs: &HashSet<String>,
) {
    for item in &mut response.output {
        resolve_json_value(vault, item, allowed_refs);
    }
}

/// Shared application state passed to axum handlers.
#[derive(Clone)]
pub struct AppState {
    /// Encrypted PII vault for storage and retrieval.
    pub vault: Arc<VaultStore>,
    /// PII detection pipeline for scanning user messages.
    pub pipeline: Arc<DetectionPipeline>,
    /// HTTP client for forwarding requests to the upstream LLM provider.
    pub client: reqwest::Client,
    /// Base URL of the upstream Anthropic API.
    pub anthropic_upstream_url: String,
    /// Base URL of the upstream OpenAI API.
    pub openai_upstream_url: String,
    /// Base URL of the upstream Codex API.
    pub codex_upstream_url: String,
    /// If true, consented values pass through upstream un-redacted.
    pub consent_passthrough: bool,
}

impl AppState {
    /// Create application state from config and vault.
    pub fn new(config: &DamConfig, vault: Arc<VaultStore>) -> Self {
        let pipeline = Arc::new(DetectionPipeline::new(config, vault.clone()));
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(120))
            .tcp_keepalive(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let anthropic_upstream_url = config
            .server
            .anthropic_upstream_url
            .clone()
            .unwrap_or_else(|| "https://api.anthropic.com".to_string());

        let openai_upstream_url = config
            .server
            .openai_upstream_url
            .clone()
            .unwrap_or_else(|| "https://api.openai.com".to_string());

        let codex_upstream_url = config
            .server
            .codex_upstream_url
            .clone()
            .unwrap_or_else(|| "https://chatgpt.com/backend-api".to_string());

        Self {
            vault,
            pipeline,
            client,
            anthropic_upstream_url,
            openai_upstream_url,
            codex_upstream_url,
            consent_passthrough: config.server.consent_passthrough,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::{Message, MessagesResponse, ResponseBlock};
    use crate::openai::{
        ChatContent, ChatMessage, ChatRequest, ChatResponse, Choice, ChoiceMessage, ContentPart,
    };
    use dam_core::PiiType;
    use dam_vault::generate_kek;
    use std::collections::{HashMap, HashSet};

    fn test_setup() -> (Arc<VaultStore>, DetectionPipeline) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join("test.db");
        let vault = Arc::new(VaultStore::open(&path, generate_kek()).unwrap());
        let pipeline = DetectionPipeline::basic(vault.clone());
        (vault, pipeline)
    }

    #[test]
    fn redact_user_text_message() {
        let (vault, pipeline) = test_setup();
        let mut req = MessagesRequest {
            model: "test".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text("Email me at john@acme.com".into()),
            }],
            max_tokens: Some(100),
            stream: None,
            system: None,
            extra: HashMap::new(),
        };

        redact_request(&pipeline, &vault, &mut req, true).unwrap();

        if let MessageContent::Text(ref text) = req.messages[0].content {
            assert!(!text.contains("john@acme.com"));
            assert!(text.contains("[email:"));
        } else {
            panic!("expected Text");
        }
    }

    #[test]
    fn redact_skips_assistant_messages() {
        let (vault, pipeline) = test_setup();
        let mut req = MessagesRequest {
            model: "test".into(),
            messages: vec![
                Message {
                    role: "user".into(),
                    content: MessageContent::Text("Hi".into()),
                },
                Message {
                    role: "assistant".into(),
                    content: MessageContent::Text("I see [email:abcd1234]".into()),
                },
            ],
            max_tokens: Some(100),
            stream: None,
            system: None,
            extra: HashMap::new(),
        };

        redact_request(&pipeline, &vault, &mut req, true).unwrap();

        // Assistant message should be untouched
        if let MessageContent::Text(ref text) = req.messages[1].content {
            assert_eq!(text, "I see [email:abcd1234]");
        }
    }

    #[test]
    fn redact_system_message() {
        let (vault, pipeline) = test_setup();
        let mut req = MessagesRequest {
            model: "test".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text("Hello".into()),
            }],
            max_tokens: Some(100),
            stream: None,
            system: Some("User email is contact@secret.com".into()),
            extra: HashMap::new(),
        };

        redact_request(&pipeline, &vault, &mut req, true).unwrap();

        let system = req.system.as_ref().unwrap();
        assert!(!system.contains("contact@secret.com"));
        assert!(system.contains("[email:"));
    }

    #[test]
    fn redact_model_field() {
        let (vault, pipeline) = test_setup();
        let mut req = MessagesRequest {
            model: "leak@evil.com".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text("Hi".into()),
            }],
            max_tokens: Some(100),
            stream: None,
            system: None,
            extra: HashMap::new(),
        };

        redact_request(&pipeline, &vault, &mut req, true).unwrap();

        assert_eq!(req.model, "leak@evil.com");
    }

    #[test]
    fn redact_metadata_field() {
        let (vault, pipeline) = test_setup();
        let mut extra = HashMap::new();
        extra.insert(
            "metadata".to_string(),
            serde_json::json!({"user_email": "leak@metadata.com"}),
        );

        let mut req = MessagesRequest {
            model: "test".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text("Hi".into()),
            }],
            max_tokens: Some(100),
            stream: None,
            system: None,
            extra,
        };

        redact_request(&pipeline, &vault, &mut req, true).unwrap();

        let metadata = req.extra.get("metadata").unwrap();
        let user_email = metadata["user_email"].as_str().unwrap();
        assert!(!user_email.contains("leak@metadata.com"));
        assert!(user_email.contains("[email:"));
    }

    #[test]
    fn redact_deeply_nested_extra_fields() {
        let (vault, pipeline) = test_setup();
        let mut extra = HashMap::new();
        extra.insert(
            "deeply_nested".to_string(),
            serde_json::json!({
                "level1": {
                    "level2": {
                        "contacts": [
                            {"email": "deep@nested.com"},
                            {"note": "no pii here"}
                        ]
                    }
                }
            }),
        );

        let mut req = MessagesRequest {
            model: "test".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text("Hi".into()),
            }],
            max_tokens: Some(100),
            stream: None,
            system: None,
            extra,
        };

        redact_request(&pipeline, &vault, &mut req, true).unwrap();

        let nested = &req.extra["deeply_nested"]["level1"]["level2"]["contacts"][0]["email"];
        let email = nested.as_str().unwrap();
        assert!(
            !email.contains("deep@nested.com"),
            "PII in deeply nested JSON should be redacted"
        );
        assert!(email.contains("[email:"));
    }

    #[test]
    fn resolve_response_replaces_refs() {
        let (vault, _) = test_setup();
        let pii_ref = vault
            .store_pii(PiiType::Email, "alice@test.com", None, None)
            .unwrap();

        let mut resp = MessagesResponse {
            id: "msg_01".into(),
            response_type: "message".into(),
            role: "assistant".into(),
            content: vec![ResponseBlock::Text {
                text: format!("Contact {}", pii_ref.display()),
                extra: HashMap::new(),
            }],
            extra: HashMap::new(),
        };

        let mut refs = HashSet::new();
        refs.insert(pii_ref.key());
        resolve_response(&vault, &mut resp, &refs);

        if let ResponseBlock::Text { ref text, .. } = resp.content[0] {
            assert_eq!(text, "Contact alice@test.com");
        }
    }

    // --- OpenAI-specific tests ---

    #[test]
    fn redact_chat_user_text() {
        let (vault, pipeline) = test_setup();
        let mut req = ChatRequest {
            model: "gpt-4o".into(),
            messages: vec![ChatMessage {
                role: "user".into(),
                content: Some(ChatContent::Text("Email me at john@acme.com".into())),
                extra: HashMap::new(),
            }],
            max_tokens: Some(100),
            stream: None,
            extra: HashMap::new(),
        };

        redact_chat_request(&pipeline, &vault, &mut req, true).unwrap();

        if let Some(ChatContent::Text(ref text)) = req.messages[0].content {
            assert!(!text.contains("john@acme.com"));
            assert!(text.contains("[email:"));
        } else {
            panic!("expected Text content");
        }
    }

    #[test]
    fn redact_chat_system_message() {
        let (vault, pipeline) = test_setup();
        let mut req = ChatRequest {
            model: "gpt-4o".into(),
            messages: vec![
                ChatMessage {
                    role: "system".into(),
                    content: Some(ChatContent::Text("User email is contact@secret.com".into())),
                    extra: HashMap::new(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: Some(ChatContent::Text("Hello".into())),
                    extra: HashMap::new(),
                },
            ],
            max_tokens: None,
            stream: None,
            extra: HashMap::new(),
        };

        redact_chat_request(&pipeline, &vault, &mut req, true).unwrap();

        if let Some(ChatContent::Text(ref text)) = req.messages[0].content {
            assert!(!text.contains("contact@secret.com"));
            assert!(text.contains("[email:"));
        }
    }

    #[test]
    fn redact_chat_skips_assistant() {
        let (vault, pipeline) = test_setup();
        let mut req = ChatRequest {
            model: "gpt-4o".into(),
            messages: vec![
                ChatMessage {
                    role: "user".into(),
                    content: Some(ChatContent::Text("Hi".into())),
                    extra: HashMap::new(),
                },
                ChatMessage {
                    role: "assistant".into(),
                    content: Some(ChatContent::Text("I see [email:abcd1234]".into())),
                    extra: HashMap::new(),
                },
            ],
            max_tokens: None,
            stream: None,
            extra: HashMap::new(),
        };

        redact_chat_request(&pipeline, &vault, &mut req, true).unwrap();

        if let Some(ChatContent::Text(ref text)) = req.messages[1].content {
            assert_eq!(text, "I see [email:abcd1234]");
        }
    }

    #[test]
    fn redact_chat_parts_content() {
        let (vault, pipeline) = test_setup();
        let mut req = ChatRequest {
            model: "gpt-4o".into(),
            messages: vec![ChatMessage {
                role: "user".into(),
                content: Some(ChatContent::Parts(vec![
                    ContentPart::Text {
                        text: "Send to bob@test.com".into(),
                        extra: HashMap::new(),
                    },
                    ContentPart::ImageUrl {
                        extra: HashMap::new(),
                    },
                ])),
                extra: HashMap::new(),
            }],
            max_tokens: None,
            stream: None,
            extra: HashMap::new(),
        };

        redact_chat_request(&pipeline, &vault, &mut req, true).unwrap();

        if let Some(ChatContent::Parts(ref parts)) = req.messages[0].content {
            if let ContentPart::Text { ref text, .. } = parts[0] {
                assert!(!text.contains("bob@test.com"));
                assert!(text.contains("[email:"));
            }
        }
    }

    #[test]
    fn resolve_chat_response_replaces_refs() {
        let (vault, _) = test_setup();
        let pii_ref = vault
            .store_pii(PiiType::Email, "alice@test.com", None, None)
            .unwrap();

        let mut resp = ChatResponse {
            id: "chatcmpl-abc".into(),
            object: "chat.completion".into(),
            choices: vec![Choice {
                index: 0,
                message: ChoiceMessage {
                    role: "assistant".into(),
                    content: Some(format!("Contact {}", pii_ref.display())),
                    extra: HashMap::new(),
                },
                finish_reason: Some("stop".into()),
                extra: HashMap::new(),
            }],
            extra: HashMap::new(),
        };

        let mut refs = HashSet::new();
        refs.insert(pii_ref.key());
        resolve_chat_response(&vault, &mut resp, &refs);

        assert_eq!(
            resp.choices[0].message.content.as_deref(),
            Some("Contact alice@test.com")
        );
    }

    // --- Consent passthrough tests ---

    #[test]
    fn consent_passthrough_email() {
        let (vault, pipeline) = test_setup();
        // Store PII first so we know the ref key
        let pii_ref = vault
            .store_pii(PiiType::Email, "alice@corp.ca", None, None)
            .unwrap();
        let ref_key = pii_ref.key();

        // Grant consent with TTL (1 hour from now)
        let expires_at = chrono::Utc::now().timestamp() + 3600;
        ConsentManager::grant_consent(vault.conn(), &ref_key, "http-proxy", "*", Some(expires_at))
            .unwrap();

        let mut req = MessagesRequest {
            model: "test".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text("Email me at alice@corp.ca".into()),
            }],
            max_tokens: Some(100),
            stream: None,
            system: None,
            extra: HashMap::new(),
        };

        redact_request(&pipeline, &vault, &mut req, true).unwrap();

        if let MessageContent::Text(ref text) = req.messages[0].content {
            assert!(
                text.contains("alice@corp.ca"),
                "Consented email should pass through, got: {text}"
            );
            assert!(
                !text.contains("[email:"),
                "Should not be redacted when consent is granted"
            );
        } else {
            panic!("expected Text");
        }
    }

    #[test]
    fn no_consent_still_redacts() {
        let (vault, pipeline) = test_setup();
        let mut req = MessagesRequest {
            model: "test".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text("Email me at noconsent@test.com".into()),
            }],
            max_tokens: Some(100),
            stream: None,
            system: None,
            extra: HashMap::new(),
        };

        redact_request(&pipeline, &vault, &mut req, true).unwrap();

        if let MessageContent::Text(ref text) = req.messages[0].content {
            assert!(!text.contains("noconsent@test.com"));
            assert!(text.contains("[email:"));
        } else {
            panic!("expected Text");
        }
    }

    #[test]
    fn mixed_consent_two_emails() {
        let (vault, pipeline) = test_setup();

        // Pre-store both emails
        let ref1 = vault
            .store_pii(PiiType::Email, "consented@test.com", None, None)
            .unwrap();
        let _ref2 = vault
            .store_pii(PiiType::Email, "denied@test.com", None, None)
            .unwrap();

        // Grant consent only for the first email
        let expires_at = chrono::Utc::now().timestamp() + 3600;
        ConsentManager::grant_consent(
            vault.conn(),
            &ref1.key(),
            "http-proxy",
            "*",
            Some(expires_at),
        )
        .unwrap();

        let mut req = MessagesRequest {
            model: "test".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text(
                    "Send to consented@test.com and denied@test.com".into(),
                ),
            }],
            max_tokens: Some(100),
            stream: None,
            system: None,
            extra: HashMap::new(),
        };

        redact_request(&pipeline, &vault, &mut req, true).unwrap();

        if let MessageContent::Text(ref text) = req.messages[0].content {
            assert!(
                text.contains("consented@test.com"),
                "Consented email should pass through, got: {text}"
            );
            assert!(
                !text.contains("denied@test.com"),
                "Non-consented email should be redacted, got: {text}"
            );
            assert!(
                text.contains("[email:"),
                "Should have at least one redacted ref"
            );
        } else {
            panic!("expected Text");
        }
    }

    #[test]
    fn consent_expired_redacts() {
        let (vault, pipeline) = test_setup();
        let pii_ref = vault
            .store_pii(PiiType::Email, "expired@test.com", None, None)
            .unwrap();
        let ref_key = pii_ref.key();

        // Grant consent that's already expired (1 second ago)
        let expires_at = chrono::Utc::now().timestamp() - 1;
        ConsentManager::grant_consent(vault.conn(), &ref_key, "http-proxy", "*", Some(expires_at))
            .unwrap();

        let mut req = MessagesRequest {
            model: "test".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text("Contact expired@test.com".into()),
            }],
            max_tokens: Some(100),
            stream: None,
            system: None,
            extra: HashMap::new(),
        };

        redact_request(&pipeline, &vault, &mut req, true).unwrap();

        if let MessageContent::Text(ref text) = req.messages[0].content {
            assert!(
                !text.contains("expired@test.com"),
                "Expired consent should still redact, got: {text}"
            );
            assert!(text.contains("[email:"));
        } else {
            panic!("expected Text");
        }
    }

    #[test]
    fn consent_passthrough_openai() {
        let (vault, pipeline) = test_setup();
        let pii_ref = vault
            .store_pii(PiiType::Email, "openai@corp.ca", None, None)
            .unwrap();
        let ref_key = pii_ref.key();

        let expires_at = chrono::Utc::now().timestamp() + 3600;
        ConsentManager::grant_consent(vault.conn(), &ref_key, "http-proxy", "*", Some(expires_at))
            .unwrap();

        let mut req = ChatRequest {
            model: "gpt-4o".into(),
            messages: vec![ChatMessage {
                role: "user".into(),
                content: Some(ChatContent::Text("Email me at openai@corp.ca".into())),
                extra: HashMap::new(),
            }],
            max_tokens: Some(100),
            stream: None,
            extra: HashMap::new(),
        };

        redact_chat_request(&pipeline, &vault, &mut req, true).unwrap();

        if let Some(ChatContent::Text(ref text)) = req.messages[0].content {
            assert!(
                text.contains("openai@corp.ca"),
                "Consented email should pass through in OpenAI request, got: {text}"
            );
        } else {
            panic!("expected Text content");
        }
    }

    #[test]
    fn consent_passthrough_system_message() {
        let (vault, pipeline) = test_setup();
        let pii_ref = vault
            .store_pii(PiiType::Email, "sys@secret.com", None, None)
            .unwrap();

        let expires_at = chrono::Utc::now().timestamp() + 3600;
        ConsentManager::grant_consent(
            vault.conn(),
            &pii_ref.key(),
            "http-proxy",
            "*",
            Some(expires_at),
        )
        .unwrap();

        let mut req = MessagesRequest {
            model: "test".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text("Hello".into()),
            }],
            max_tokens: Some(100),
            stream: None,
            system: Some("User email is sys@secret.com".into()),
            extra: HashMap::new(),
        };

        redact_request(&pipeline, &vault, &mut req, true).unwrap();

        let system = req.system.as_ref().unwrap();
        assert!(
            system.contains("sys@secret.com"),
            "Consented email in system message should pass through, got: {system}"
        );
        assert!(
            !system.contains("[email:"),
            "Should not be redacted in system message"
        );
    }

    #[test]
    fn consent_passthrough_nested_json() {
        let (vault, pipeline) = test_setup();
        let pii_ref = vault
            .store_pii(PiiType::Email, "meta@nested.com", None, None)
            .unwrap();

        let expires_at = chrono::Utc::now().timestamp() + 3600;
        ConsentManager::grant_consent(
            vault.conn(),
            &pii_ref.key(),
            "http-proxy",
            "*",
            Some(expires_at),
        )
        .unwrap();

        let mut extra = HashMap::new();
        extra.insert(
            "metadata".to_string(),
            serde_json::json!({"user_email": "meta@nested.com"}),
        );

        let mut req = MessagesRequest {
            model: "test".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text("Hi".into()),
            }],
            max_tokens: Some(100),
            stream: None,
            system: None,
            extra,
        };

        redact_request(&pipeline, &vault, &mut req, true).unwrap();

        let email = req.extra["metadata"]["user_email"].as_str().unwrap();
        assert!(
            email.contains("meta@nested.com"),
            "Consented email in metadata should pass through, got: {email}"
        );
    }

    #[test]
    fn consent_passthrough_anthropic_content_blocks() {
        let (vault, pipeline) = test_setup();
        let pii_ref = vault
            .store_pii(PiiType::Email, "blocks@test.com", None, None)
            .unwrap();

        let expires_at = chrono::Utc::now().timestamp() + 3600;
        ConsentManager::grant_consent(
            vault.conn(),
            &pii_ref.key(),
            "http-proxy",
            "*",
            Some(expires_at),
        )
        .unwrap();

        let mut req = MessagesRequest {
            model: "test".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![ContentBlock::Text {
                    text: "Send to blocks@test.com".into(),
                    extra: HashMap::new(),
                }]),
            }],
            max_tokens: Some(100),
            stream: None,
            system: None,
            extra: HashMap::new(),
        };

        redact_request(&pipeline, &vault, &mut req, true).unwrap();

        if let MessageContent::Blocks(ref blocks) = req.messages[0].content {
            if let ContentBlock::Text { ref text, .. } = blocks[0] {
                assert!(
                    text.contains("blocks@test.com"),
                    "Consented email in content block should pass through, got: {text}"
                );
            } else {
                panic!("expected Text block");
            }
        } else {
            panic!("expected Blocks");
        }
    }

    #[test]
    fn consent_passthrough_openai_parts() {
        let (vault, pipeline) = test_setup();
        let pii_ref = vault
            .store_pii(PiiType::Email, "parts@test.com", None, None)
            .unwrap();

        let expires_at = chrono::Utc::now().timestamp() + 3600;
        ConsentManager::grant_consent(
            vault.conn(),
            &pii_ref.key(),
            "http-proxy",
            "*",
            Some(expires_at),
        )
        .unwrap();

        let mut req = ChatRequest {
            model: "gpt-4o".into(),
            messages: vec![ChatMessage {
                role: "user".into(),
                content: Some(ChatContent::Parts(vec![ContentPart::Text {
                    text: "Send to parts@test.com".into(),
                    extra: HashMap::new(),
                }])),
                extra: HashMap::new(),
            }],
            max_tokens: None,
            stream: None,
            extra: HashMap::new(),
        };

        redact_chat_request(&pipeline, &vault, &mut req, true).unwrap();

        if let Some(ChatContent::Parts(ref parts)) = req.messages[0].content {
            if let ContentPart::Text { ref text, .. } = parts[0] {
                assert!(
                    text.contains("parts@test.com"),
                    "Consented email in OpenAI parts should pass through, got: {text}"
                );
            }
        } else {
            panic!("expected Parts content");
        }
    }

    #[test]
    fn consent_wildcard_accessor_matches_http_proxy() {
        let (vault, pipeline) = test_setup();
        let pii_ref = vault
            .store_pii(PiiType::Email, "wild@test.com", None, None)
            .unwrap();

        // Grant consent with wildcard accessor — should match "http-proxy"
        let expires_at = chrono::Utc::now().timestamp() + 3600;
        ConsentManager::grant_consent(vault.conn(), &pii_ref.key(), "*", "*", Some(expires_at))
            .unwrap();

        let mut req = MessagesRequest {
            model: "test".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text("Email wild@test.com".into()),
            }],
            max_tokens: Some(100),
            stream: None,
            system: None,
            extra: HashMap::new(),
        };

        redact_request(&pipeline, &vault, &mut req, true).unwrap();

        if let MessageContent::Text(ref text) = req.messages[0].content {
            assert!(
                text.contains("wild@test.com"),
                "Wildcard accessor consent should match http-proxy, got: {text}"
            );
        } else {
            panic!("expected Text");
        }
    }

    #[test]
    fn consent_wrong_accessor_still_redacts() {
        let (vault, pipeline) = test_setup();
        let pii_ref = vault
            .store_pii(PiiType::Email, "wrong@test.com", None, None)
            .unwrap();

        // Grant consent for a different accessor — should NOT match "http-proxy"
        let expires_at = chrono::Utc::now().timestamp() + 3600;
        ConsentManager::grant_consent(
            vault.conn(),
            &pii_ref.key(),
            "some-other-tool",
            "*",
            Some(expires_at),
        )
        .unwrap();

        let mut req = MessagesRequest {
            model: "test".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text("Email wrong@test.com".into()),
            }],
            max_tokens: Some(100),
            stream: None,
            system: None,
            extra: HashMap::new(),
        };

        redact_request(&pipeline, &vault, &mut req, true).unwrap();

        if let MessageContent::Text(ref text) = req.messages[0].content {
            assert!(
                !text.contains("wrong@test.com"),
                "Consent for different accessor should not match, got: {text}"
            );
            assert!(text.contains("[email:"));
        } else {
            panic!("expected Text");
        }
    }

    #[test]
    fn consent_revoked_re_redacts() {
        let (vault, pipeline) = test_setup();
        let pii_ref = vault
            .store_pii(PiiType::Email, "revoke@test.com", None, None)
            .unwrap();
        let ref_key = pii_ref.key();

        // Grant consent
        let expires_at = chrono::Utc::now().timestamp() + 3600;
        ConsentManager::grant_consent(vault.conn(), &ref_key, "http-proxy", "*", Some(expires_at))
            .unwrap();

        // Verify it passes through
        let mut req1 = MessagesRequest {
            model: "test".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text("Email revoke@test.com".into()),
            }],
            max_tokens: Some(100),
            stream: None,
            system: None,
            extra: HashMap::new(),
        };
        redact_request(&pipeline, &vault, &mut req1, true).unwrap();
        if let MessageContent::Text(ref text) = req1.messages[0].content {
            assert!(
                text.contains("revoke@test.com"),
                "Should pass through before revoke"
            );
        }

        // Revoke consent
        ConsentManager::revoke_consent(vault.conn(), &ref_key, "http-proxy", "*").unwrap();

        // Now it should be redacted again
        let mut req2 = MessagesRequest {
            model: "test".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text("Email revoke@test.com".into()),
            }],
            max_tokens: Some(100),
            stream: None,
            system: None,
            extra: HashMap::new(),
        };
        redact_request(&pipeline, &vault, &mut req2, true).unwrap();
        if let MessageContent::Text(ref text) = req2.messages[0].content {
            assert!(
                !text.contains("revoke@test.com"),
                "Should be redacted after revoke, got: {text}"
            );
            assert!(text.contains("[email:"));
        }
    }

    #[test]
    fn consent_openai_system_passthrough() {
        let (vault, pipeline) = test_setup();
        let pii_ref = vault
            .store_pii(PiiType::Email, "oaisys@test.com", None, None)
            .unwrap();

        let expires_at = chrono::Utc::now().timestamp() + 3600;
        ConsentManager::grant_consent(
            vault.conn(),
            &pii_ref.key(),
            "http-proxy",
            "*",
            Some(expires_at),
        )
        .unwrap();

        let mut req = ChatRequest {
            model: "gpt-4o".into(),
            messages: vec![
                ChatMessage {
                    role: "system".into(),
                    content: Some(ChatContent::Text("User email is oaisys@test.com".into())),
                    extra: HashMap::new(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: Some(ChatContent::Text("Hello".into())),
                    extra: HashMap::new(),
                },
            ],
            max_tokens: None,
            stream: None,
            extra: HashMap::new(),
        };

        redact_chat_request(&pipeline, &vault, &mut req, true).unwrap();

        if let Some(ChatContent::Text(ref text)) = req.messages[0].content {
            assert!(
                text.contains("oaisys@test.com"),
                "Consented email in OpenAI system message should pass through, got: {text}"
            );
        }
    }

    // --- Responses API tests ---

    #[test]
    fn redact_responses_string_input() {
        let (vault, pipeline) = test_setup();
        let mut req = ResponsesRequest {
            model: "gpt-4o".into(),
            input: serde_json::json!("Email me at john@acme.com"),
            instructions: None,
            stream: None,
            extra: HashMap::new(),
        };

        redact_responses_request(&pipeline, &vault, &mut req, true).unwrap();

        let text = req.input.as_str().unwrap();
        assert!(!text.contains("john@acme.com"));
        assert!(text.contains("[email:"));
    }

    #[test]
    fn redact_responses_instructions() {
        let (vault, pipeline) = test_setup();
        let mut req = ResponsesRequest {
            model: "gpt-4o".into(),
            input: serde_json::json!("Hello"),
            instructions: Some("User email is contact@secret.com".into()),
            stream: None,
            extra: HashMap::new(),
        };

        redact_responses_request(&pipeline, &vault, &mut req, true).unwrap();

        let instructions = req.instructions.as_ref().unwrap();
        assert!(!instructions.contains("contact@secret.com"));
        assert!(instructions.contains("[email:"));
    }

    #[test]
    fn redact_responses_array_input() {
        let (vault, pipeline) = test_setup();
        let mut req = ResponsesRequest {
            model: "gpt-4o".into(),
            input: serde_json::json!([
                {
                    "type": "message",
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": "Send to bob@test.com"}
                    ]
                }
            ]),
            instructions: None,
            stream: None,
            extra: HashMap::new(),
        };

        redact_responses_request(&pipeline, &vault, &mut req, true).unwrap();

        let text = req.input[0]["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains("bob@test.com"));
        assert!(text.contains("[email:"));
    }

    #[test]
    fn redact_responses_skips_model() {
        let (vault, pipeline) = test_setup();
        let mut req = ResponsesRequest {
            model: "gpt-4o".into(),
            input: serde_json::json!("Hello"),
            instructions: None,
            stream: None,
            extra: HashMap::new(),
        };

        redact_responses_request(&pipeline, &vault, &mut req, true).unwrap();
        assert_eq!(req.model, "gpt-4o");
    }

    #[test]
    fn redact_responses_extra_fields() {
        let (vault, pipeline) = test_setup();
        let mut extra = HashMap::new();
        extra.insert(
            "metadata".to_string(),
            serde_json::json!({"user_email": "leak@metadata.com"}),
        );

        let mut req = ResponsesRequest {
            model: "gpt-4o".into(),
            input: serde_json::json!("Hello"),
            instructions: None,
            stream: None,
            extra,
        };

        redact_responses_request(&pipeline, &vault, &mut req, true).unwrap();

        let email = req.extra["metadata"]["user_email"].as_str().unwrap();
        assert!(!email.contains("leak@metadata.com"));
        assert!(email.contains("[email:"));
    }

    #[test]
    fn resolve_responses_response_replaces_refs() {
        let (vault, _) = test_setup();
        let pii_ref = vault
            .store_pii(PiiType::Email, "alice@test.com", None, None)
            .unwrap();

        let mut resp = ResponsesResponse {
            id: "resp_abc".into(),
            output: vec![serde_json::json!({
                "type": "message",
                "role": "assistant",
                "content": [
                    {"type": "output_text", "text": format!("Contact {}", pii_ref.display())}
                ]
            })],
            extra: HashMap::new(),
        };

        let mut refs = HashSet::new();
        refs.insert(pii_ref.key());
        resolve_responses_response(&vault, &mut resp, &refs);

        let text = resp.output[0]["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "Contact alice@test.com");
    }
}
