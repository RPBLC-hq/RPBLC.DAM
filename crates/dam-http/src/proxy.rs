use crate::anthropic::{
    ContentBlock, MessageContent, MessagesRequest, MessagesResponse, ResponseBlock,
};
use crate::openai::{ChatContent, ChatMessage, ChatRequest, ChatResponse, ContentPart};
use crate::resolve::resolve_text;
use dam_core::DamConfig;
use dam_detect::DetectionPipeline;
use dam_vault::VaultStore;
use serde_json::Value;
use std::sync::Arc;

/// Recursively scan a JSON value for PII strings and replace them.
pub(crate) fn scan_json_value(
    pipeline: &DetectionPipeline,
    value: &mut Value,
) -> Result<(), dam_core::DamError> {
    match value {
        Value::String(s) => {
            let result = pipeline.scan(s, Some("http-proxy"))?;
            *s = result.redacted_text;
        }
        Value::Array(arr) => {
            for item in arr {
                scan_json_value(pipeline, item)?;
            }
        }
        Value::Object(map) => {
            for val in map.values_mut() {
                scan_json_value(pipeline, val)?;
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
pub fn redact_request(
    pipeline: &DetectionPipeline,
    request: &mut MessagesRequest,
) -> Result<(), dam_core::DamError> {
    // Scan model field
    let result = pipeline.scan(&request.model, Some("http-proxy"))?;
    request.model = result.redacted_text;

    // Scan system message if present
    if let Some(ref mut system) = request.system {
        let result = pipeline.scan(system, Some("http-proxy"))?;
        *system = result.redacted_text;
    }

    // Scan all extra fields (metadata, etc.)
    for value in request.extra.values_mut() {
        scan_json_value(pipeline, value)?;
    }

    // Scan user messages
    for message in &mut request.messages {
        if message.role != "user" {
            continue;
        }

        match &mut message.content {
            MessageContent::Text(text) => {
                let result = pipeline.scan(text, Some("http-proxy"))?;
                *text = result.redacted_text;
            }
            MessageContent::Blocks(blocks) => {
                for block in blocks {
                    if let ContentBlock::Text { text, .. } = block {
                        let result = pipeline.scan(text, Some("http-proxy"))?;
                        *text = result.redacted_text;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Resolve PII references in a non-streaming Anthropic response.
pub fn resolve_response(vault: &Arc<VaultStore>, response: &mut MessagesResponse) {
    for block in &mut response.content {
        if let ResponseBlock::Text { text, .. } = block {
            *text = resolve_text(vault, text);
        }
    }
}

/// Recursively resolve PII references in a JSON value.
pub(crate) fn resolve_json_value(vault: &Arc<VaultStore>, value: &mut Value) {
    match value {
        Value::String(s) => {
            *s = resolve_text(vault, s);
        }
        Value::Array(arr) => {
            for item in arr {
                resolve_json_value(vault, item);
            }
        }
        Value::Object(map) => {
            for val in map.values_mut() {
                resolve_json_value(vault, val);
            }
        }
        _ => {}
    }
}

/// Scan an OpenAI ChatMessage for PII and replace with vault references.
fn redact_chat_message(
    pipeline: &DetectionPipeline,
    message: &mut ChatMessage,
) -> Result<(), dam_core::DamError> {
    if let Some(ref mut content) = message.content {
        match content {
            ChatContent::Text(text) => {
                let result = pipeline.scan(text, Some("http-proxy"))?;
                *text = result.redacted_text;
            }
            ChatContent::Parts(parts) => {
                for part in parts {
                    if let ContentPart::Text { text, .. } = part {
                        let result = pipeline.scan(text, Some("http-proxy"))?;
                        *text = result.redacted_text;
                    }
                }
            }
        }
    }
    // Scan extra fields (e.g. name, tool_call arguments)
    for value in message.extra.values_mut() {
        scan_json_value(pipeline, value)?;
    }
    Ok(())
}

/// Scan user and system messages in an OpenAI ChatRequest for PII.
///
/// Scans user messages, system messages, and all extra fields.
/// Assistant and tool messages are skipped.
pub fn redact_chat_request(
    pipeline: &DetectionPipeline,
    request: &mut ChatRequest,
) -> Result<(), dam_core::DamError> {
    // Scan all extra fields
    for value in request.extra.values_mut() {
        scan_json_value(pipeline, value)?;
    }

    // Scan user and system messages
    for message in &mut request.messages {
        match message.role.as_str() {
            "user" | "system" => {
                redact_chat_message(pipeline, message)?;
            }
            _ => {} // Skip assistant, tool messages
        }
    }
    Ok(())
}

/// Resolve PII references in a non-streaming OpenAI ChatResponse.
pub fn resolve_chat_response(vault: &Arc<VaultStore>, response: &mut ChatResponse) {
    for choice in &mut response.choices {
        if let Some(ref mut content) = choice.message.content {
            *content = resolve_text(vault, content);
        }
        // Resolve refs in choice extras (e.g. tool_calls arguments)
        for value in choice.message.extra.values_mut() {
            resolve_json_value(vault, value);
        }
        for value in choice.extra.values_mut() {
            resolve_json_value(vault, value);
        }
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
}

impl AppState {
    /// Create application state from config and vault.
    pub fn new(config: &DamConfig, vault: Arc<VaultStore>) -> Self {
        let pipeline = Arc::new(DetectionPipeline::new(config, vault.clone()));
        let client = reqwest::Client::new();

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

        Self {
            vault,
            pipeline,
            client,
            anthropic_upstream_url,
            openai_upstream_url,
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
    use std::collections::HashMap;

    fn test_setup() -> (Arc<VaultStore>, DetectionPipeline) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join("test.db");
        let vault = Arc::new(VaultStore::open(&path, generate_kek()).unwrap());
        let pipeline = DetectionPipeline::basic(vault.clone());
        (vault, pipeline)
    }

    #[test]
    fn redact_user_text_message() {
        let (_vault, pipeline) = test_setup();
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

        redact_request(&pipeline, &mut req).unwrap();

        if let MessageContent::Text(ref text) = req.messages[0].content {
            assert!(!text.contains("john@acme.com"));
            assert!(text.contains("[email:"));
        } else {
            panic!("expected Text");
        }
    }

    #[test]
    fn redact_skips_assistant_messages() {
        let (_vault, pipeline) = test_setup();
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

        redact_request(&pipeline, &mut req).unwrap();

        // Assistant message should be untouched
        if let MessageContent::Text(ref text) = req.messages[1].content {
            assert_eq!(text, "I see [email:abcd1234]");
        }
    }

    #[test]
    fn redact_system_message() {
        let (_vault, pipeline) = test_setup();
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

        redact_request(&pipeline, &mut req).unwrap();

        let system = req.system.as_ref().unwrap();
        assert!(!system.contains("contact@secret.com"));
        assert!(system.contains("[email:"));
    }

    #[test]
    fn redact_model_field() {
        let (_vault, pipeline) = test_setup();
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

        redact_request(&pipeline, &mut req).unwrap();

        assert!(!req.model.contains("leak@evil.com"));
        assert!(req.model.contains("[email:"));
    }

    #[test]
    fn redact_metadata_field() {
        let (_vault, pipeline) = test_setup();
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

        redact_request(&pipeline, &mut req).unwrap();

        let metadata = req.extra.get("metadata").unwrap();
        let user_email = metadata["user_email"].as_str().unwrap();
        assert!(!user_email.contains("leak@metadata.com"));
        assert!(user_email.contains("[email:"));
    }

    #[test]
    fn redact_deeply_nested_extra_fields() {
        let (_vault, pipeline) = test_setup();
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

        redact_request(&pipeline, &mut req).unwrap();

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

        resolve_response(&vault, &mut resp);

        if let ResponseBlock::Text { ref text, .. } = resp.content[0] {
            assert_eq!(text, "Contact alice@test.com");
        }
    }

    // --- OpenAI-specific tests ---

    #[test]
    fn redact_chat_user_text() {
        let (_vault, pipeline) = test_setup();
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

        redact_chat_request(&pipeline, &mut req).unwrap();

        if let Some(ChatContent::Text(ref text)) = req.messages[0].content {
            assert!(!text.contains("john@acme.com"));
            assert!(text.contains("[email:"));
        } else {
            panic!("expected Text content");
        }
    }

    #[test]
    fn redact_chat_system_message() {
        let (_vault, pipeline) = test_setup();
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

        redact_chat_request(&pipeline, &mut req).unwrap();

        if let Some(ChatContent::Text(ref text)) = req.messages[0].content {
            assert!(!text.contains("contact@secret.com"));
            assert!(text.contains("[email:"));
        }
    }

    #[test]
    fn redact_chat_skips_assistant() {
        let (_vault, pipeline) = test_setup();
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

        redact_chat_request(&pipeline, &mut req).unwrap();

        if let Some(ChatContent::Text(ref text)) = req.messages[1].content {
            assert_eq!(text, "I see [email:abcd1234]");
        }
    }

    #[test]
    fn redact_chat_parts_content() {
        let (_vault, pipeline) = test_setup();
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

        redact_chat_request(&pipeline, &mut req).unwrap();

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

        resolve_chat_response(&vault, &mut resp);

        assert_eq!(
            resp.choices[0].message.content.as_deref(),
            Some("Contact alice@test.com")
        );
    }
}
