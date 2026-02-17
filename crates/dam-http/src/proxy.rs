use crate::anthropic::{
    ContentBlock, MessageContent, MessagesRequest, MessagesResponse, ResponseBlock,
};
use crate::resolve::resolve_text;
use dam_core::DamConfig;
use dam_detect::DetectionPipeline;
use dam_vault::VaultStore;
use serde_json::Value;
use std::sync::Arc;

/// Recursively scan a JSON value for PII strings and replace them.
fn scan_json_value(
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

/// Resolve PII references in a non-streaming response.
pub fn resolve_response(vault: &Arc<VaultStore>, response: &mut MessagesResponse) {
    for block in &mut response.content {
        if let ResponseBlock::Text { text, .. } = block {
            *text = resolve_text(vault, text);
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
    /// Base URL of the upstream API (e.g. `https://api.anthropic.com`).
    pub upstream_url: String,
}

impl AppState {
    /// Create application state from config and vault, targeting the Anthropic API.
    pub fn new(config: &DamConfig, vault: Arc<VaultStore>) -> Self {
        let pipeline = Arc::new(DetectionPipeline::new(config, vault.clone()));
        let client = reqwest::Client::new();
        let upstream_url = "https://api.anthropic.com".to_string();

        Self {
            vault,
            pipeline,
            client,
            upstream_url,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::{Message, MessagesResponse, ResponseBlock};
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
}
