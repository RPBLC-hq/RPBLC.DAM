use crate::anthropic::{
    ContentBlock, MessageContent, MessagesRequest, MessagesResponse, ResponseBlock,
};
use crate::resolve::resolve_text;
use dam_core::DamConfig;
use dam_detect::DetectionPipeline;
use dam_vault::VaultStore;
use std::sync::Arc;

/// Scan user messages in a request for PII and replace with vault references.
///
/// Only user messages are scanned — assistant messages already contain
/// references from previous turns.
pub fn redact_request(
    pipeline: &DetectionPipeline,
    request: &mut MessagesRequest,
) -> Result<(), dam_core::DamError> {
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

/// Shared application state passed to handlers.
#[derive(Clone)]
pub struct AppState {
    pub vault: Arc<VaultStore>,
    pub pipeline: Arc<DetectionPipeline>,
    pub client: reqwest::Client,
    pub upstream_url: String,
}

impl AppState {
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
            extra: HashMap::new(),
        };

        redact_request(&pipeline, &mut req).unwrap();

        // Assistant message should be untouched
        if let MessageContent::Text(ref text) = req.messages[1].content {
            assert_eq!(text, "I see [email:abcd1234]");
        }
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
