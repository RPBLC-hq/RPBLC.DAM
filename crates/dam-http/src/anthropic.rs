use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Anthropic Messages API request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A single message in the conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: MessageContent,
}

/// Message content: either a plain string or structured blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

/// A content block within a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentBlock {
    #[serde(rename = "text")]
    Text {
        text: String,
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
    #[serde(rename = "image")]
    Image {
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
    #[serde(rename = "tool_use")]
    ToolUse {
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
    #[serde(other)]
    Other,
}

/// Anthropic Messages API response body (non-streaming).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesResponse {
    pub id: String,
    #[serde(rename = "type")]
    pub response_type: String,
    pub role: String,
    pub content: Vec<ResponseBlock>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A content block in the response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ResponseBlock {
    #[serde(rename = "text")]
    Text {
        text: String,
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
    #[serde(rename = "tool_use")]
    ToolUse {
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
    #[serde(other)]
    Other,
}

/// SSE event types from the streaming API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StreamEvent {
    #[serde(rename = "message_start")]
    MessageStart { message: serde_json::Value },
    #[serde(rename = "content_block_start")]
    ContentBlockStart {
        index: usize,
        content_block: serde_json::Value,
    },
    #[serde(rename = "content_block_delta")]
    ContentBlockDelta { index: usize, delta: Delta },
    #[serde(rename = "content_block_stop")]
    ContentBlockStop { index: usize },
    #[serde(rename = "message_delta")]
    MessageDelta {
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
    #[serde(rename = "message_stop")]
    MessageStop {},
    #[serde(rename = "ping")]
    Ping {},
    #[serde(rename = "error")]
    Error { error: serde_json::Value },
}

/// Delta within a content_block_delta event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Delta {
    #[serde(rename = "text_delta")]
    TextDelta { text: String },
    #[serde(rename = "input_json_delta")]
    InputJsonDelta { partial_json: String },
    #[serde(other)]
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_string_content() {
        let json = r#"{
            "model": "claude-sonnet-4-5-20250929",
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        }"#;
        let req: MessagesRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.model, "claude-sonnet-4-5-20250929");
        assert_eq!(req.messages.len(), 1);
        assert!(matches!(req.messages[0].content, MessageContent::Text(ref s) if s == "Hello"));
    }

    #[test]
    fn parse_request_block_content() {
        let json = r#"{
            "model": "claude-sonnet-4-5-20250929",
            "max_tokens": 1024,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Describe this image"},
                        {"type": "image", "source": {"type": "base64", "data": "abc"}}
                    ]
                }
            ]
        }"#;
        let req: MessagesRequest = serde_json::from_str(json).unwrap();
        if let MessageContent::Blocks(ref blocks) = req.messages[0].content {
            assert_eq!(blocks.len(), 2);
            assert!(matches!(blocks[0], ContentBlock::Text { .. }));
            assert!(matches!(blocks[1], ContentBlock::Image { .. }));
        } else {
            panic!("expected Blocks");
        }
    }

    #[test]
    fn parse_response() {
        let json = r#"{
            "id": "msg_01",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Hello [email:abcd1234]!"}
            ],
            "model": "claude-sonnet-4-5-20250929",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5}
        }"#;
        let resp: MessagesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "msg_01");
        assert_eq!(resp.content.len(), 1);
        if let ResponseBlock::Text { ref text, .. } = resp.content[0] {
            assert!(text.contains("[email:abcd1234]"));
        } else {
            panic!("expected Text block");
        }
    }

    #[test]
    fn roundtrip_request_preserves_extra_fields() {
        let json = r#"{
            "model": "claude-sonnet-4-5-20250929",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "Hi"}],
            "temperature": 0.5,
            "system": "You are helpful"
        }"#;
        let req: MessagesRequest = serde_json::from_str(json).unwrap();
        let output = serde_json::to_string(&req).unwrap();
        assert!(output.contains("temperature"));
        assert!(output.contains("system"));
    }

    #[test]
    fn parse_stream_events() {
        let text_delta = r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}"#;
        let event: StreamEvent = serde_json::from_str(text_delta).unwrap();
        if let StreamEvent::ContentBlockDelta { index, delta } = event {
            assert_eq!(index, 0);
            assert!(matches!(delta, Delta::TextDelta { ref text } if text == "Hello"));
        } else {
            panic!("expected ContentBlockDelta");
        }

        let stop = r#"{"type":"content_block_stop","index":0}"#;
        let event: StreamEvent = serde_json::from_str(stop).unwrap();
        assert!(matches!(event, StreamEvent::ContentBlockStop { index: 0 }));

        let ping = r#"{"type":"ping"}"#;
        let event: StreamEvent = serde_json::from_str(ping).unwrap();
        assert!(matches!(event, StreamEvent::Ping {}));
    }
}
