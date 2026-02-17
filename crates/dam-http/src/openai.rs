use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// OpenAI Chat Completions API request body.
///
/// Known fields are parsed explicitly; unknown fields (e.g. `temperature`,
/// `top_p`) are captured in `extra` via `serde(flatten)` for passthrough.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    /// Model identifier (e.g. `"gpt-4o"`).
    pub model: String,
    /// Conversation messages (including system messages).
    pub messages: Vec<ChatMessage>,
    /// Maximum tokens to generate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Whether to stream the response as SSE events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// All other API fields, preserved for passthrough.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A single message in the OpenAI conversation.
///
/// Content is `Option` because tool-call messages may have `null` content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Message role: `"system"`, `"user"`, `"assistant"`, or `"tool"`.
    pub role: String,
    /// Message content (text string, content parts array, or null).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<ChatContent>,
    /// All other fields (e.g. `name`, `tool_calls`, `tool_call_id`).
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Message content: either a plain string or an array of content parts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ChatContent {
    /// Simple text content.
    Text(String),
    /// Array of typed content parts (text, image_url, etc.).
    Parts(Vec<ContentPart>),
}

/// A content part within a multi-part message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentPart {
    /// Text content part.
    #[serde(rename = "text")]
    Text {
        text: String,
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
    /// Image URL content part.
    #[serde(rename = "image_url")]
    ImageUrl {
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
    /// Forward-compatible catch-all for unknown part types.
    #[serde(other)]
    Other,
}

/// OpenAI Chat Completions API response body (non-streaming).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    /// Unique completion identifier.
    pub id: String,
    /// Object type, always `"chat.completion"`.
    pub object: String,
    /// Response choices.
    pub choices: Vec<Choice>,
    /// All other response fields (e.g. `usage`, `created`, `model`).
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A single choice in the non-streaming response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Choice {
    /// Choice index.
    pub index: usize,
    /// The generated message.
    pub message: ChoiceMessage,
    /// Reason the generation stopped.
    pub finish_reason: Option<String>,
    /// All other fields.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// The message within a response choice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChoiceMessage {
    /// Always `"assistant"`.
    pub role: String,
    /// Generated text content (may be null for tool-call-only responses).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// All other fields (e.g. `tool_calls`, `refusal`).
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A streaming chunk from the OpenAI Chat Completions API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatChunk {
    /// Chunk identifier (same across all chunks in a stream).
    pub id: String,
    /// Object type, always `"chat.completion.chunk"`.
    pub object: String,
    /// Chunk choices (usually one).
    pub choices: Vec<ChunkChoice>,
    /// All other fields (e.g. `created`, `model`).
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A single choice within a streaming chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkChoice {
    /// Choice index.
    pub index: usize,
    /// The delta for this chunk.
    pub delta: ChunkDelta,
    /// Finish reason (`"stop"`, `"length"`, etc.) — present in the final chunk.
    pub finish_reason: Option<String>,
    /// All other fields.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// The delta payload within a streaming chunk choice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkDelta {
    /// Text content fragment (present in content chunks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Role (present in the first chunk only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// All other fields (e.g. `tool_calls`).
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_string_content() {
        let json = r#"{
            "model": "gpt-4o",
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        }"#;
        let req: ChatRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.model, "gpt-4o");
        assert_eq!(req.messages.len(), 1);
        assert!(matches!(req.messages[0].content, Some(ChatContent::Text(ref s)) if s == "Hello"));
    }

    #[test]
    fn parse_request_parts_content() {
        let json = r#"{
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Describe this image"},
                        {"type": "image_url", "image_url": {"url": "https://example.com/img.png"}}
                    ]
                }
            ]
        }"#;
        let req: ChatRequest = serde_json::from_str(json).unwrap();
        if let Some(ChatContent::Parts(ref parts)) = req.messages[0].content {
            assert_eq!(parts.len(), 2);
            assert!(matches!(parts[0], ContentPart::Text { .. }));
            assert!(matches!(parts[1], ContentPart::ImageUrl { .. }));
        } else {
            panic!("expected Parts content");
        }
    }

    #[test]
    fn parse_response() {
        let json = r#"{
            "id": "chatcmpl-abc123",
            "object": "chat.completion",
            "created": 1700000000,
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Hello [email:abcd1234]!"
                    },
                    "finish_reason": "stop"
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        }"#;
        let resp: ChatResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "chatcmpl-abc123");
        assert_eq!(resp.choices.len(), 1);
        assert_eq!(
            resp.choices[0].message.content.as_deref(),
            Some("Hello [email:abcd1234]!")
        );
    }

    #[test]
    fn parse_chunk() {
        let json = r#"{
            "id": "chatcmpl-abc123",
            "object": "chat.completion.chunk",
            "created": 1700000000,
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": "Hello"},
                    "finish_reason": null
                }
            ]
        }"#;
        let chunk: ChatChunk = serde_json::from_str(json).unwrap();
        assert_eq!(chunk.choices[0].delta.content.as_deref(), Some("Hello"));
        assert!(chunk.choices[0].finish_reason.is_none());
    }

    #[test]
    fn roundtrip_preserves_extras() {
        let json = r#"{
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hi"}],
            "temperature": 0.7,
            "top_p": 0.9,
            "stream": true
        }"#;
        let req: ChatRequest = serde_json::from_str(json).unwrap();
        let output = serde_json::to_string(&req).unwrap();
        assert!(output.contains("temperature"));
        assert!(output.contains("top_p"));
        assert!(output.contains("\"stream\":true"));
    }

    #[test]
    fn system_message_in_messages() {
        let json = r#"{
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are helpful"},
                {"role": "user", "content": "Hi"}
            ]
        }"#;
        let req: ChatRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.messages.len(), 2);
        assert_eq!(req.messages[0].role, "system");
        assert!(
            matches!(req.messages[0].content, Some(ChatContent::Text(ref s)) if s == "You are helpful")
        );
    }

    #[test]
    fn null_content_tool_call_message() {
        let json = r#"{
            "model": "gpt-4o",
            "messages": [
                {"role": "assistant", "content": null, "tool_calls": []}
            ]
        }"#;
        let req: ChatRequest = serde_json::from_str(json).unwrap();
        assert!(req.messages[0].content.is_none());
        assert!(req.messages[0].extra.contains_key("tool_calls"));
    }

    #[test]
    fn parse_chunk_with_stop() {
        let json = r#"{
            "id": "chatcmpl-abc123",
            "object": "chat.completion.chunk",
            "created": 1700000000,
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "delta": {},
                    "finish_reason": "stop"
                }
            ]
        }"#;
        let chunk: ChatChunk = serde_json::from_str(json).unwrap();
        assert_eq!(chunk.choices[0].finish_reason.as_deref(), Some("stop"));
        assert!(chunk.choices[0].delta.content.is_none());
    }
}
