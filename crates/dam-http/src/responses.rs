use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// OpenAI Responses API request body (`POST /v1/responses`).
///
/// Known fields are parsed explicitly; unknown fields (e.g. `previous_response_id`,
/// `tools`, `store`) are captured in `extra` via `serde(flatten)` for passthrough.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsesRequest {
    /// Model identifier (e.g. `"gpt-4o"`, `"o3"`).
    pub model: String,
    /// Input: either a plain string or an array of input items.
    pub input: serde_json::Value,
    /// System-level instructions (scanned for PII).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    /// Whether to stream the response as SSE events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// All other API fields, preserved for passthrough.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// OpenAI Responses API response body (non-streaming).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsesResponse {
    /// Unique response identifier.
    pub id: String,
    /// Output items (messages, function calls, etc.).
    pub output: Vec<serde_json::Value>,
    /// All other response fields (e.g. `status`, `usage`, `model`).
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A streaming SSE event from the Responses API.
///
/// Responses API streaming uses `event: <type>\ndata: <json>\n\n` format
/// (like Anthropic, unlike Chat Completions which omits `event:` lines).
///
/// We only parse the events we need to intercept for PII resolution;
/// everything else passes through unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsesStreamDelta {
    /// The delta text fragment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta: Option<String>,
    /// Item ID for correlating deltas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    /// Output index within the response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_index: Option<usize>,
    /// Content index within an output item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_index: Option<usize>,
    /// All other fields.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_string_input() {
        let json = r#"{
            "model": "gpt-4o",
            "input": "Tell me about Alice",
            "stream": false
        }"#;
        let req: ResponsesRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.model, "gpt-4o");
        assert!(req.input.is_string());
        assert_eq!(req.stream, Some(false));
        assert!(req.instructions.is_none());
    }

    #[test]
    fn parse_request_array_input() {
        let json = r#"{
            "model": "gpt-4o",
            "input": [
                {
                    "type": "message",
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": "Hello world"}
                    ]
                }
            ],
            "instructions": "You are a helpful assistant"
        }"#;
        let req: ResponsesRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.model, "gpt-4o");
        assert!(req.input.is_array());
        assert_eq!(
            req.instructions.as_deref(),
            Some("You are a helpful assistant")
        );
    }

    #[test]
    fn parse_request_preserves_extras() {
        let json = r#"{
            "model": "gpt-4o",
            "input": "Hello",
            "previous_response_id": "resp_abc123",
            "store": true,
            "tools": [{"type": "web_search"}]
        }"#;
        let req: ResponsesRequest = serde_json::from_str(json).unwrap();
        assert!(req.extra.contains_key("previous_response_id"));
        assert!(req.extra.contains_key("store"));
        assert!(req.extra.contains_key("tools"));

        // Roundtrip preserves extras
        let output = serde_json::to_string(&req).unwrap();
        assert!(output.contains("previous_response_id"));
        assert!(output.contains("store"));
    }

    #[test]
    fn parse_response() {
        let json = r#"{
            "id": "resp_abc123",
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [
                        {"type": "output_text", "text": "Hello [email:abcd1234]!"}
                    ]
                }
            ],
            "status": "completed",
            "model": "gpt-4o",
            "usage": {"input_tokens": 10, "output_tokens": 5}
        }"#;
        let resp: ResponsesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "resp_abc123");
        assert_eq!(resp.output.len(), 1);
        assert!(resp.extra.contains_key("status"));
        assert!(resp.extra.contains_key("usage"));
    }

    #[test]
    fn parse_stream_delta() {
        let json = r#"{
            "delta": "Hello world",
            "item_id": "item_abc",
            "output_index": 0,
            "content_index": 0
        }"#;
        let delta: ResponsesStreamDelta = serde_json::from_str(json).unwrap();
        assert_eq!(delta.delta.as_deref(), Some("Hello world"));
        assert_eq!(delta.item_id.as_deref(), Some("item_abc"));
        assert_eq!(delta.output_index, Some(0));
        assert_eq!(delta.content_index, Some(0));
    }

    #[test]
    fn parse_stream_delta_minimal() {
        let json = r#"{"delta": "text fragment"}"#;
        let delta: ResponsesStreamDelta = serde_json::from_str(json).unwrap();
        assert_eq!(delta.delta.as_deref(), Some("text fragment"));
        assert!(delta.item_id.is_none());
        assert!(delta.output_index.is_none());
    }

    #[test]
    fn roundtrip_response() {
        let resp = ResponsesResponse {
            id: "resp_test".into(),
            output: vec![serde_json::json!({
                "type": "message",
                "content": [{"type": "output_text", "text": "hi"}]
            })],
            extra: {
                let mut m = HashMap::new();
                m.insert("status".into(), serde_json::json!("completed"));
                m
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ResponsesResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "resp_test");
        assert_eq!(parsed.output.len(), 1);
    }
}
