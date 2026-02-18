use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use bytes::BytesMut;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;

use crate::anthropic::{Delta, MessagesRequest, MessagesResponse, StreamEvent};
use crate::error::AppError;
use crate::openai::{ChatChunk, ChatRequest, ChatResponse};
use crate::proxy::{
    AppState, redact_chat_request, redact_request, resolve_chat_response, resolve_response,
};
use crate::streaming::StreamingResolver;

/// Build the axum router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/messages", post(handle_messages))
        .route("/v1/chat/completions", post(handle_chat_completions))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Shared SSE buffer
// ---------------------------------------------------------------------------

/// Reusable SSE byte buffer that splits raw bytes into complete events.
///
/// An SSE event is terminated by `\n\n` (or `\r\n\r\n`). This struct buffers
/// incoming bytes and yields complete events one at a time.
pub(crate) struct SseBuffer {
    pub(crate) raw_buf: BytesMut,
}

impl SseBuffer {
    pub(crate) fn new() -> Self {
        Self {
            raw_buf: BytesMut::new(),
        }
    }

    /// Feed raw bytes from the upstream response.
    pub(crate) fn feed(&mut self, chunk: &[u8]) {
        self.raw_buf.extend_from_slice(chunk);
    }

    /// Extract the next complete SSE event (terminated by `\n\n`).
    pub(crate) fn next_event(&mut self) -> Option<Vec<u8>> {
        let buf = &self.raw_buf[..];
        // Look for \n\n
        for i in 0..buf.len().saturating_sub(1) {
            if buf[i] == b'\n' && buf[i + 1] == b'\n' {
                let event = self.raw_buf.split_to(i + 2).to_vec();
                return Some(event);
            }
        }
        // Also check for \r\n\r\n
        for i in 0..buf.len().saturating_sub(3) {
            if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n'
            {
                let event = self.raw_buf.split_to(i + 4).to_vec();
                return Some(event);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Anthropic SSE handler
// ---------------------------------------------------------------------------

/// Headers to forward from the client to Anthropic.
const ANTHROPIC_FORWARD_HEADERS: &[&str] = &[
    "x-api-key",
    "authorization",
    "anthropic-version",
    "anthropic-beta",
    "content-type",
];

/// POST /v1/messages handler.
async fn handle_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let mut request: MessagesRequest =
        serde_json::from_str(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let is_streaming = request.stream.unwrap_or(false);
    tracing::debug!(model = %request.model, streaming = is_streaming, "incoming request");

    redact_request(&state.pipeline, &mut request)?;
    tracing::debug!("request redacted");

    let upstream_url = format!("{}/v1/messages", state.anthropic_upstream_url);
    let mut upstream_req = state.client.post(&upstream_url);

    for &name in ANTHROPIC_FORWARD_HEADERS {
        if let Some(value) = headers.get(name) {
            upstream_req = upstream_req.header(name, value);
        }
    }
    upstream_req = upstream_req.header("content-type", "application/json");

    let upstream_body =
        serde_json::to_string(&request).map_err(|e| AppError::Proxy(e.to_string()))?;

    let upstream_resp = upstream_req.body(upstream_body).send().await?;

    let status = upstream_resp.status();
    tracing::debug!(status = %status, "upstream response");

    if !status.is_success() {
        return pass_through_error(upstream_resp).await;
    }

    if is_streaming {
        handle_anthropic_streaming(state, upstream_resp).await
    } else {
        handle_anthropic_non_streaming(state, upstream_resp).await
    }
}

/// Handle a non-streaming Anthropic response.
async fn handle_anthropic_non_streaming(
    state: AppState,
    upstream_resp: reqwest::Response,
) -> Result<Response, AppError> {
    let body = upstream_resp.text().await?;
    let mut response: MessagesResponse =
        serde_json::from_str(&body).map_err(|e| AppError::Upstream(e.to_string()))?;

    resolve_response(&state.vault, &mut response);

    let json = serde_json::to_string(&response).map_err(|e| AppError::Proxy(e.to_string()))?;

    Ok((StatusCode::OK, [("content-type", "application/json")], json).into_response())
}

/// Handle a streaming Anthropic response.
async fn handle_anthropic_streaming(
    state: AppState,
    upstream_resp: reqwest::Response,
) -> Result<Response, AppError> {
    let vault = state.vault.clone();
    let byte_stream = upstream_resp.bytes_stream();

    let stream = async_stream::stream! {
        let mut sse_state = AnthropicSseState::new(vault);

        tokio::pin!(byte_stream);

        while let Some(chunk_result) = byte_stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    sse_state.buf.feed(&chunk);
                    while let Some(event_bytes) = sse_state.buf.next_event() {
                        let output = sse_state.process_event(&event_bytes);
                        yield Ok::<_, std::io::Error>(axum::body::Bytes::from(output));
                    }
                }
                Err(e) => {
                    yield Err(std::io::Error::other(e.to_string()));
                    break;
                }
            }
        }

        // Flush remaining SSE bytes
        if !sse_state.buf.raw_buf.is_empty() {
            if let Ok(s) = std::str::from_utf8(&sse_state.buf.raw_buf) {
                yield Ok::<_, std::io::Error>(axum::body::Bytes::from(s.to_owned()));
            }
            sse_state.buf.raw_buf.clear();
        }

        // Flush remaining resolver buffers
        for (_, mut resolver) in sse_state.resolvers.drain() {
            let remaining = resolver.finish();
            if !remaining.is_empty() {
                yield Ok::<_, std::io::Error>(axum::body::Bytes::from(remaining));
            }
        }
    };

    let body = Body::from_stream(stream);

    Ok((
        StatusCode::OK,
        [
            ("content-type", "text/event-stream"),
            ("cache-control", "no-cache"),
        ],
        body,
    )
        .into_response())
}

/// Anthropic SSE state: buffer + per-content-block resolvers.
struct AnthropicSseState {
    vault: Arc<dam_vault::VaultStore>,
    buf: SseBuffer,
    resolvers: HashMap<usize, StreamingResolver>,
}

impl AnthropicSseState {
    fn new(vault: Arc<dam_vault::VaultStore>) -> Self {
        Self {
            vault,
            buf: SseBuffer::new(),
            resolvers: HashMap::new(),
        }
    }

    fn process_event(&mut self, event_bytes: &[u8]) -> Vec<u8> {
        let event_str = match std::str::from_utf8(event_bytes) {
            Ok(s) => s,
            Err(_) => return event_bytes.to_vec(),
        };

        let mut event_type = None;
        let mut data = None;

        for line in event_str.lines() {
            if let Some(val) = line.strip_prefix("event:") {
                event_type = Some(val.trim());
            } else if let Some(val) = line.strip_prefix("data:") {
                data = Some(val.trim());
            }
        }

        let (Some(event_type), Some(data)) = (event_type, data) else {
            return event_bytes.to_vec();
        };

        match event_type {
            "content_block_delta" => self.handle_delta(event_str, data),
            "content_block_stop" => self.handle_stop(event_str, data),
            _ => event_bytes.to_vec(),
        }
    }

    fn handle_delta(&mut self, original: &str, data: &str) -> Vec<u8> {
        let Ok(event) = serde_json::from_str::<StreamEvent>(data) else {
            return original.as_bytes().to_vec();
        };

        let StreamEvent::ContentBlockDelta { index, delta } = &event else {
            return original.as_bytes().to_vec();
        };

        let Delta::TextDelta { text } = delta else {
            return original.as_bytes().to_vec();
        };

        let resolver = self
            .resolvers
            .entry(*index)
            .or_insert_with(|| StreamingResolver::new(self.vault.clone()));

        let resolved = resolver.push(text);

        let new_event = StreamEvent::ContentBlockDelta {
            index: *index,
            delta: Delta::TextDelta { text: resolved },
        };

        let new_data = serde_json::to_string(&new_event).unwrap_or_else(|_| data.to_string());
        format!("event: content_block_delta\ndata: {new_data}\n\n").into_bytes()
    }

    fn handle_stop(&mut self, original: &str, data: &str) -> Vec<u8> {
        let Ok(event) = serde_json::from_str::<StreamEvent>(data) else {
            return original.as_bytes().to_vec();
        };

        let StreamEvent::ContentBlockStop { index } = &event else {
            return original.as_bytes().to_vec();
        };

        let index = *index;
        let mut output = Vec::new();

        if let Some(mut resolver) = self.resolvers.remove(&index) {
            let remaining = resolver.finish();
            if !remaining.is_empty() {
                let flush_event = StreamEvent::ContentBlockDelta {
                    index,
                    delta: Delta::TextDelta { text: remaining },
                };
                let flush_data = serde_json::to_string(&flush_event).unwrap_or_default();
                output.extend_from_slice(
                    format!("event: content_block_delta\ndata: {flush_data}\n\n").as_bytes(),
                );
            }
        }

        output.extend_from_slice(original.as_bytes());
        output
    }
}

// ---------------------------------------------------------------------------
// OpenAI SSE handler
// ---------------------------------------------------------------------------

/// Headers to forward from the client to OpenAI-compatible APIs.
const OPENAI_FORWARD_HEADERS: &[&str] = &[
    "authorization",
    "openai-organization",
    "openai-project",
    "x-request-id",
];

/// POST /v1/chat/completions handler.
async fn handle_chat_completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let mut request: ChatRequest =
        serde_json::from_str(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let is_streaming = request.stream.unwrap_or(false);
    tracing::debug!(model = %request.model, streaming = is_streaming, "incoming openai request");

    redact_chat_request(&state.pipeline, &mut request)?;
    tracing::debug!("openai request redacted");

    let upstream_url = format!("{}/v1/chat/completions", state.openai_upstream_url);
    let mut upstream_req = state.client.post(&upstream_url);

    for &name in OPENAI_FORWARD_HEADERS {
        if let Some(value) = headers.get(name) {
            upstream_req = upstream_req.header(name, value);
        }
    }
    upstream_req = upstream_req.header("content-type", "application/json");

    let upstream_body =
        serde_json::to_string(&request).map_err(|e| AppError::Proxy(e.to_string()))?;

    let upstream_resp = upstream_req.body(upstream_body).send().await?;

    let status = upstream_resp.status();
    tracing::debug!(status = %status, "openai upstream response");

    if !status.is_success() {
        return pass_through_error(upstream_resp).await;
    }

    if is_streaming {
        handle_openai_streaming(state, upstream_resp).await
    } else {
        handle_openai_non_streaming(state, upstream_resp).await
    }
}

/// Handle a non-streaming OpenAI response.
async fn handle_openai_non_streaming(
    state: AppState,
    upstream_resp: reqwest::Response,
) -> Result<Response, AppError> {
    let body = upstream_resp.text().await?;
    let mut response: ChatResponse =
        serde_json::from_str(&body).map_err(|e| AppError::Upstream(e.to_string()))?;

    resolve_chat_response(&state.vault, &mut response);

    let json = serde_json::to_string(&response).map_err(|e| AppError::Proxy(e.to_string()))?;

    Ok((StatusCode::OK, [("content-type", "application/json")], json).into_response())
}

/// Handle a streaming OpenAI response.
async fn handle_openai_streaming(
    state: AppState,
    upstream_resp: reqwest::Response,
) -> Result<Response, AppError> {
    let vault = state.vault.clone();
    let byte_stream = upstream_resp.bytes_stream();

    let stream = async_stream::stream! {
        let mut sse_state = OpenAiSseState::new(vault);

        tokio::pin!(byte_stream);

        while let Some(chunk_result) = byte_stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    sse_state.buf.feed(&chunk);
                    while let Some(event_bytes) = sse_state.buf.next_event() {
                        for output in sse_state.process_event(&event_bytes) {
                            yield Ok::<_, std::io::Error>(axum::body::Bytes::from(output));
                        }
                    }
                }
                Err(e) => {
                    yield Err(std::io::Error::other(e.to_string()));
                    break;
                }
            }
        }

        // Flush remaining SSE bytes
        if !sse_state.buf.raw_buf.is_empty() {
            if let Ok(s) = std::str::from_utf8(&sse_state.buf.raw_buf) {
                yield Ok::<_, std::io::Error>(axum::body::Bytes::from(s.to_owned()));
            }
            sse_state.buf.raw_buf.clear();
        }

        // Flush remaining resolver buffers as SSE-formatted events
        for (idx, mut resolver) in sse_state.resolvers.drain() {
            let remaining = resolver.finish();
            if !remaining.is_empty() {
                let flush_json = serde_json::json!({
                    "id": "", "object": "chat.completion.chunk",
                    "choices": [{"index": idx, "delta": {"content": remaining}, "finish_reason": null}]
                });
                let event = format!("data: {flush_json}\n\n");
                yield Ok::<_, std::io::Error>(axum::body::Bytes::from(event));
            }
        }
    };

    let body = Body::from_stream(stream);

    Ok((
        StatusCode::OK,
        [
            ("content-type", "text/event-stream"),
            ("cache-control", "no-cache"),
        ],
        body,
    )
        .into_response())
}

/// OpenAI SSE state: buffer + per-choice resolvers.
struct OpenAiSseState {
    vault: Arc<dam_vault::VaultStore>,
    buf: SseBuffer,
    resolvers: HashMap<usize, StreamingResolver>,
}

impl OpenAiSseState {
    fn new(vault: Arc<dam_vault::VaultStore>) -> Self {
        Self {
            vault,
            buf: SseBuffer::new(),
            resolvers: HashMap::new(),
        }
    }

    /// Process a complete SSE event. Returns zero or more output byte chunks.
    ///
    /// OpenAI SSE format: no `event:` line, only `data: <json>\n\n`.
    /// Terminal event: `data: [DONE]\n\n`.
    fn process_event(&mut self, event_bytes: &[u8]) -> Vec<Vec<u8>> {
        let event_str = match std::str::from_utf8(event_bytes) {
            Ok(s) => s,
            Err(_) => return vec![event_bytes.to_vec()],
        };

        // Extract the data line
        let mut data = None;
        for line in event_str.lines() {
            if let Some(val) = line.strip_prefix("data:") {
                data = Some(val.trim());
            }
        }

        let Some(data) = data else {
            return vec![event_bytes.to_vec()];
        };

        // Handle [DONE] sentinel — flush all resolvers, then pass through
        if data == "[DONE]" {
            let mut outputs = Vec::new();
            for (_, mut resolver) in self.resolvers.drain() {
                let remaining = resolver.finish();
                if !remaining.is_empty() {
                    // Wrap flushed text in a synthetic SSE data event
                    let flush_json = serde_json::json!({
                        "id": "", "object": "chat.completion.chunk",
                        "choices": [{"index": 0, "delta": {"content": remaining}, "finish_reason": null}]
                    });
                    outputs.push(format!("data: {flush_json}\n\n").into_bytes());
                }
            }
            outputs.push(event_bytes.to_vec());
            return outputs;
        }

        // Parse as ChatChunk
        let Ok(chunk) = serde_json::from_str::<ChatChunk>(data) else {
            return vec![event_bytes.to_vec()];
        };

        self.handle_chunk(chunk, data)
    }

    fn handle_chunk(&mut self, mut chunk: ChatChunk, original_data: &str) -> Vec<Vec<u8>> {
        let mut outputs = Vec::new();
        let mut modified = false;

        for choice in &mut chunk.choices {
            if let Some(ref text) = choice.delta.content {
                let resolver = self
                    .resolvers
                    .entry(choice.index)
                    .or_insert_with(|| StreamingResolver::new(self.vault.clone()));
                let resolved = resolver.push(text);
                choice.delta.content = Some(resolved);
                modified = true;
            }

            // Flush resolver on stop
            if choice.finish_reason.as_deref() == Some("stop")
                && let Some(mut resolver) = self.resolvers.remove(&choice.index)
            {
                let remaining = resolver.finish();
                if !remaining.is_empty() {
                    // Emit a synthetic delta chunk with the remaining text before stop
                    let flush_chunk = ChatChunk {
                        id: chunk.id.clone(),
                        object: chunk.object.clone(),
                        choices: vec![crate::openai::ChunkChoice {
                            index: choice.index,
                            delta: crate::openai::ChunkDelta {
                                content: Some(remaining),
                                role: None,
                                extra: HashMap::new(),
                            },
                            finish_reason: None,
                            extra: HashMap::new(),
                        }],
                        extra: chunk.extra.clone(),
                    };
                    if let Ok(flush_data) = serde_json::to_string(&flush_chunk) {
                        outputs.push(format!("data: {flush_data}\n\n").into_bytes());
                    }
                }
            }
        }

        if modified {
            let new_data =
                serde_json::to_string(&chunk).unwrap_or_else(|_| original_data.to_string());
            outputs.push(format!("data: {new_data}\n\n").into_bytes());
        } else {
            outputs.push(format!("data: {original_data}\n\n").into_bytes());
        }

        outputs
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Pass through an error response from upstream, preserving status and headers.
async fn pass_through_error(upstream_resp: reqwest::Response) -> Result<Response, AppError> {
    let status = upstream_resp.status();
    let upstream_status = StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(upstream_status);

    for name in &["content-type", "x-request-id", "request-id", "retry-after"] {
        if let Some(value) = upstream_resp.headers().get(*name) {
            builder = builder.header(*name, value);
        }
    }

    let body_bytes = upstream_resp.bytes().await.unwrap_or_default();
    let response = builder.body(Body::from(body_bytes)).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::empty())
            .unwrap()
    });
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dam_core::PiiType;
    use dam_vault::generate_kek;

    fn test_vault_with_entry() -> (Arc<dam_vault::VaultStore>, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join("test.db");
        let vault = Arc::new(dam_vault::VaultStore::open(&path, generate_kek()).unwrap());
        let pii_ref = vault
            .store_pii(PiiType::Email, "alice@example.com", None, None)
            .unwrap();
        (vault, pii_ref.key())
    }

    // --- SseBuffer tests ---

    #[test]
    fn sse_buffer_splits_events() {
        let mut buf = SseBuffer::new();
        buf.feed(b"event: ping\ndata: {}\n\nevent: message_start\ndata: {}\n\n");

        let ev1 = buf.next_event().unwrap();
        assert!(String::from_utf8_lossy(&ev1).contains("ping"));

        let ev2 = buf.next_event().unwrap();
        assert!(String::from_utf8_lossy(&ev2).contains("message_start"));

        assert!(buf.next_event().is_none());
    }

    // --- Anthropic SSE tests ---

    #[test]
    fn sse_state_splits_events() {
        let (vault, _) = test_vault_with_entry();
        let mut state = AnthropicSseState::new(vault);

        state.buf.feed(b"event: ping\ndata: {}\n\nevent: message_start\ndata: {\"type\":\"message_start\",\"message\":{}}\n\n");

        let ev1 = state.buf.next_event().unwrap();
        assert!(String::from_utf8_lossy(&ev1).contains("ping"));

        let ev2 = state.buf.next_event().unwrap();
        assert!(String::from_utf8_lossy(&ev2).contains("message_start"));

        assert!(state.buf.next_event().is_none());
    }

    #[test]
    fn sse_state_passthrough_non_text_events() {
        let (vault, _) = test_vault_with_entry();
        let mut state = AnthropicSseState::new(vault);

        let ping = b"event: ping\ndata: {\"type\":\"ping\"}\n\n";
        state.buf.feed(ping);

        let ev = state.buf.next_event().unwrap();
        let output = state.process_event(&ev);
        assert_eq!(output, ping.to_vec());
    }

    #[test]
    fn sse_state_resolves_text_delta() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = AnthropicSseState::new(vault);

        let data = format!(
            r#"{{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":"Hello [{}] world"}}}}"#,
            ref_key
        );
        let event = format!("event: content_block_delta\ndata: {data}\n\n");
        state.buf.feed(event.as_bytes());

        let ev = state.buf.next_event().unwrap();
        let output = state.process_event(&ev);
        let output_str = String::from_utf8(output).unwrap();

        assert!(output_str.contains("alice@example.com"));
        assert!(!output_str.contains(&format!("[{ref_key}]")));
    }

    // --- OpenAI SSE tests ---

    #[test]
    fn openai_sse_resolves_text_delta() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = OpenAiSseState::new(vault);

        let data = format!(
            r#"{{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{{"index":0,"delta":{{"content":"Hello [{ref_key}] world"}},"finish_reason":null}}]}}"#,
        );
        let event = format!("data: {data}\n\n");
        state.buf.feed(event.as_bytes());

        let ev = state.buf.next_event().unwrap();
        let outputs = state.process_event(&ev);
        assert_eq!(outputs.len(), 1);

        let output_str = String::from_utf8(outputs[0].clone()).unwrap();
        assert!(
            output_str.contains("alice@example.com"),
            "should resolve ref: {output_str}"
        );
        assert!(!output_str.contains(&format!("[{ref_key}]")));
    }

    #[test]
    fn openai_sse_passthrough_non_content_chunk() {
        let (vault, _) = test_vault_with_entry();
        let mut state = OpenAiSseState::new(vault);

        // A chunk with role only (first chunk in stream), no content
        let data = r#"{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}"#;
        let event = format!("data: {data}\n\n");
        state.buf.feed(event.as_bytes());

        let ev = state.buf.next_event().unwrap();
        let outputs = state.process_event(&ev);
        assert_eq!(outputs.len(), 1);

        let output_str = String::from_utf8(outputs[0].clone()).unwrap();
        assert!(output_str.contains("assistant"));
    }

    #[test]
    fn openai_sse_done_termination() {
        let (vault, _) = test_vault_with_entry();
        let mut state = OpenAiSseState::new(vault);

        let event = "data: [DONE]\n\n";
        state.buf.feed(event.as_bytes());

        let ev = state.buf.next_event().unwrap();
        let outputs = state.process_event(&ev);

        // Should pass through [DONE]
        let last = String::from_utf8(outputs.last().unwrap().clone()).unwrap();
        assert!(last.contains("[DONE]"));
    }

    #[test]
    fn openai_sse_flush_on_stop() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = OpenAiSseState::new(vault);

        // First chunk: partial ref (opens bracket, held by resolver)
        let partial = format!("[{}", &ref_key[..ref_key.len() / 2]);
        let data1 = format!(
            r#"{{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{{"index":0,"delta":{{"content":"{partial}"}},"finish_reason":null}}]}}"#,
        );
        let event1 = format!("data: {data1}\n\n");
        state.buf.feed(event1.as_bytes());
        let ev1 = state.buf.next_event().unwrap();
        let _ = state.process_event(&ev1);

        // Second chunk: rest of ref + stop
        let rest = &ref_key[ref_key.len() / 2..];
        let data2 = format!(
            r#"{{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{{"index":0,"delta":{{"content":"{rest}]"}},"finish_reason":"stop"}}]}}"#,
        );
        let event2 = format!("data: {data2}\n\n");
        state.buf.feed(event2.as_bytes());
        let ev2 = state.buf.next_event().unwrap();
        let outputs = state.process_event(&ev2);

        // Combine all outputs and verify the ref was resolved
        let combined: String = outputs
            .iter()
            .map(|o| String::from_utf8_lossy(o).to_string())
            .collect();
        assert!(
            combined.contains("alice@example.com"),
            "should resolve ref across chunks: {combined}"
        );
    }
}
