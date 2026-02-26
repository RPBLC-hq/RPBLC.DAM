use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::anthropic::{Delta, MessagesRequest, MessagesResponse, StreamEvent};
use crate::error::AppError;
use crate::headers::forward_request_headers;
use crate::openai::{ChatChunk, ChatRequest, ChatResponse};
use crate::proxy::{
    AppState, collect_chat_request_refs, collect_request_refs, collect_responses_request_refs,
    redact_chat_request, redact_request, redact_responses_request, resolve_chat_response,
    resolve_json_value, resolve_response, resolve_responses_response,
};
use crate::resolve::resolve_text;
use crate::responses::{ResponsesRequest, ResponsesResponse, ResponsesStreamDelta};
use crate::sse_buffer::SseBuffer;
use crate::streaming::StreamingResolver;
use crate::upstream::extract_upstream_override;

// ---------------------------------------------------------------------------
// Anthropic SSE handler
// ---------------------------------------------------------------------------

/// POST /v1/messages handler.
pub(crate) async fn handle_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let mut request: MessagesRequest =
        serde_json::from_str(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let is_streaming = request.stream.unwrap_or(false);
    tracing::debug!(model = %request.model, streaming = is_streaming, "incoming request");

    redact_request(
        &state.pipeline,
        &state.vault,
        &mut request,
        state.consent_passthrough,
    )?;
    let allowed_refs = Arc::new(collect_request_refs(&request));
    tracing::debug!(allowed_refs = allowed_refs.len(), "request redacted");

    let base = extract_upstream_override(&headers)?
        .unwrap_or_else(|| state.anthropic_upstream_url.clone());
    let upstream_url = format!("{base}/v1/messages");
    let mut upstream_req = state.client.post(&upstream_url);
    upstream_req = forward_request_headers(upstream_req, &headers);
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
        handle_anthropic_streaming(state, upstream_resp, allowed_refs).await
    } else {
        handle_anthropic_non_streaming(state, upstream_resp, &allowed_refs).await
    }
}

/// Handle a non-streaming Anthropic response.
async fn handle_anthropic_non_streaming(
    state: AppState,
    upstream_resp: reqwest::Response,
    allowed_refs: &HashSet<String>,
) -> Result<Response, AppError> {
    let body = upstream_resp.text().await?;
    let mut response: MessagesResponse =
        serde_json::from_str(&body).map_err(|e| AppError::Upstream(e.to_string()))?;

    resolve_response(&state.vault, &mut response, allowed_refs);

    let json = serde_json::to_string(&response).map_err(|e| AppError::Proxy(e.to_string()))?;

    Ok((StatusCode::OK, [("content-type", "application/json")], json).into_response())
}

/// Handle a streaming Anthropic response.
async fn handle_anthropic_streaming(
    state: AppState,
    upstream_resp: reqwest::Response,
    allowed_refs: Arc<HashSet<String>>,
) -> Result<Response, AppError> {
    let vault = state.vault.clone();
    let byte_stream = upstream_resp.bytes_stream();

    let stream = async_stream::stream! {
        let mut sse_state = AnthropicSseState::new(vault, allowed_refs.clone());

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
    allowed_refs: Arc<HashSet<String>>,
    buf: SseBuffer,
    resolvers: HashMap<usize, StreamingResolver>,
}

impl AnthropicSseState {
    fn new(vault: Arc<dam_vault::VaultStore>, allowed_refs: Arc<HashSet<String>>) -> Self {
        Self {
            vault,
            allowed_refs,
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

        let resolver = self.resolvers.entry(*index).or_insert_with(|| {
            StreamingResolver::new(self.vault.clone(), self.allowed_refs.clone())
        });

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

/// POST /v1/chat/completions handler.
pub(crate) async fn handle_chat_completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let mut request: ChatRequest =
        serde_json::from_str(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let is_streaming = request.stream.unwrap_or(false);
    tracing::debug!(model = %request.model, streaming = is_streaming, "incoming openai request");

    redact_chat_request(
        &state.pipeline,
        &state.vault,
        &mut request,
        state.consent_passthrough,
    )?;
    let allowed_refs = Arc::new(collect_chat_request_refs(&request));
    tracing::debug!(allowed_refs = allowed_refs.len(), "openai request redacted");

    let base =
        extract_upstream_override(&headers)?.unwrap_or_else(|| state.openai_upstream_url.clone());
    let upstream_url = format!("{base}/v1/chat/completions");
    let mut upstream_req = state.client.post(&upstream_url);
    upstream_req = forward_request_headers(upstream_req, &headers);
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
        handle_openai_streaming(state, upstream_resp, allowed_refs).await
    } else {
        handle_openai_non_streaming(state, upstream_resp, &allowed_refs).await
    }
}

/// Handle a non-streaming OpenAI response.
async fn handle_openai_non_streaming(
    state: AppState,
    upstream_resp: reqwest::Response,
    allowed_refs: &HashSet<String>,
) -> Result<Response, AppError> {
    let body = upstream_resp.text().await?;
    let mut response: ChatResponse =
        serde_json::from_str(&body).map_err(|e| AppError::Upstream(e.to_string()))?;

    resolve_chat_response(&state.vault, &mut response, allowed_refs);

    let json = serde_json::to_string(&response).map_err(|e| AppError::Proxy(e.to_string()))?;

    Ok((StatusCode::OK, [("content-type", "application/json")], json).into_response())
}

/// Handle a streaming OpenAI response.
async fn handle_openai_streaming(
    state: AppState,
    upstream_resp: reqwest::Response,
    allowed_refs: Arc<HashSet<String>>,
) -> Result<Response, AppError> {
    let vault = state.vault.clone();
    let byte_stream = upstream_resp.bytes_stream();

    let stream = async_stream::stream! {
        let mut sse_state = OpenAiSseState::new(vault, allowed_refs.clone());

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
    allowed_refs: Arc<HashSet<String>>,
    buf: SseBuffer,
    resolvers: HashMap<usize, StreamingResolver>,
}

impl OpenAiSseState {
    fn new(vault: Arc<dam_vault::VaultStore>, allowed_refs: Arc<HashSet<String>>) -> Self {
        Self {
            vault,
            allowed_refs,
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
                let resolver = self.resolvers.entry(choice.index).or_insert_with(|| {
                    StreamingResolver::new(self.vault.clone(), self.allowed_refs.clone())
                });
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
// OpenAI Responses API handler
// ---------------------------------------------------------------------------

/// POST /v1/responses handler.
pub(crate) async fn handle_responses(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let mut request: ResponsesRequest =
        serde_json::from_str(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let is_streaming = request.stream.unwrap_or(false);
    tracing::debug!(
        model = %request.model,
        streaming = is_streaming,
        "incoming responses api request"
    );

    redact_responses_request(
        &state.pipeline,
        &state.vault,
        &mut request,
        state.consent_passthrough,
    )?;
    let allowed_refs = Arc::new(collect_responses_request_refs(&request));
    tracing::debug!(
        allowed_refs = allowed_refs.len(),
        "responses request redacted"
    );

    let base =
        extract_upstream_override(&headers)?.unwrap_or_else(|| state.openai_upstream_url.clone());
    let upstream_url = format!("{base}/v1/responses");
    let mut upstream_req = state.client.post(&upstream_url);
    upstream_req = forward_request_headers(upstream_req, &headers);
    upstream_req = upstream_req.header("content-type", "application/json");

    let upstream_body =
        serde_json::to_string(&request).map_err(|e| AppError::Proxy(e.to_string()))?;

    let upstream_resp = upstream_req.body(upstream_body).send().await?;

    let status = upstream_resp.status();
    tracing::debug!(status = %status, "responses api upstream response");

    if !status.is_success() {
        return pass_through_error(upstream_resp).await;
    }

    if is_streaming {
        handle_responses_streaming(state, upstream_resp, allowed_refs).await
    } else {
        handle_responses_non_streaming(state, upstream_resp, &allowed_refs).await
    }
}

/// Handle a non-streaming Responses API response.
async fn handle_responses_non_streaming(
    state: AppState,
    upstream_resp: reqwest::Response,
    allowed_refs: &HashSet<String>,
) -> Result<Response, AppError> {
    let body = upstream_resp.text().await?;
    let mut response: ResponsesResponse =
        serde_json::from_str(&body).map_err(|e| AppError::Upstream(e.to_string()))?;

    resolve_responses_response(&state.vault, &mut response, allowed_refs);

    let json = serde_json::to_string(&response).map_err(|e| AppError::Proxy(e.to_string()))?;

    Ok((StatusCode::OK, [("content-type", "application/json")], json).into_response())
}

/// Handle a streaming Responses API response.
async fn handle_responses_streaming(
    state: AppState,
    upstream_resp: reqwest::Response,
    allowed_refs: Arc<HashSet<String>>,
) -> Result<Response, AppError> {
    let vault = state.vault.clone();
    let byte_stream = upstream_resp.bytes_stream();

    let stream = async_stream::stream! {
        let mut sse_state = ResponsesSseState::new(vault, allowed_refs.clone());

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

        // Flush remaining resolver buffers as properly framed SSE events
        for (key, mut resolver) in sse_state.resolvers.drain() {
            let remaining = resolver.finish();
            if !remaining.is_empty()
                && let Ok(flush_data) = serde_json::to_string(&serde_json::json!({
                    "delta": remaining,
                    "output_index": key.0,
                    "content_index": key.1,
                })) {
                    let event = format!("event: response.output_text.delta\ndata: {flush_data}\n\n");
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

/// Responses API SSE state: buffer + per-content-block resolvers.
///
/// Resolver keys are `(output_index, content_index)` tuples to distinguish
/// between concurrent output streams (e.g. text + function call arguments).
struct ResponsesSseState {
    vault: Arc<dam_vault::VaultStore>,
    allowed_refs: Arc<HashSet<String>>,
    buf: SseBuffer,
    resolvers: HashMap<(usize, usize), StreamingResolver>,
}

impl ResponsesSseState {
    fn new(vault: Arc<dam_vault::VaultStore>, allowed_refs: Arc<HashSet<String>>) -> Self {
        Self {
            vault,
            allowed_refs,
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
            "response.output_text.delta" | "response.function_call_arguments.delta" => {
                self.handle_delta(event_type, data, event_bytes)
            }
            "response.output_text.done" => self.handle_text_done(data, event_bytes),
            "response.completed" => self.handle_completed(event_bytes),
            _ => event_bytes.to_vec(),
        }
    }

    fn handle_delta(&mut self, event_type: &str, data: &str, original: &[u8]) -> Vec<u8> {
        let Ok(delta) = serde_json::from_str::<ResponsesStreamDelta>(data) else {
            return original.to_vec();
        };

        let Some(ref text) = delta.delta else {
            return original.to_vec();
        };

        let key = (
            delta.output_index.unwrap_or(0),
            delta.content_index.unwrap_or(0),
        );
        let resolver = self.resolvers.entry(key).or_insert_with(|| {
            StreamingResolver::new(self.vault.clone(), self.allowed_refs.clone())
        });

        let resolved = resolver.push(text);

        let mut new_delta = delta.clone();
        new_delta.delta = Some(resolved);

        let new_data = serde_json::to_string(&new_delta).unwrap_or_else(|_| data.to_string());
        self.format_event(event_type, &new_data)
    }

    fn handle_text_done(&mut self, data: &str, original: &[u8]) -> Vec<u8> {
        // Flush the resolver for this content block
        let mut output = Vec::new();

        let Ok(delta) = serde_json::from_str::<ResponsesStreamDelta>(data) else {
            return original.to_vec();
        };

        let key = (
            delta.output_index.unwrap_or(0),
            delta.content_index.unwrap_or(0),
        );
        if let Some(mut resolver) = self.resolvers.remove(&key) {
            let remaining = resolver.finish();
            if !remaining.is_empty() {
                // Emit a synthetic text delta with the remaining text
                let mut flush_delta = delta.clone();
                flush_delta.delta = Some(remaining);
                if let Ok(flush_data) = serde_json::to_string(&flush_delta) {
                    output.extend_from_slice(
                        self.format_event("response.output_text.delta", &flush_data)
                            .as_slice(),
                    );
                }
            }
        }

        // Resolve the `text` field in the done payload (it contains the full block text)
        let mut done_value = serde_json::from_str::<serde_json::Value>(data)
            .unwrap_or_else(|_| serde_json::Value::String(data.to_string()));
        if let serde_json::Value::Object(ref mut map) = done_value
            && let Some(serde_json::Value::String(text)) = map.get_mut("text")
        {
            *text = resolve_text(&self.vault, text, Some(&self.allowed_refs));
        }
        let done_data = serde_json::to_string(&done_value).unwrap_or_else(|_| data.to_string());
        output.extend_from_slice(
            self.format_event("response.output_text.done", &done_data)
                .as_slice(),
        );
        output
    }

    fn handle_completed(&mut self, original: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();

        // Flush all remaining resolvers as properly framed SSE delta events
        for (key, mut resolver) in self.resolvers.drain() {
            let remaining = resolver.finish();
            if !remaining.is_empty()
                && let Ok(flush_data) = serde_json::to_string(&serde_json::json!({
                    "delta": remaining,
                    "output_index": key.0,
                    "content_index": key.1,
                }))
            {
                output.extend_from_slice(
                    format!("event: response.output_text.delta\ndata: {flush_data}\n\n").as_bytes(),
                );
            }
        }

        // Resolve references in the completed payload (contains full response JSON)
        let event_str = std::str::from_utf8(original).ok();
        if let Some(event_str) = event_str {
            let mut data = None;
            let mut event_type = None;
            for line in event_str.lines() {
                if let Some(val) = line.strip_prefix("event:") {
                    event_type = Some(val.trim());
                } else if let Some(val) = line.strip_prefix("data:") {
                    data = Some(val.trim());
                }
            }
            if let (Some(event_type), Some(data_str)) = (event_type, data)
                && let Ok(mut value) = serde_json::from_str::<serde_json::Value>(data_str)
            {
                resolve_json_value(&self.vault, &mut value, &self.allowed_refs);
                let new_data =
                    serde_json::to_string(&value).unwrap_or_else(|_| data_str.to_string());
                output.extend_from_slice(self.format_event(event_type, &new_data).as_slice());
                return output;
            }
        }

        output.extend_from_slice(original);
        output
    }

    fn format_event(&self, event_type: &str, data: &str) -> Vec<u8> {
        format!("event: {event_type}\ndata: {data}\n\n").into_bytes()
    }
}

// ---------------------------------------------------------------------------
// OpenAI Codex Responses API handler
// ---------------------------------------------------------------------------

/// POST /codex/responses handler.
///
/// Reuses the same Responses API types and redaction/resolution logic,
/// but forwards to the Codex backend API (`chatgpt.com/backend-api`)
/// instead of OpenAI's standard API.
pub(crate) async fn handle_codex_responses(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let mut request: ResponsesRequest =
        serde_json::from_str(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let is_streaming = request.stream.unwrap_or(false);
    tracing::debug!(model = %request.model, streaming = is_streaming, "incoming codex request");

    redact_responses_request(
        &state.pipeline,
        &state.vault,
        &mut request,
        state.consent_passthrough,
    )?;
    let allowed_refs = Arc::new(collect_responses_request_refs(&request));
    tracing::debug!(allowed_refs = allowed_refs.len(), "codex request redacted");

    let base =
        extract_upstream_override(&headers)?.unwrap_or_else(|| state.codex_upstream_url.clone());
    let upstream_url = format!("{base}/codex/responses");
    let mut upstream_req = state.client.post(&upstream_url);
    upstream_req = forward_request_headers(upstream_req, &headers);
    upstream_req = upstream_req.header("content-type", "application/json");

    let upstream_body =
        serde_json::to_string(&request).map_err(|e| AppError::Proxy(e.to_string()))?;

    let upstream_resp = upstream_req.body(upstream_body).send().await?;

    let status = upstream_resp.status();
    tracing::debug!(status = %status, "codex upstream response");

    if !status.is_success() {
        return pass_through_error(upstream_resp).await;
    }

    if is_streaming {
        handle_responses_streaming(state, upstream_resp, allowed_refs).await
    } else {
        handle_responses_non_streaming(state, upstream_resp, &allowed_refs).await
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
    use crate::upstream::MAX_UPSTREAM_URL_LEN;
    use dam_core::PiiType;
    use dam_vault::generate_kek;
    use std::collections::HashSet;

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
        let mut state = AnthropicSseState::new(vault, Arc::new(HashSet::new()));

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
        let mut state = AnthropicSseState::new(vault, Arc::new(HashSet::new()));

        let ping = b"event: ping\ndata: {\"type\":\"ping\"}\n\n";
        state.buf.feed(ping);

        let ev = state.buf.next_event().unwrap();
        let output = state.process_event(&ev);
        assert_eq!(output, ping.to_vec());
    }

    #[test]
    fn sse_state_resolves_text_delta() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = AnthropicSseState::new(vault, allowlist_for(&ref_key));

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
        let mut state = OpenAiSseState::new(vault, allowlist_for(&ref_key));

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
        let mut state = OpenAiSseState::new(vault, Arc::new(HashSet::new()));

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
        let mut state = OpenAiSseState::new(vault, Arc::new(HashSet::new()));

        let event = "data: [DONE]\n\n";
        state.buf.feed(event.as_bytes());

        let ev = state.buf.next_event().unwrap();
        let outputs = state.process_event(&ev);

        // Should pass through [DONE]
        let last = String::from_utf8(outputs.last().unwrap().clone()).unwrap();
        assert!(last.contains("[DONE]"));
    }

    // --- Responses API SSE tests ---

    #[test]
    fn responses_sse_resolves_text_delta() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = ResponsesSseState::new(vault, allowlist_for(&ref_key));

        let data =
            format!(r#"{{"delta":"Hello [{ref_key}] world","output_index":0,"content_index":0}}"#,);
        let event = format!("event: response.output_text.delta\ndata: {data}\n\n");
        state.buf.feed(event.as_bytes());

        let ev = state.buf.next_event().unwrap();
        let output = state.process_event(&ev);
        let output_str = String::from_utf8(output).unwrap();

        assert!(
            output_str.contains("alice@example.com"),
            "should resolve ref: {output_str}"
        );
        assert!(!output_str.contains(&format!("[{ref_key}]")));
        assert!(output_str.starts_with("event: response.output_text.delta\n"));
    }

    #[test]
    fn responses_sse_passthrough_non_text_events() {
        let (vault, _) = test_vault_with_entry();
        let mut state = ResponsesSseState::new(vault, Arc::new(HashSet::new()));

        let event =
            b"event: response.created\ndata: {\"type\":\"response\",\"id\":\"resp_abc\"}\n\n";
        state.buf.feed(event);

        let ev = state.buf.next_event().unwrap();
        let output = state.process_event(&ev);
        assert_eq!(output, event.to_vec());
    }

    #[test]
    fn responses_sse_flush_on_text_done() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = ResponsesSseState::new(vault, Arc::new(HashSet::new()));

        // First: partial ref in a delta
        let partial = format!("[{}", &ref_key[..ref_key.len() / 2]);
        let data1 = format!(r#"{{"delta":"{partial}","output_index":0,"content_index":0}}"#,);
        let event1 = format!("event: response.output_text.delta\ndata: {data1}\n\n");
        state.buf.feed(event1.as_bytes());
        let ev1 = state.buf.next_event().unwrap();
        let _ = state.process_event(&ev1);

        // Second: rest of ref in another delta
        let rest = &ref_key[ref_key.len() / 2..];
        let data2 = format!(r#"{{"delta":"{rest}]","output_index":0,"content_index":0}}"#,);
        let event2 = format!("event: response.output_text.delta\ndata: {data2}\n\n");
        state.buf.feed(event2.as_bytes());
        let ev2 = state.buf.next_event().unwrap();
        let _ = state.process_event(&ev2);

        // Now send text done — should flush resolver
        let done_data = r#"{"output_index":0,"content_index":0,"text":"full text"}"#;
        let done_event = format!("event: response.output_text.done\ndata: {done_data}\n\n");
        state.buf.feed(done_event.as_bytes());
        let ev3 = state.buf.next_event().unwrap();
        let output = state.process_event(&ev3);
        let output_str = String::from_utf8(output).unwrap();

        // The done event should pass through, and the resolver should be removed
        assert!(output_str.contains("response.output_text.done"));
        assert!(
            state.resolvers.is_empty(),
            "resolver should be removed after done"
        );
    }

    #[test]
    fn responses_sse_flush_on_completed() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = ResponsesSseState::new(vault, Arc::new(HashSet::new()));

        // Push a partial ref
        let partial = format!("[{}", &ref_key[..ref_key.len() / 2]);
        let data1 = format!(r#"{{"delta":"{partial}","output_index":0,"content_index":0}}"#,);
        let event1 = format!("event: response.output_text.delta\ndata: {data1}\n\n");
        state.buf.feed(event1.as_bytes());
        let ev1 = state.buf.next_event().unwrap();
        let _ = state.process_event(&ev1);

        // Send completed — should flush all resolvers
        let completed_event = b"event: response.completed\ndata: {\"type\":\"response\"}\n\n";
        state.buf.feed(completed_event);
        let ev2 = state.buf.next_event().unwrap();
        let output = state.process_event(&ev2);
        let output_str = String::from_utf8(output).unwrap();

        assert!(output_str.contains("response.completed"));
        assert!(
            state.resolvers.is_empty(),
            "all resolvers should be flushed on completed"
        );
    }

    #[test]
    fn responses_sse_function_call_delta() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = ResponsesSseState::new(vault, allowlist_for(&ref_key));

        let data = format!(r#"{{"delta":"[{ref_key}]","output_index":0,"content_index":0}}"#,);
        let event = format!("event: response.function_call_arguments.delta\ndata: {data}\n\n");
        state.buf.feed(event.as_bytes());

        let ev = state.buf.next_event().unwrap();
        let output = state.process_event(&ev);
        let output_str = String::from_utf8(output).unwrap();

        assert!(
            output_str.contains("alice@example.com"),
            "should resolve ref in function call args: {output_str}"
        );
        assert!(output_str.starts_with("event: response.function_call_arguments.delta\n"));
    }

    // --- extract_upstream_override tests ---

    fn allowlist_for(ref_key: &str) -> Arc<HashSet<String>> {
        let mut set = HashSet::new();
        set.insert(ref_key.to_string());
        Arc::new(set)
    }

    fn headers_with(name: &str, value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(
            axum::http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            axum::http::header::HeaderValue::from_str(value).unwrap(),
        );
        map
    }

    #[test]
    fn upstream_override_absent() {
        let headers = HeaderMap::new();
        assert!(extract_upstream_override(&headers).unwrap().is_none());
    }

    #[test]
    fn upstream_override_https() {
        let headers = headers_with("x-dam-upstream", "https://api.x.ai");
        assert_eq!(
            extract_upstream_override(&headers).unwrap().as_deref(),
            Some("https://api.x.ai")
        );
    }

    #[test]
    fn upstream_override_http_localhost() {
        let headers = headers_with("x-dam-upstream", "http://localhost:8080");
        assert_eq!(
            extract_upstream_override(&headers).unwrap().as_deref(),
            Some("http://localhost:8080")
        );
    }

    #[test]
    fn upstream_override_strips_trailing_slash() {
        let headers = headers_with("x-dam-upstream", "https://api.x.ai/");
        assert_eq!(
            extract_upstream_override(&headers).unwrap().as_deref(),
            Some("https://api.x.ai")
        );
    }

    #[test]
    fn upstream_override_trims_whitespace() {
        let headers = headers_with("x-dam-upstream", "  https://api.x.ai  ");
        assert_eq!(
            extract_upstream_override(&headers).unwrap().as_deref(),
            Some("https://api.x.ai")
        );
    }

    #[test]
    fn upstream_override_empty_string() {
        let headers = headers_with("x-dam-upstream", "");
        assert!(extract_upstream_override(&headers).unwrap().is_none());
    }

    #[test]
    fn upstream_override_whitespace_only() {
        let headers = headers_with("x-dam-upstream", "   ");
        assert!(extract_upstream_override(&headers).unwrap().is_none());
    }

    #[test]
    fn upstream_override_rejects_ftp() {
        let headers = headers_with("x-dam-upstream", "ftp://evil.com");
        assert!(extract_upstream_override(&headers).is_err());
    }

    #[test]
    fn upstream_override_rejects_no_scheme() {
        let headers = headers_with("x-dam-upstream", "not a url");
        assert!(extract_upstream_override(&headers).is_err());
    }

    #[test]
    fn upstream_override_rejects_credentials() {
        let headers = headers_with("x-dam-upstream", "https://user:pass@api.x.ai");
        assert!(extract_upstream_override(&headers).is_err());
    }

    #[test]
    fn upstream_override_rejects_query_string() {
        let headers = headers_with("x-dam-upstream", "https://api.x.ai?key=val");
        assert!(extract_upstream_override(&headers).is_err());
    }

    #[test]
    fn upstream_override_rejects_fragment() {
        let headers = headers_with("x-dam-upstream", "https://api.x.ai#frag");
        assert!(extract_upstream_override(&headers).is_err());
    }

    #[test]
    fn upstream_override_rejects_too_long() {
        let long_url = format!("https://example.com/{}", "a".repeat(MAX_UPSTREAM_URL_LEN));
        let headers = headers_with("x-dam-upstream", &long_url);
        assert!(extract_upstream_override(&headers).is_err());
    }

    #[test]
    fn upstream_override_allows_path_prefix() {
        let headers = headers_with("x-dam-upstream", "https://gateway.corp.com/openai-proxy");
        assert_eq!(
            extract_upstream_override(&headers).unwrap().as_deref(),
            Some("https://gateway.corp.com/openai-proxy")
        );
    }

    #[test]
    fn upstream_override_allows_local_ip() {
        let headers = headers_with("x-dam-upstream", "http://127.0.0.1:11434");
        assert_eq!(
            extract_upstream_override(&headers).unwrap().as_deref(),
            Some("http://127.0.0.1:11434")
        );
    }

    #[test]
    fn upstream_override_strips_multiple_trailing_slashes() {
        let headers = headers_with("x-dam-upstream", "https://api.x.ai///");
        assert_eq!(
            extract_upstream_override(&headers).unwrap().as_deref(),
            Some("https://api.x.ai")
        );
    }

    #[test]
    fn openai_sse_flush_on_stop() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = OpenAiSseState::new(vault, allowlist_for(&ref_key));

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
