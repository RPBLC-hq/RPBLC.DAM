use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

use crate::error::AppError;
use crate::headers::forward_request_headers;
use crate::proxy::{
    AppState, collect_responses_request_refs, redact_responses_request, resolve_json_value,
    resolve_responses_response,
};
use crate::resolve::resolve_text;
use crate::responses::{ResponsesRequest, ResponsesResponse, ResponsesStreamDelta};
use crate::sse_buffer::SseBuffer;
use crate::streaming::StreamingResolver;
use crate::upstream::extract_upstream_override;
use crate::upstream_error::pass_through_error;

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
    tracing::debug!(allowed_refs = allowed_refs.len(), "responses request redacted");

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

        if !sse_state.buf.raw_buf.is_empty() {
            if let Ok(s) = std::str::from_utf8(&sse_state.buf.raw_buf) {
                yield Ok::<_, std::io::Error>(axum::body::Bytes::from(s.to_owned()));
            }
            sse_state.buf.raw_buf.clear();
        }

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
        [("content-type", "text/event-stream"), ("cache-control", "no-cache")],
        body,
    )
        .into_response())
}

pub(crate) struct ResponsesSseState {
    pub(crate) vault: Arc<dam_vault::VaultStore>,
    pub(crate) allowed_refs: Arc<HashSet<String>>,
    pub(crate) buf: SseBuffer,
    pub(crate) resolvers: HashMap<(usize, usize), StreamingResolver>,
}

impl ResponsesSseState {
    pub(crate) fn new(vault: Arc<dam_vault::VaultStore>, allowed_refs: Arc<HashSet<String>>) -> Self {
        Self {
            vault,
            allowed_refs,
            buf: SseBuffer::new(),
            resolvers: HashMap::new(),
        }
    }

    pub(crate) fn process_event(&mut self, event_bytes: &[u8]) -> Vec<u8> {
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

        let key = (delta.output_index.unwrap_or(0), delta.content_index.unwrap_or(0));
        let resolver = self
            .resolvers
            .entry(key)
            .or_insert_with(|| StreamingResolver::new(self.vault.clone(), self.allowed_refs.clone()));

        let resolved = resolver.push(text);
        let mut new_delta = delta.clone();
        new_delta.delta = Some(resolved);

        let new_data = serde_json::to_string(&new_delta).unwrap_or_else(|_| data.to_string());
        self.format_event(event_type, &new_data)
    }

    fn handle_text_done(&mut self, data: &str, original: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();

        let Ok(delta) = serde_json::from_str::<ResponsesStreamDelta>(data) else {
            return original.to_vec();
        };

        let key = (delta.output_index.unwrap_or(0), delta.content_index.unwrap_or(0));
        if let Some(mut resolver) = self.resolvers.remove(&key) {
            let remaining = resolver.finish();
            if !remaining.is_empty() {
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
                let new_data = serde_json::to_string(&value).unwrap_or_else(|_| data_str.to_string());
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
