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
use crate::proxy::{AppState, redact_request, resolve_response};
use crate::sse_buffer::SseBuffer;
use crate::streaming::StreamingResolver;
use crate::upstream::extract_upstream_override;
use crate::upstream_error::pass_through_error;

pub(crate) async fn handle_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let mut request: MessagesRequest =
        serde_json::from_str(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let is_streaming = request.stream.unwrap_or(false);
    tracing::debug!(model = %request.model, streaming = is_streaming, "incoming request");

    let allowed_refs = Arc::new(redact_request(
        &state.pipeline,
        &state.vault,
        &mut request,
        state.consent_passthrough,
    )?);
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

        if !sse_state.buf.raw_buf.is_empty() {
            if let Ok(s) = std::str::from_utf8(&sse_state.buf.raw_buf) {
                yield Ok::<_, std::io::Error>(axum::body::Bytes::from(s.to_owned()));
            }
            sse_state.buf.raw_buf.clear();
        }

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
        [("content-type", "text/event-stream"), ("cache-control", "no-cache")],
        body,
    )
        .into_response())
}

pub(crate) struct AnthropicSseState {
    pub(crate) vault: Arc<dam_vault::VaultStore>,
    pub(crate) allowed_refs: Arc<HashSet<String>>,
    pub(crate) buf: SseBuffer,
    pub(crate) resolvers: HashMap<usize, StreamingResolver>,
}

impl AnthropicSseState {
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
            .or_insert_with(|| StreamingResolver::new(self.vault.clone(), self.allowed_refs.clone()));
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
