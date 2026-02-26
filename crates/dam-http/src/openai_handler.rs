use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::error::AppError;
use crate::headers::forward_request_headers;
use crate::openai::{ChatChunk, ChatRequest, ChatResponse};
use crate::proxy::{AppState, redact_chat_request, resolve_chat_response};
use crate::sse_buffer::SseBuffer;
use crate::streaming::StreamingResolver;
use crate::upstream::extract_upstream_override;
use crate::upstream_error::pass_through_error;

pub(crate) async fn handle_chat_completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let mut request: ChatRequest =
        serde_json::from_str(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let is_streaming = request.stream.unwrap_or(false);
    tracing::debug!(model = %request.model, streaming = is_streaming, "incoming openai request");

    let allowed_refs = Arc::new(redact_chat_request(
        &state.pipeline,
        &state.vault,
        &mut request,
        state.consent_passthrough,
    )?);
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

        if !sse_state.buf.raw_buf.is_empty() {
            if let Ok(s) = std::str::from_utf8(&sse_state.buf.raw_buf) {
                yield Ok::<_, std::io::Error>(axum::body::Bytes::from(s.to_owned()));
            }
            sse_state.buf.raw_buf.clear();
        }

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

pub(crate) struct OpenAiSseState {
    pub(crate) vault: Arc<dam_vault::VaultStore>,
    pub(crate) allowed_refs: Arc<HashSet<String>>,
    pub(crate) buf: SseBuffer,
    pub(crate) resolvers: HashMap<usize, StreamingResolver>,
}

impl OpenAiSseState {
    pub(crate) fn new(
        vault: Arc<dam_vault::VaultStore>,
        allowed_refs: Arc<HashSet<String>>,
    ) -> Self {
        Self {
            vault,
            allowed_refs,
            buf: SseBuffer::new(),
            resolvers: HashMap::new(),
        }
    }

    pub(crate) fn process_event(&mut self, event_bytes: &[u8]) -> Vec<Vec<u8>> {
        let event_str = match std::str::from_utf8(event_bytes) {
            Ok(s) => s,
            Err(_) => return vec![event_bytes.to_vec()],
        };

        let mut data = None;
        for line in event_str.lines() {
            if let Some(val) = line.strip_prefix("data:") {
                data = Some(val.trim());
            }
        }

        let Some(data) = data else {
            return vec![event_bytes.to_vec()];
        };

        if data == "[DONE]" {
            let mut outputs = Vec::new();
            for (_, mut resolver) in self.resolvers.drain() {
                let remaining = resolver.finish();
                if !remaining.is_empty() {
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

            if choice.finish_reason.as_deref() == Some("stop")
                && let Some(mut resolver) = self.resolvers.remove(&choice.index)
            {
                let remaining = resolver.finish();
                if !remaining.is_empty() {
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
