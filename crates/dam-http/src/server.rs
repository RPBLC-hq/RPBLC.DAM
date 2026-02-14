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
use crate::proxy::{AppState, redact_request, resolve_response};
use crate::streaming::StreamingResolver;

/// Build the axum router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/messages", post(handle_messages))
        .with_state(state)
}

/// Headers to forward from the client to Anthropic.
const FORWARD_HEADERS: &[&str] = &[
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
    // Parse the request
    let mut request: MessagesRequest =
        serde_json::from_str(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let is_streaming = request.stream.unwrap_or(false);

    // Redact PII in user messages
    redact_request(&state.pipeline, &mut request)?;

    // Build the upstream request
    let upstream_url = format!("{}/v1/messages", state.upstream_url);
    let mut upstream_req = state.client.post(&upstream_url);

    // Forward relevant headers
    for &name in FORWARD_HEADERS {
        if let Some(value) = headers.get(name) {
            upstream_req = upstream_req.header(name, value);
        }
    }

    // Always ensure Content-Type is set (upstream requires JSON)
    upstream_req = upstream_req.header("content-type", "application/json");

    let upstream_body =
        serde_json::to_string(&request).map_err(|e| AppError::Proxy(e.to_string()))?;

    let upstream_resp = upstream_req.body(upstream_body).send().await?;

    let status = upstream_resp.status();

    // If upstream returned an error, pass it through preserving headers
    if !status.is_success() {
        let upstream_status =
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let mut builder = Response::builder().status(upstream_status);

        // Forward headers clients may rely on
        for name in &[
            "content-type",
            "x-request-id",
            "request-id",
            "retry-after",
        ] {
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
        return Ok(response);
    }

    if is_streaming {
        handle_streaming(state, upstream_resp).await
    } else {
        handle_non_streaming(state, upstream_resp).await
    }
}

/// Handle a non-streaming response: parse JSON, resolve refs, return.
async fn handle_non_streaming(
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

/// Handle a streaming response: transform SSE events on the fly.
async fn handle_streaming(
    state: AppState,
    upstream_resp: reqwest::Response,
) -> Result<Response, AppError> {
    let vault = state.vault.clone();

    let byte_stream = upstream_resp.bytes_stream();

    let stream = async_stream::stream! {
        let mut sse_state = SseState::new(vault);

        tokio::pin!(byte_stream);

        while let Some(chunk_result) = byte_stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    sse_state.feed(&chunk);
                    while let Some(event_bytes) = sse_state.next_event() {
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

        // Flush any remaining buffered SSE bytes (stream ended without final \n\n)
        if !sse_state.raw_buf.is_empty() {
            if let Ok(s) = std::str::from_utf8(&sse_state.raw_buf) {
                yield Ok::<_, std::io::Error>(axum::body::Bytes::from(s.to_owned()));
            }
            sse_state.raw_buf.clear();
        }

        // Flush any remaining resolver buffers (stream ended without content_block_stop)
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

/// Buffers raw SSE bytes and splits them into complete events.
struct SseState {
    vault: Arc<dam_vault::VaultStore>,
    raw_buf: BytesMut,
    resolvers: HashMap<usize, StreamingResolver>,
}

impl SseState {
    fn new(vault: Arc<dam_vault::VaultStore>) -> Self {
        Self {
            vault,
            raw_buf: BytesMut::new(),
            resolvers: HashMap::new(),
        }
    }

    /// Feed raw bytes from the upstream response.
    fn feed(&mut self, chunk: &[u8]) {
        self.raw_buf.extend_from_slice(chunk);
    }

    /// Extract the next complete SSE event (terminated by `\n\n`).
    fn next_event(&mut self) -> Option<Vec<u8>> {
        // Look for double newline (SSE event boundary)
        let buf = &self.raw_buf[..];
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

    /// Process a complete SSE event, resolving references in text deltas.
    fn process_event(&mut self, event_bytes: &[u8]) -> Vec<u8> {
        let event_str = match std::str::from_utf8(event_bytes) {
            Ok(s) => s,
            Err(_) => return event_bytes.to_vec(),
        };

        // Parse SSE: find "event:" and "data:" lines
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

        // Only process content_block_delta and content_block_stop
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

        // Rebuild the SSE event with the resolved text
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

        // Flush the resolver for this block
        if let Some(mut resolver) = self.resolvers.remove(&index) {
            let remaining = resolver.finish();
            if !remaining.is_empty() {
                // Emit a synthetic text_delta with the remaining resolved text
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

        // Pass through the stop event
        output.extend_from_slice(original.as_bytes());
        output
    }
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

    #[test]
    fn sse_state_splits_events() {
        let (vault, _) = test_vault_with_entry();
        let mut state = SseState::new(vault);

        state.feed(b"event: ping\ndata: {}\n\nevent: message_start\ndata: {\"type\":\"message_start\",\"message\":{}}\n\n");

        let ev1 = state.next_event().unwrap();
        assert!(String::from_utf8_lossy(&ev1).contains("ping"));

        let ev2 = state.next_event().unwrap();
        assert!(String::from_utf8_lossy(&ev2).contains("message_start"));

        assert!(state.next_event().is_none());
    }

    #[test]
    fn sse_state_passthrough_non_text_events() {
        let (vault, _) = test_vault_with_entry();
        let mut state = SseState::new(vault);

        let ping = b"event: ping\ndata: {\"type\":\"ping\"}\n\n";
        state.feed(ping);

        let ev = state.next_event().unwrap();
        let output = state.process_event(&ev);
        assert_eq!(output, ping.to_vec());
    }

    #[test]
    fn sse_state_resolves_text_delta() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = SseState::new(vault);

        let data = format!(
            r#"{{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":"Hello [{}] world"}}}}"#,
            ref_key
        );
        let event = format!("event: content_block_delta\ndata: {data}\n\n");
        state.feed(event.as_bytes());

        let ev = state.next_event().unwrap();
        let output = state.process_event(&ev);
        let output_str = String::from_utf8(output).unwrap();

        assert!(output_str.contains("alice@example.com"));
        assert!(!output_str.contains(&format!("[{ref_key}]")));
    }
}
