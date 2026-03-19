use crate::destination::Destination;
use crate::flow::FlowExecutor;
use crate::module_trait::FlowContext;
use crate::stream::{SseBuffer, StreamingTokenizer};
use crate::tls::CertCache;
use crate::token::Token;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
};
use bytes::Bytes;
use futures_util::StreamExt;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceExt;

/// Callback type for resolving tokens to original values.
/// Returns Some(value) if the token is in the vault, None to leave as-is.
pub type TokenResolver = Arc<dyn Fn(&Token) -> Option<String> + Send + Sync>;

/// Shared state for the proxy server.
#[derive(Clone)]
pub struct ProxyState {
    pub flow: Arc<FlowExecutor>,
    pub client: reqwest::Client,
    /// Optional resolver for auto-resolving tokens in LLM responses.
    /// If None, responses pass through with tokens intact.
    pub resolver: Option<TokenResolver>,
    /// TLS interceptor for CONNECT tunnels. If None, CONNECT requests are blind-tunneled.
    pub tls: Option<Arc<CertCache>>,
}

/// Start the proxy server on the given port.
///
/// Handles both regular HTTP requests (X-DAM-Upstream / path-based routing)
/// and CONNECT requests (HTTPS proxy mode, for `HTTPS_PROXY` clients).
pub async fn start_proxy(state: ProxyState, port: u16) -> Result<(), crate::DamError> {
    let app = Router::new()
        .fallback(any(handle_proxy))
        .with_state(state.clone());

    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).await.map_err(|e| {
        crate::DamError::Proxy(format!("failed to bind to {addr}: {e}"))
    })?;

    tracing::info!("DAM running on :{port}");
    if state.tls.is_some() {
        tracing::info!("TLS interception enabled — set HTTPS_PROXY=http://localhost:{port}");
    }

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!(error = %e, "accept failed");
                continue;
            }
        };

        let state = state.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(stream);

            let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let state = state.clone();
                let app = app.clone();
                async move {
                    if req.method() == Method::CONNECT {
                        crate::connect::handle_connect(req, &state).await
                    } else {
                        let req = req.map(Body::new);
                        app.oneshot(req)
                            .await
                            .map_err(|e: Infallible| match e {})
                    }
                }
            });

            if let Err(e) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, svc)
                .with_upgrades()
                .await
            {
                tracing::debug!(error = %e, "connection closed");
            }
        });
    }
}

/// Shared request processing logic used by both the axum handler and the CONNECT interceptor.
pub(crate) async fn process_request(
    state: &ProxyState,
    method: Method,
    upstream_url: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    let destination = Destination::from_url(upstream_url);

    // Decompress body if content-encoding is present
    let content_encoding = headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase());

    let decompressed = match content_encoding.as_deref() {
        Some("zstd") => {
            match zstd::decode_all(body.as_ref()) {
                Ok(decoded) => {
                    tracing::debug!(original = body.len(), decoded = decoded.len(), "decompressed zstd");
                    decoded
                }
                Err(e) => {
                    tracing::warn!(error = %e, "zstd decompression failed, forwarding raw");
                    body.to_vec()
                }
            }
        }
        Some(enc) => {
            tracing::warn!(encoding = %enc, "unsupported content-encoding, forwarding raw");
            body.to_vec()
        }
        _ => body.to_vec(),
    };

    let body_str = String::from_utf8_lossy(&decompressed).to_string();

    // Run module flow on request body (detect → consent → vault → redact → log)
    let mut ctx = FlowContext::new(body_str, destination.clone());
    if let Err(e) = state.flow.run(&mut ctx) {
        tracing::error!(error = %e, "module flow failed");
    }

    if !ctx.detections.is_empty() {
        let types: Vec<_> = ctx.detections.iter().map(|d| d.data_type.tag()).collect();
        tracing::debug!(
            detections = ctx.detections.len(),
            modified = ctx.modified_body.is_some(),
            types = ?types,
            "pipeline results"
        );
    }

    let output_body = ctx.output_body().to_string();

    // Build upstream request
    let mut req_builder = state.client.request(method, upstream_url);

    for (name, value) in headers.iter() {
        let n = name.as_str().to_lowercase();
        if matches!(n.as_str(), "host" | "content-length" | "content-encoding" | "accept-encoding" | "x-dam-upstream" | "transfer-encoding") {
            continue;
        }
        req_builder = req_builder.header(name.clone(), value.clone());
    }

    req_builder = req_builder.body(output_body);

    let upstream_resp = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, url = %upstream_url, "upstream request failed");
            return (StatusCode::BAD_GATEWAY, format!("Upstream unreachable: {e}")).into_response();
        }
    };

    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    // Log upstream errors at debug level
    if status.is_client_error() || status.is_server_error() {
        tracing::debug!(url = %upstream_url, status = %status, "upstream error");
    }

    let mut resp_headers = HeaderMap::new();
    for (name, value) in upstream_resp.headers().iter() {
        // Skip headers that reqwest already handled or that may be stale after body modification
        let n = name.as_str();
        if matches!(n, "content-length" | "content-encoding" | "transfer-encoding") {
            continue;
        }
        resp_headers.insert(name.clone(), value.clone());
    }

    let is_sse = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false);

    let should_resolve = destination.is_llm() && state.resolver.is_some();

    if is_sse {
        let byte_stream = upstream_resp.bytes_stream();
        let stream = stream_sse(byte_stream, state.resolver.clone());
        let body = Body::from_stream(stream);
        (status, resp_headers, body).into_response()
    } else if should_resolve {
        match upstream_resp.bytes().await {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                let resolved = resolve_tokens_in_text(&text, &state.resolver);
                (status, resp_headers, resolved).into_response()
            }
            Err(e) => {
                (StatusCode::BAD_GATEWAY, format!("Failed to read upstream response: {e}")).into_response()
            }
        }
    } else {
        match upstream_resp.bytes().await {
            Ok(bytes) => (status, resp_headers, bytes).into_response(),
            Err(e) => {
                (StatusCode::BAD_GATEWAY, format!("Failed to read upstream response: {e}")).into_response()
            }
        }
    }
}

async fn handle_proxy(
    State(state): State<ProxyState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let upstream_url = match extract_upstream(&headers, &uri) {
        Some(url) => url,
        None => {
            return (StatusCode::BAD_REQUEST, "Missing upstream URL. Set X-DAM-Upstream header, use path-based routing, or set HTTPS_PROXY.").into_response();
        }
    };

    process_request(&state, method, &upstream_url, &headers, body).await
}

/// Resolve DAM tokens in a text string using the resolver.
/// Resolve DAM tokens in a text string using the resolver.
fn resolve_tokens_in_text(text: &str, resolver: &Option<TokenResolver>) -> String {
    match resolver {
        Some(resolver) => Token::replace_all(text, |token| resolver(token)),
        None => text.to_string(),
    }
}

/// Stream SSE response, resolving tokens in event data if a resolver is provided.
///
/// Extracts just the `"delta"` or `"content"` text from each SSE event's JSON data,
/// feeds it to the StreamingTokenizer (which handles tokens split across events),
/// then replaces the value in the original event. Non-content events get full-text
/// token resolution directly.
fn stream_sse(
    byte_stream: impl futures_util::Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static,
    resolver: Option<TokenResolver>,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
    async_stream::stream! {
        let mut sse_buf = SseBuffer::new();

        let resolver = match resolver {
            Some(r) => r,
            None => {
                // No resolver — passthrough mode
                tokio::pin!(byte_stream);
                while let Some(chunk_result) = byte_stream.next().await {
                    match chunk_result {
                        Ok(chunk) => {
                            sse_buf.feed(&chunk);
                            while let Some(event_bytes) = sse_buf.next_event() {
                                yield Ok(Bytes::from(event_bytes));
                            }
                        }
                        Err(e) => {
                            yield Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
                            break;
                        }
                    }
                }
                return;
            }
        };

        // Content-only tokenizer: fed delta/content text extracted from SSE events,
        // not raw SSE framing. This lets it correctly handle DAM tokens split across
        // multiple streaming events (each SSE event carries one NLP token).
        let r2 = resolver.clone();
        let replacer: Box<dyn FnMut(&str) -> String + Send> = Box::new(move |text: &str| {
            Token::replace_all(text, |token| r2(token))
        });
        let mut tokenizer = StreamingTokenizer::new(replacer);

        tokio::pin!(byte_stream);

        while let Some(chunk_result) = byte_stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    sse_buf.feed(&chunk);
                    while let Some(event_bytes) = sse_buf.next_event() {
                        let event_str = String::from_utf8_lossy(&event_bytes);

                        if let Some((val_start, val_end)) = find_json_string_value(&event_str) {
                            // Delta/content event: extract text, feed to tokenizer
                            let delta_text = &event_str[val_start..val_end];
                            tracing::trace!(delta_text, "sse delta extracted");
                            let resolved = tokenizer.push(delta_text);

                            // Rebuild event with resolved delta
                            let mut modified = String::with_capacity(event_str.len());
                            modified.push_str(&event_str[..val_start]);
                            modified.push_str(&resolved);
                            modified.push_str(&event_str[val_end..]);
                            yield Ok(Bytes::from(modified.into_bytes()));
                        } else {
                            // Non-content event (response.created, done, etc.)
                            // Flush any held content from the tokenizer first
                            let flushed = tokenizer.finish();
                            if !flushed.is_empty() {
                                // Emit held content as raw text before this event
                                let resolved = Token::replace_all(&flushed, |t| resolver(t));
                                if !resolved.is_empty() {
                                    yield Ok(Bytes::from(resolved.into_bytes()));
                                }
                            }
                            // Resolve tokens in the full event text (for .done events with complete text)
                            let resolved = Token::replace_all(&event_str, |t| resolver(t));
                            yield Ok(Bytes::from(resolved.into_bytes()));
                        }
                    }
                }
                Err(e) => {
                    yield Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
                    break;
                }
            }
        }

        let remaining = tokenizer.finish();
        if !remaining.is_empty() {
            let resolved = Token::replace_all(&remaining, |t| resolver(t));
            if !resolved.is_empty() {
                yield Ok(Bytes::from(resolved.into_bytes()));
            }
        }
    }
}

/// Find the byte range of the first `"delta":"..."` or `"content":"..."` string value
/// in an SSE event. Returns `(start, end)` — byte offsets of the value between quotes.
fn find_json_string_value(event: &str) -> Option<(usize, usize)> {
    let bytes = event.as_bytes();
    for key in &["\"delta\":\"", "\"content\":\""] {
        let key_bytes = key.as_bytes();
        if let Some(pos) = event.find(key) {
            let val_start = pos + key_bytes.len();
            // Walk to the closing quote, handling JSON escapes
            let mut i = val_start;
            while i < bytes.len() {
                match bytes[i] {
                    b'"' => return Some((val_start, i)),
                    b'\\' => i += 2,
                    _ => i += 1,
                }
            }
        }
    }
    None
}

fn extract_upstream(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    // 1. X-DAM-Upstream header (explicit routing)
    if let Some(val) = headers.get("x-dam-upstream") {
        if let Ok(s) = val.to_str() {
            return Some(s.to_string());
        }
    }

    // 2. Absolute URI (HTTP_PROXY mode: GET http://example.com/path)
    if uri.scheme().is_some() {
        return Some(uri.to_string());
    }

    // 3. Path-based routing: /https://api.openai.com/v1/...
    let path = uri.path();
    if path.starts_with("/https://") || path.starts_with("/http://") {
        let url = &path[1..];
        if let Some(query) = uri.query() {
            return Some(format!("{url}?{query}"));
        }
        return Some(url.to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_upstream_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-dam-upstream", HeaderValue::from_static("https://api.anthropic.com/v1/messages"));
        let uri: Uri = "/anything".parse().unwrap();
        let result = extract_upstream(&headers, &uri);
        assert_eq!(result, Some("https://api.anthropic.com/v1/messages".into()));
    }

    #[test]
    fn test_extract_upstream_from_path() {
        let headers = HeaderMap::new();
        let uri: Uri = "/https://api.openai.com/v1/chat/completions".parse().unwrap();
        let result = extract_upstream(&headers, &uri);
        assert_eq!(result, Some("https://api.openai.com/v1/chat/completions".into()));
    }

    #[test]
    fn test_extract_upstream_missing() {
        let headers = HeaderMap::new();
        let uri: Uri = "/no-url-here".parse().unwrap();
        let result = extract_upstream(&headers, &uri);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_upstream_header_takes_priority() {
        let mut headers = HeaderMap::new();
        headers.insert("x-dam-upstream", HeaderValue::from_static("https://custom.api.com"));
        let uri: Uri = "/https://api.openai.com/v1/chat".parse().unwrap();
        let result = extract_upstream(&headers, &uri);
        assert_eq!(result, Some("https://custom.api.com".into()));
    }

    #[test]
    fn test_resolve_tokens_in_text_with_resolver() {
        let resolver: Option<TokenResolver> = Some(Arc::new(|token: &Token| {
            if token.data_type == crate::types::SensitiveDataType::Email {
                Some("john@example.com".into())
            } else {
                None
            }
        }));
        let token = Token::generate(crate::types::SensitiveDataType::Email);
        let text = format!("Send to {} please", token.display());
        let resolved = resolve_tokens_in_text(&text, &resolver);
        assert_eq!(resolved, "Send to john@example.com please");
    }

    #[test]
    fn test_resolve_tokens_in_text_no_resolver() {
        let token = Token::generate(crate::types::SensitiveDataType::Email);
        let text = format!("Send to {} please", token.display());
        let resolved = resolve_tokens_in_text(&text, &None);
        assert_eq!(resolved, text);
    }

    #[test]
    fn test_resolve_tokens_no_tokens_in_text() {
        let resolver: Option<TokenResolver> = Some(Arc::new(|_| Some("resolved".into())));
        let text = "plain text with no tokens";
        let resolved = resolve_tokens_in_text(text, &resolver);
        assert_eq!(resolved, "plain text with no tokens");
    }
}
