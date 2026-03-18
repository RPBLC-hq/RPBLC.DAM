use crate::destination::Destination;
use crate::flow::FlowExecutor;
use crate::module_trait::FlowContext;
use crate::stream::{SseBuffer, StreamingTokenizer};
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
use std::sync::Arc;
use tokio::net::TcpListener;

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
}

/// Start the proxy server on the given port.
pub async fn start_proxy(state: ProxyState, port: u16) -> Result<(), crate::DamError> {
    let app = Router::new()
        .fallback(any(handle_proxy))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).await.map_err(|e| {
        crate::DamError::Proxy(format!("failed to bind to {addr}: {e}"))
    })?;

    tracing::info!("DAM running on :{port}");

    axum::serve(listener, app).await.map_err(|e| {
        crate::DamError::Proxy(format!("server error: {e}"))
    })
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
            return (StatusCode::BAD_REQUEST, "Missing upstream URL. Set X-DAM-Upstream header or use path-based routing.").into_response();
        }
    };

    let destination = Destination::from_url(&upstream_url);
    let body_str = String::from_utf8_lossy(&body).to_string();

    // Run module flow on request body (detect → consent → vault → redact → log)
    let mut ctx = FlowContext::new(body_str, destination.clone());
    if let Err(e) = state.flow.run(&mut ctx) {
        tracing::error!(error = %e, "module flow failed");
    }

    let output_body = ctx.output_body().to_string();

    // Build upstream request
    let mut req_builder = state.client.request(method.clone(), &upstream_url);

    for (name, value) in headers.iter() {
        let n = name.as_str().to_lowercase();
        if n == "host" || n == "content-length" || n == "x-dam-upstream" || n == "transfer-encoding" {
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

    let mut resp_headers = HeaderMap::new();
    for (name, value) in upstream_resp.headers().iter() {
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
        // Non-streaming LLM response: resolve tokens in body
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
        // Non-LLM or no resolver: pass through
        match upstream_resp.bytes().await {
            Ok(bytes) => (status, resp_headers, bytes).into_response(),
            Err(e) => {
                (StatusCode::BAD_GATEWAY, format!("Failed to read upstream response: {e}")).into_response()
            }
        }
    }
}

/// Resolve DAM tokens in a text string using the resolver.
fn resolve_tokens_in_text(text: &str, resolver: &Option<TokenResolver>) -> String {
    match resolver {
        Some(resolver) => Token::replace_all(text, |token| resolver(token)),
        None => text.to_string(),
    }
}

/// Stream SSE response, resolving tokens in event data if a resolver is provided.
fn stream_sse(
    byte_stream: impl futures_util::Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static,
    resolver: Option<TokenResolver>,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
    async_stream::stream! {
        let mut sse_buf = SseBuffer::new();

        // If we have a resolver, use StreamingTokenizer to handle token splits across chunks
        let mut tokenizer: Option<StreamingTokenizer<Box<dyn FnMut(&str) -> String + Send>>> = resolver.map(|r| {
            let replacer: Box<dyn FnMut(&str) -> String + Send> = Box::new(move |text: &str| {
                Token::replace_all(text, |token| r(token))
            });
            StreamingTokenizer::new(replacer)
        });

        tokio::pin!(byte_stream);

        while let Some(chunk_result) = byte_stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    sse_buf.feed(&chunk);
                    while let Some(event_bytes) = sse_buf.next_event() {
                        if let Some(ref mut tok) = tokenizer {
                            // Resolve tokens in the SSE event data
                            let event_str = String::from_utf8_lossy(&event_bytes);
                            let resolved = tok.push(&event_str);
                            if !resolved.is_empty() {
                                yield Ok(Bytes::from(resolved.into_bytes()));
                            }
                        } else {
                            yield Ok(Bytes::from(event_bytes));
                        }
                    }
                }
                Err(e) => {
                    yield Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
                    break;
                }
            }
        }

        // Flush remaining tokenizer buffer
        if let Some(ref mut tok) = tokenizer {
            let remaining = tok.finish();
            if !remaining.is_empty() {
                yield Ok(Bytes::from(remaining.into_bytes()));
            }
        }
    }
}

fn extract_upstream(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    if let Some(val) = headers.get("x-dam-upstream") {
        if let Ok(s) = val.to_str() {
            return Some(s.to_string());
        }
    }

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
        // Use a real generated token for testing
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
        assert_eq!(resolved, text); // unchanged
    }

    #[test]
    fn test_resolve_tokens_no_tokens_in_text() {
        let resolver: Option<TokenResolver> = Some(Arc::new(|_| Some("resolved".into())));
        let text = "plain text with no tokens";
        let resolved = resolve_tokens_in_text(text, &resolver);
        assert_eq!(resolved, "plain text with no tokens");
    }
}
