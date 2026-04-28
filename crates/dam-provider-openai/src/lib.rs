use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, Method, Response, Uri, header},
};
use futures_util::TryStreamExt;
use reqwest::Url;
use std::{collections::HashSet, time::Duration};

const UPSTREAM_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum OpenAiProviderError {
    #[error("failed to initialize OpenAI-compatible provider: {0}")]
    Client(String),

    #[error("failed to build upstream URL: {0}")]
    UpstreamUrl(String),

    #[error("upstream request failed: {0}")]
    Request(String),

    #[error("upstream response failed: {0}")]
    Response(String),
}

#[derive(Clone)]
pub struct OpenAiProvider {
    client: reqwest::Client,
}

pub struct ForwardRequest<'a> {
    pub upstream: &'a str,
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub target_api_key: Option<&'a str>,
}

impl OpenAiProvider {
    pub fn new() -> Result<Self, OpenAiProviderError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(UPSTREAM_REQUEST_TIMEOUT)
            .build()
            .map_err(|error| OpenAiProviderError::Client(error.to_string()))?;

        Ok(Self { client })
    }

    pub async fn forward<F>(
        &self,
        request: ForwardRequest<'_>,
        transform_non_streaming_body: F,
    ) -> Result<Response<Body>, OpenAiProviderError>
    where
        F: FnOnce(Bytes) -> Bytes,
    {
        let url = upstream_url(request.upstream, &request.uri)?;
        let method = reqwest::Method::from_bytes(request.method.as_str().as_bytes())
            .map_err(|error| OpenAiProviderError::Request(error.to_string()))?;
        let request_connection_headers = connection_header_tokens(&request.headers);
        let mut upstream_request = self.client.request(method, url).body(request.body);

        for (name, value) in request.headers.iter() {
            if should_skip_request_header(
                name.as_str(),
                request.target_api_key.is_some(),
                &request_connection_headers,
            ) {
                continue;
            }
            upstream_request = upstream_request.header(name, value);
        }

        if let Some(api_key) = request.target_api_key {
            upstream_request = upstream_request.bearer_auth(api_key);
        }

        let response = upstream_request
            .send()
            .await
            .map_err(|error| OpenAiProviderError::Request(error.to_string()))?;
        let status = response.status();
        let response_headers = response.headers().clone();
        let response_connection_headers = connection_header_tokens(&response_headers);
        let streaming_response = is_streaming_response(&response_headers);

        if streaming_response {
            let mut builder = Response::builder().status(status);
            for (name, value) in response_headers.iter() {
                if should_skip_response_header(name.as_str(), &response_connection_headers) {
                    continue;
                }
                builder = builder.header(name, value);
            }

            let stream = response
                .bytes_stream()
                .map_err(|error| std::io::Error::other(error.to_string()));

            return builder
                .body(Body::from_stream(stream))
                .map_err(|error| OpenAiProviderError::Response(error.to_string()));
        }

        let response_body = response
            .bytes()
            .await
            .map_err(|error| OpenAiProviderError::Response(error.to_string()))?;
        let response_body = transform_non_streaming_body(response_body);

        let mut builder = Response::builder().status(status);
        for (name, value) in response_headers.iter() {
            if should_skip_response_header(name.as_str(), &response_connection_headers) {
                continue;
            }
            builder = builder.header(name, value);
        }

        builder
            .body(Body::from(response_body))
            .map_err(|error| OpenAiProviderError::Response(error.to_string()))
    }
}

fn upstream_url(base: &str, uri: &Uri) -> Result<String, OpenAiProviderError> {
    let mut url =
        Url::parse(base).map_err(|error| OpenAiProviderError::UpstreamUrl(error.to_string()))?;
    let base_path = url.path().trim_end_matches('/');
    let request_path = uri.path().trim_start_matches('/');
    let path = match (
        base_path.is_empty() || base_path == "/",
        request_path.is_empty(),
    ) {
        (true, true) => "/".to_string(),
        (true, false) => format!("/{request_path}"),
        (false, true) => base_path.to_string(),
        (false, false) => format!("{base_path}/{request_path}"),
    };
    url.set_path(&path);
    url.set_query(uri.query());
    Ok(url.to_string())
}

fn should_skip_request_header(
    name: &str,
    target_sets_authorization: bool,
    connection_headers: &HashSet<String>,
) -> bool {
    let normalized = name.to_ascii_lowercase();
    connection_headers.contains(&normalized)
        || matches!(
            normalized.as_str(),
            "host"
                | "content-length"
                | "connection"
                | "transfer-encoding"
                | "te"
                | "trailer"
                | "upgrade"
                | "keep-alive"
                | "proxy-authorization"
                | "proxy-authenticate"
        )
        || (target_sets_authorization && normalized == "authorization")
}

fn should_skip_response_header(name: &str, connection_headers: &HashSet<String>) -> bool {
    let normalized = name.to_ascii_lowercase();
    connection_headers.contains(&normalized)
        || matches!(
            normalized.as_str(),
            "content-length"
                | "connection"
                | "transfer-encoding"
                | "te"
                | "trailer"
                | "upgrade"
                | "keep-alive"
                | "proxy-authenticate"
        )
}

fn connection_header_tokens(headers: &HeaderMap) -> HashSet<String> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn is_streaming_response(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .any(|part| part.trim().eq_ignore_ascii_case("text/event-stream"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::to_bytes,
        extract::State,
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::post,
    };
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    async fn spawn_app(app: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    async fn spawn_capture_echo_upstream(seen_body: Arc<Mutex<Option<String>>>) -> String {
        async fn echo(
            State(seen_body): State<Arc<Mutex<Option<String>>>>,
            body: Bytes,
        ) -> Response {
            let body_text =
                String::from_utf8(body.to_vec()).expect("upstream body should be utf-8");
            *seen_body.lock().unwrap() = Some(body_text.clone());
            (StatusCode::OK, body_text).into_response()
        }

        spawn_app(
            Router::new()
                .route("/base/v1/chat/completions", post(echo))
                .with_state(seen_body),
        )
        .await
    }

    async fn spawn_capture_headers_upstream(
        seen_headers: Arc<Mutex<Vec<(String, String)>>>,
    ) -> String {
        async fn echo(
            State(seen_headers): State<Arc<Mutex<Vec<(String, String)>>>>,
            headers: HeaderMap,
        ) -> Response {
            *seen_headers.lock().unwrap() = headers
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_string(), value.to_string()))
                })
                .collect();
            (StatusCode::OK, "{}").into_response()
        }

        spawn_app(
            Router::new()
                .route("/v1/chat/completions", post(echo))
                .with_state(seen_headers),
        )
        .await
    }

    async fn spawn_sse_upstream(seen_body: Arc<Mutex<Option<String>>>) -> String {
        async fn sse(State(seen_body): State<Arc<Mutex<Option<String>>>>, body: Bytes) -> Response {
            let body_text =
                String::from_utf8(body.to_vec()).expect("upstream body should be utf-8");
            *seen_body.lock().unwrap() = Some(body_text.clone());
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/event-stream")],
                format!("event: response.output_text.delta\ndata: {body_text}\n\n"),
            )
                .into_response()
        }

        spawn_app(
            Router::new()
                .route("/v1/responses", post(sse))
                .with_state(seen_body),
        )
        .await
    }

    async fn response_body(response: Response<Body>) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn upstream_url_preserves_base_path_request_path_and_query() {
        let uri = Uri::from_static("/v1/chat/completions?stream=false");

        let url = upstream_url("https://api.example.test/base", &uri).unwrap();

        assert_eq!(
            url,
            "https://api.example.test/base/v1/chat/completions?stream=false"
        );
    }

    #[tokio::test]
    async fn non_streaming_response_uses_body_transform() {
        let seen_body = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_echo_upstream(seen_body.clone()).await;
        let provider = OpenAiProvider::new().unwrap();

        let response = provider
            .forward(
                ForwardRequest {
                    upstream: &format!("{upstream}/base"),
                    method: Method::POST,
                    uri: Uri::from_static("/v1/chat/completions"),
                    headers: HeaderMap::new(),
                    body: Bytes::from_static(b"raw [email:abc]"),
                    target_api_key: None,
                },
                |_| Bytes::from_static(b"resolved body"),
            )
            .await
            .unwrap();

        assert_eq!(
            seen_body.lock().unwrap().as_deref(),
            Some("raw [email:abc]")
        );
        assert_eq!(response_body(response).await, "resolved body");
    }

    #[tokio::test]
    async fn target_api_key_replaces_inbound_authorization() {
        let seen_headers = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let upstream = spawn_capture_headers_upstream(seen_headers.clone()).await;
        let provider = OpenAiProvider::new().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer local-agent-secret".parse().unwrap(),
        );

        provider
            .forward(
                ForwardRequest {
                    upstream: &upstream,
                    method: Method::POST,
                    uri: Uri::from_static("/v1/chat/completions"),
                    headers,
                    body: Bytes::from_static(b"{}"),
                    target_api_key: Some("upstream-secret"),
                },
                |body| body,
            )
            .await
            .unwrap();

        let authorization_values = seen_headers
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>();
        assert_eq!(authorization_values, ["Bearer upstream-secret"]);
    }

    #[tokio::test]
    async fn hop_by_hop_and_connection_listed_headers_are_not_forwarded() {
        let seen_headers = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let upstream = spawn_capture_headers_upstream(seen_headers.clone()).await;
        let provider = OpenAiProvider::new().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, "x-drop-me, keep-alive".parse().unwrap());
        headers.insert("x-drop-me", "secret".parse().unwrap());
        headers.insert("te", "trailers".parse().unwrap());
        headers.insert("trailer", "x-trailer".parse().unwrap());
        headers.insert("upgrade", "websocket".parse().unwrap());
        headers.insert("proxy-authorization", "Basic local".parse().unwrap());
        headers.insert("x-keep-me", "ok".parse().unwrap());

        provider
            .forward(
                ForwardRequest {
                    upstream: &upstream,
                    method: Method::POST,
                    uri: Uri::from_static("/v1/chat/completions"),
                    headers,
                    body: Bytes::from_static(b"{}"),
                    target_api_key: None,
                },
                |body| body,
            )
            .await
            .unwrap();

        let headers = seen_headers.lock().unwrap();
        assert!(
            headers
                .iter()
                .any(|(name, value)| { name.eq_ignore_ascii_case("x-keep-me") && value == "ok" })
        );
        for blocked in [
            "connection",
            "x-drop-me",
            "te",
            "trailer",
            "upgrade",
            "proxy-authorization",
        ] {
            assert!(
                !headers
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case(blocked)),
                "{blocked} should not be forwarded"
            );
        }
    }

    #[tokio::test]
    async fn event_stream_response_passes_through_without_body_transform() {
        let seen_body = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_sse_upstream(seen_body.clone()).await;
        let provider = OpenAiProvider::new().unwrap();

        let response = provider
            .forward(
                ForwardRequest {
                    upstream: &upstream,
                    method: Method::POST,
                    uri: Uri::from_static("/v1/responses"),
                    headers: HeaderMap::new(),
                    body: Bytes::from_static(b"stream token"),
                    target_api_key: None,
                },
                |_| panic!("streaming response body should not be transformed"),
            )
            .await
            .unwrap();

        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/event-stream")
        );
        assert_eq!(seen_body.lock().unwrap().as_deref(), Some("stream token"));
        assert!(response_body(response).await.contains("stream token"));
    }
}
