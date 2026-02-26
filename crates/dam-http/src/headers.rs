use axum::http::HeaderMap;

pub(crate) fn should_forward_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    !matches!(
        n.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
            | "x-dam-upstream"
    )
}

pub(crate) fn forward_request_headers(
    mut upstream_req: reqwest::RequestBuilder,
    headers: &HeaderMap,
) -> reqwest::RequestBuilder {
    for (name, value) in headers {
        if should_forward_header(name.as_str()) {
            upstream_req = upstream_req.header(name, value);
        }
    }
    upstream_req
}
