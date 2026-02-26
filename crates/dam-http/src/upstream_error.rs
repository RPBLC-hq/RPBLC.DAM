use crate::error::AppError;
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;

/// Pass through an error response from upstream, preserving status and headers.
pub(crate) async fn pass_through_error(upstream_resp: reqwest::Response) -> Result<Response, AppError> {
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
