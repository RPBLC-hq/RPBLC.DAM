use crate::error::AppError;
use axum::http::HeaderMap;

pub(crate) const DAM_UPSTREAM_HEADER: &str = "x-dam-upstream";
pub(crate) const MAX_UPSTREAM_URL_LEN: usize = 2048;

/// Extract an optional upstream URL override from the `X-DAM-Upstream` header.
///
/// Returns `None` if the header is absent or empty, allowing fallback to the
/// configured default. Validates scheme, rejects credentials/query/fragment,
/// and strips trailing slashes.
pub(crate) fn extract_upstream_override(headers: &HeaderMap) -> Result<Option<String>, AppError> {
    let value = match headers.get(DAM_UPSTREAM_HEADER) {
        Some(v) => v,
        None => return Ok(None),
    };

    let s = value
        .to_str()
        .map_err(|_| {
            AppError::BadRequest("X-DAM-Upstream header contains invalid characters".into())
        })?
        .trim();

    if s.is_empty() {
        return Ok(None);
    }

    if s.len() > MAX_UPSTREAM_URL_LEN {
        return Err(AppError::BadRequest(format!(
            "X-DAM-Upstream URL exceeds {MAX_UPSTREAM_URL_LEN} character limit"
        )));
    }

    if s.contains('@') {
        return Err(AppError::BadRequest(
            "X-DAM-Upstream URL must not contain credentials (@)".into(),
        ));
    }

    if s.contains('?') || s.contains('#') {
        return Err(AppError::BadRequest(
            "X-DAM-Upstream URL must not contain query string or fragment".into(),
        ));
    }

    if !s.starts_with("http://") && !s.starts_with("https://") {
        return Err(AppError::BadRequest(
            "X-DAM-Upstream URL must use http:// or https:// scheme".into(),
        ));
    }

    let trimmed = s.trim_end_matches('/');
    Ok(Some(trimmed.to_string()))
}
