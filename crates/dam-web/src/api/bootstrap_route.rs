//! `GET /api/v1/bootstrap` — surface, locale, theme, version.
//!
//! The SPA also receives bootstrap data via the index.html script tag.
//! This endpoint exists as the canonical fetchable form.

use axum::extract::State;
use serde::Serialize;

use crate::AppState;
use crate::bootstrap::Bootstrap;
use crate::error::{Ok, WebResult};

#[derive(Debug, Clone, Serialize)]
pub struct BootstrapView {
    pub surface: &'static str,
    pub tray_post_token: Option<String>,
    pub version: &'static str,
}

impl From<Bootstrap> for BootstrapView {
    fn from(b: Bootstrap) -> Self {
        Self {
            surface: b.surface,
            tray_post_token: b.tray_post_token,
            version: b.version,
        }
    }
}

pub async fn get(State(state): State<AppState>) -> WebResult<BootstrapView> {
    Ok(Ok::new(Bootstrap::from_state(&state).into()))
}
