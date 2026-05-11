//! Builds the SPA index.html with bootstrap data injected as a
//! `<script type="application/json" id="dam-web-bootstrap">` block.
//!
//! Keeps the bundle pure (no env-specific data) and gives the SPA the
//! few facts it needs to mount: surface flag, tray POST token, version.

use serde::Serialize;

use crate::AppState;

const BOOTSTRAP_PLACEHOLDER: &str = "<!-- DAM_WEB_BOOTSTRAP -->";

/// `<script type="application/json" id="dam-web-bootstrap">…</script>`
/// payload consumed by `ui/src/lib/surface.ts`.
#[derive(Debug, Clone, Serialize)]
pub struct Bootstrap {
    pub surface: &'static str,
    pub tray_post_token: Option<String>,
    pub version: &'static str,
}

impl Bootstrap {
    pub fn from_state(state: &AppState) -> Self {
        Self {
            surface: state.surface.as_str(),
            tray_post_token: state.tray_post_token.clone(),
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}

/// Inject the bootstrap JSON into the embedded HTML template.
pub fn render_index(template: &str, bootstrap: &Bootstrap) -> String {
    let payload = serde_json::to_string(bootstrap).unwrap_or_else(|_| "{}".to_string());
    let escaped = payload.replace('<', "\\u003c");
    let block =
        format!("<script type=\"application/json\" id=\"dam-web-bootstrap\">{escaped}</script>");
    template.replacen(BOOTSTRAP_PLACEHOLDER, &block, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_bootstrap_block() {
        let template = "<head><!-- DAM_WEB_BOOTSTRAP --></head>";
        let boot = Bootstrap {
            surface: "tray",
            tray_post_token: Some("abc".into()),
            version: "0.0.0",
        };
        let html = render_index(template, &boot);
        assert!(html.contains("dam-web-bootstrap"));
        assert!(html.contains("\"surface\":\"tray\""));
        assert!(html.contains("\"tray_post_token\":\"abc\""));
        assert!(!html.contains(BOOTSTRAP_PLACEHOLDER));
    }

    #[test]
    fn escapes_angle_brackets_in_payload() {
        let template = "<!-- DAM_WEB_BOOTSTRAP -->";
        // Token is unlikely to contain '<', but guard anyway.
        let boot = Bootstrap {
            surface: "web",
            tray_post_token: Some("a<b".into()),
            version: "0.0.0",
        };
        let html = render_index(template, &boot);
        assert!(!html.contains("a<b"));
        assert!(html.contains("a\\u003cb"));
    }
}
