//! `/api/v1/*` route table. Each surface lives in its own module.

mod activity;
mod allowed;
mod bootstrap_route;
mod connect;
mod events;
mod health;
mod insights;
mod recently_scanned;
mod requests;
mod settings;
mod system;
mod wallet;

use axum::Router;
use axum::routing::{get, post};

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/bootstrap", get(bootstrap_route::get))
        .route("/connect", get(connect::get))
        .route("/connect/action", post(connect::post_action))
        .route("/wallet", get(wallet::list))
        .route("/wallet/:key", get(wallet::detail))
        .route("/wallet/:key/allow", post(wallet::allow))
        .route("/wallet/:key/revoke", post(wallet::revoke))
        .route("/wallet/:key/protect", post(wallet::protect))
        .route("/activity", get(activity::list))
        .route("/activity/:id", get(activity::detail))
        .route("/allowed", get(allowed::list))
        .route("/system", get(system::list))
        .route("/settings", get(settings::get))
        .route("/settings/apps/:id", post(settings::post_app))
        .route(
            "/settings/integrations/:id/apply",
            post(settings::post_apply),
        )
        .route(
            "/settings/integrations/:id/rollback",
            post(settings::post_rollback),
        )
        .route("/settings/defaults", post(settings::post_defaults))
        .route("/settings/danger/stop", post(settings::post_stop_daemon))
        .route("/settings/danger/reset", post(settings::post_reset))
        .route("/settings/danger/uninstall", post(settings::post_uninstall))
        .route("/health", get(health::get))
        .route("/insights", get(insights::get))
        .route("/recently-scanned", get(recently_scanned::list))
        .route("/requests/pending", get(requests::pending))
        .route("/requests/trigger", post(requests::trigger))
        .route("/requests/:id/allow-once", post(requests::resolve))
        .route("/requests/:id/allow-always", post(requests::resolve))
        .route("/requests/:id/deny", post(requests::resolve))
        .route("/events", get(events::stream))
}
