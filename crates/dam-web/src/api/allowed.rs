//! `/api/v1/allowed` — currently-allowed grants surface (web only).
//!
//! v1 reads `dam-consent` grants if available and joins with vault
//! values when the canonical key resolves. The richer per-target /
//! per-profile scopes are parked (see `passthrough.md`); this slice
//! returns the canonical-value scope only.

use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::AppState;
use crate::activity_map::day_label;
use crate::error::{Ok, WebError, WebErrorCode, WebResult};

#[derive(Debug, Clone, Default, Serialize)]
pub struct AllowedView {
    pub active: Vec<AllowedGrant>,
    pub expired: Vec<AllowedGrant>,
    pub revoked: Vec<AllowedGrant>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AllowedGrant {
    pub id: String,
    pub party: String,
    pub kind: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ListQuery {
    pub q: Option<String>,
    pub sort: Option<String>,
    pub dir: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> WebResult<AllowedView> {
    let Some(store) = state.consent_store.as_deref() else {
        return Ok(Ok::new(AllowedView::default()));
    };
    let entries = store
        .list()
        .map_err(|_| WebError::new(WebErrorCode::Unknown))?;
    let now = now_unix_secs()?;
    Ok(Ok::new(allowed_view_from_entries(
        state.vault.as_ref(),
        entries,
        &query,
        now,
    )?))
}

fn allowed_view_from_entries(
    vault: &dam_vault::Vault,
    entries: Vec<dam_consent::ConsentEntry>,
    query: &ListQuery,
    now: i64,
) -> Result<AllowedView, WebError> {
    let mut view = AllowedView::default();
    let q = query.q.as_deref().unwrap_or("").to_lowercase();

    for entry in entries {
        let grant = map_grant(vault, &entry)?;
        if !matches_query(&grant, &q) {
            continue;
        }
        match entry.status_at(now) {
            "active" => view.active.push(grant),
            "expired" => view.expired.push(grant),
            _ => view.revoked.push(grant),
        }
    }

    sort_grants(
        &mut view.active,
        query.sort.as_deref(),
        query.dir.as_deref(),
    );
    sort_grants(
        &mut view.expired,
        query.sort.as_deref(),
        query.dir.as_deref(),
    );
    sort_grants(
        &mut view.revoked,
        query.sort.as_deref(),
        query.dir.as_deref(),
    );

    Ok(view)
}

fn map_grant(
    vault: &dam_vault::Vault,
    entry: &dam_consent::ConsentEntry,
) -> Result<AllowedGrant, WebError> {
    Ok(AllowedGrant {
        id: entry.id.clone(),
        party: entry.created_by.clone(),
        kind: entry.kind.tag().to_string(),
        value: grant_value(vault, entry)?,
        since: Some(day_label(entry.created_at)),
        expires_at: Some(day_label(entry.expires_at)),
    })
}

fn grant_value(
    vault: &dam_vault::Vault,
    entry: &dam_consent::ConsentEntry,
) -> Result<String, WebError> {
    let Some(vault_key) = &entry.vault_key else {
        return Ok(format!("[{} grant]", entry.kind.tag()));
    };

    match vault
        .get(vault_key)
        .map_err(|_| WebError::new(WebErrorCode::WalletUnreachable))?
    {
        Some(value) => Ok(value),
        None => Ok(format!("[{vault_key}]")),
    }
}

fn matches_query(grant: &AllowedGrant, q: &str) -> bool {
    q.is_empty()
        || grant.party.to_lowercase().contains(q)
        || grant.kind.to_lowercase().contains(q)
        || grant.value.to_lowercase().contains(q)
}

fn sort_grants(grants: &mut [AllowedGrant], sort: Option<&str>, dir: Option<&str>) {
    let descending = matches!(dir, Some("desc"));
    match sort.unwrap_or("recent") {
        "kind" => grants.sort_by(|a, b| a.kind.cmp(&b.kind)),
        "party" => grants.sort_by(|a, b| a.party.cmp(&b.party)),
        "value" => grants.sort_by(|a, b| a.value.cmp(&b.value)),
        "expires" => grants.sort_by(|a, b| a.expires_at.cmp(&b.expires_at)),
        _ => {}
    }
    if descending {
        grants.reverse();
    }
}

fn now_unix_secs() -> Result<i64, WebError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .map_err(|_| WebError::new(WebErrorCode::Unknown))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_view_groups_active_expired_and_revoked_consents() {
        let vault = dam_vault::Vault::open_in_memory().unwrap();
        vault.put("email:active", "ada@example.test").unwrap();
        vault.put("phone:expired", "+1 415 555 0142").unwrap();
        vault.put("email:revoked", "revoked@example.test").unwrap();

        let store = dam_consent::ConsentStore::open_in_memory().unwrap();
        store
            .grant(&dam_consent::GrantConsent {
                kind: dam_core::SensitiveType::Email,
                value: "ada@example.test".to_string(),
                vault_key: Some("email:active".to_string()),
                ttl_seconds: 60,
                created_by: "anthropic".to_string(),
                reason: None,
            })
            .unwrap();
        store
            .grant(&dam_consent::GrantConsent {
                kind: dam_core::SensitiveType::Phone,
                value: "+1 415 555 0142".to_string(),
                vault_key: Some("phone:expired".to_string()),
                ttl_seconds: 0,
                created_by: "openai".to_string(),
                reason: None,
            })
            .unwrap();
        let revoked = store
            .grant(&dam_consent::GrantConsent {
                kind: dam_core::SensitiveType::Email,
                value: "revoked@example.test".to_string(),
                vault_key: Some("email:revoked".to_string()),
                ttl_seconds: 60,
                created_by: "codex".to_string(),
                reason: None,
            })
            .unwrap();
        assert!(store.revoke(&revoked.id).unwrap());

        let now = now_unix_secs().unwrap();
        let view =
            allowed_view_from_entries(&vault, store.list().unwrap(), &ListQuery::default(), now)
                .unwrap();

        assert_eq!(view.active.len(), 1);
        assert_eq!(view.active[0].value, "ada@example.test");
        assert_eq!(view.expired.len(), 1);
        assert_eq!(view.revoked.len(), 1);
    }

    #[test]
    fn allowed_view_filters_by_query() {
        let vault = dam_vault::Vault::open_in_memory().unwrap();
        vault.put("email:active", "ada@example.test").unwrap();
        let store = dam_consent::ConsentStore::open_in_memory().unwrap();
        store
            .grant(&dam_consent::GrantConsent {
                kind: dam_core::SensitiveType::Email,
                value: "ada@example.test".to_string(),
                vault_key: Some("email:active".to_string()),
                ttl_seconds: 60,
                created_by: "anthropic".to_string(),
                reason: None,
            })
            .unwrap();

        let query = ListQuery {
            q: Some("anthropic".to_string()),
            ..ListQuery::default()
        };
        let view = allowed_view_from_entries(
            &vault,
            store.list().unwrap(),
            &query,
            now_unix_secs().unwrap(),
        )
        .unwrap();

        assert_eq!(view.active.len(), 1);

        let query = ListQuery {
            q: Some("openai".to_string()),
            ..ListQuery::default()
        };
        let view = allowed_view_from_entries(
            &vault,
            store.list().unwrap(),
            &query,
            now_unix_secs().unwrap(),
        )
        .unwrap();

        assert_eq!(view.active.len(), 0);
    }

    #[test]
    fn raw_value_grants_do_not_expose_fingerprints() {
        let vault = dam_vault::Vault::open_in_memory().unwrap();
        let store = dam_consent::ConsentStore::open_in_memory().unwrap();
        store
            .grant(&dam_consent::GrantConsent {
                kind: dam_core::SensitiveType::Email,
                value: "ada@example.test".to_string(),
                vault_key: None,
                ttl_seconds: 60,
                created_by: "test".to_string(),
                reason: None,
            })
            .unwrap();

        let view = allowed_view_from_entries(
            &vault,
            store.list().unwrap(),
            &ListQuery::default(),
            now_unix_secs().unwrap(),
        )
        .unwrap();

        assert_eq!(view.active[0].value, "[email grant]");
        assert!(!view.active[0].value.contains("ada@example.test"));
    }
}
