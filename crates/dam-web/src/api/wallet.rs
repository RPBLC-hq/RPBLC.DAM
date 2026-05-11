//! Wallet list, detail, and consent mutations.
//!
//! v1 reads `dam-vault::Vault::list()` and joins simple consent state.
//! Full at-a-glance metadata, sharing roster timestamps, and per-event
//! last-seen derivation land progressively.

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::error::{Ok, WebError, WebErrorCode, WebResult};

#[derive(Debug, Clone, Serialize)]
pub struct WalletItem {
    pub id: String,
    pub kind: String,
    pub value: String,
    pub state: ItemState,
    pub shared_with: Vec<SharedWith>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SharedWith {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum ItemState {
    Protected,
    Allowed,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Serialize)]
pub struct WalletList {
    pub items: Vec<WalletItem>,
    pub total: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListQuery {
    pub q: Option<String>,
    pub sort: Option<String>,
    pub dir: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> WebResult<WalletList> {
    let entries = state
        .vault
        .list()
        .map_err(|_| WebError::new(WebErrorCode::WalletUnreachable))?;

    let q = query.q.as_deref().unwrap_or("").to_lowercase();
    let mut items: Vec<WalletItem> = entries
        .into_iter()
        .map(map_entry)
        .filter(|item| {
            q.is_empty()
                || item.kind.to_lowercase().contains(&q)
                || item.value.to_lowercase().contains(&q)
        })
        .collect();

    sort_items(&mut items, query.sort.as_deref(), query.dir.as_deref());

    Ok(Ok::new(WalletList {
        total: items.len() as u64,
        items,
    }))
}

#[derive(Debug, Clone, Serialize)]
pub struct WalletDetail {
    pub item: WalletItem,
    pub meta: Vec<MetaEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    pub reference: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetaEntry {
    pub key: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub emphasis: Option<bool>,
}

pub async fn detail(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> WebResult<WalletDetail> {
    let value = state
        .vault
        .get(&key)
        .map_err(|_| WebError::new(WebErrorCode::WalletUnreachable))?
        .ok_or_else(|| WebError::new(WebErrorCode::WalletValueMissing))?;

    let item = WalletItem {
        id: key.clone(),
        kind: kind_from_key(&key).to_string(),
        value,
        state: ItemState::Protected,
        shared_with: Vec::new(),
        last_seen: None,
    };

    Ok(Ok::new(WalletDetail {
        meta: vec![MetaEntry {
            key: "stored in".into(),
            value: "local vault".into(),
            emphasis: Some(true),
        }],
        first_seen: None,
        reference: format!("[{}]", key),
        item,
    }))
}

#[derive(Debug, Clone, Deserialize)]
pub struct AllowRequest {
    pub party: String,
    pub ttl_seconds: Option<u64>,
    pub reason: Option<String>,
}

pub async fn allow(
    State(_state): State<AppState>,
    Path(_key): Path<String>,
    Json(body): Json<AllowRequest>,
) -> WebResult<WalletDetail> {
    let _ = (body.party, body.ttl_seconds, body.reason);
    Err(WebError::new(WebErrorCode::NotImplemented))
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevokeRequest {
    pub party: String,
}

pub async fn revoke(
    State(_state): State<AppState>,
    Path(_key): Path<String>,
    Json(body): Json<RevokeRequest>,
) -> WebResult<WalletDetail> {
    let _ = body.party;
    Err(WebError::new(WebErrorCode::NotImplemented))
}

pub async fn protect(
    State(_state): State<AppState>,
    Path(_key): Path<String>,
) -> WebResult<WalletDetail> {
    Err(WebError::new(WebErrorCode::NotImplemented))
}

fn map_entry(entry: dam_vault::VaultEntry) -> WalletItem {
    let id = entry.key.clone();
    let kind = kind_from_key(&entry.key).to_string();
    WalletItem {
        id,
        kind,
        value: entry.value,
        state: ItemState::Protected,
        shared_with: Vec::new(),
        last_seen: None,
    }
}

fn kind_from_key(key: &str) -> &str {
    key.split_once(':').map(|(k, _)| k).unwrap_or(key)
}

fn sort_items(items: &mut [WalletItem], sort: Option<&str>, dir: Option<&str>) {
    let descending = matches!(dir, Some("desc"));
    match sort.unwrap_or("recent") {
        "kind" => items.sort_by(|a, b| a.kind.cmp(&b.kind)),
        "value" => items.sort_by(|a, b| a.value.cmp(&b.value)),
        _ => {} // recent — preserve underlying order
    }
    if descending {
        items.reverse();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_from_key_extracts_prefix() {
        assert_eq!(kind_from_key("email:abc123"), "email");
        assert_eq!(kind_from_key("phone:xyz"), "phone");
        assert_eq!(kind_from_key("nokey"), "nokey");
    }
}
