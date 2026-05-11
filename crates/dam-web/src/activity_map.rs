//! Map raw `dam-log` events into CTZN-facing sentence-shaped Activity events.
//!
//! Lives in `dam-web` rather than `dam-log` so `dam-log`'s privacy contract
//! stays small. Surfaces derive their views.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Granted,
    Sealed,
    Denied,
}

#[derive(Debug, Clone)]
pub struct DerivedEvent {
    pub id: i64,
    pub ts: i64,
    pub day: String,
    pub actor: String,
    pub kind: String,
    pub decision: Decision,
    pub purpose: Option<String>,
    pub audit_id: String,
}

pub fn derive_event_with_actor(
    entry: &dam_log::LogEntry,
    actor_hint: Option<&str>,
) -> Option<DerivedEvent> {
    let decision = decision_for(entry)?;
    let kind = entry.kind.clone().unwrap_or_else(|| kind_for(entry));
    let actor = actor_hint
        .map(ToOwned::to_owned)
        .or_else(|| actor_from_entry(entry))
        .unwrap_or_else(|| "DAM".to_string());
    let day = day_label(entry.timestamp);
    Some(DerivedEvent {
        id: entry.id,
        ts: entry.timestamp,
        day,
        actor,
        kind,
        decision,
        purpose: None,
        audit_id: format!("evt_{:016x}", entry.id),
    })
}

fn decision_for(entry: &dam_log::LogEntry) -> Option<Decision> {
    let action = entry.action.as_deref()?;
    match (entry.event_type.as_str(), action) {
        ("policy_decision", "allow") => Some(Decision::Granted),
        ("policy_decision", "tokenize") | ("policy_decision", "redact") => Some(Decision::Sealed),
        ("policy_decision", "block") => Some(Decision::Denied),
        ("consent", _) => Some(Decision::Granted),
        ("redaction", _) => Some(Decision::Sealed),
        ("proxy_forward", "request_protection") => proxy_request_decision(&entry.message),
        ("proxy_failure", "provider_down") => Some(Decision::Denied),
        _ => None,
    }
}

fn actor_from_entry(entry: &dam_log::LogEntry) -> Option<String> {
    // Best-effort extraction from the operation_id ("anthropic-1234") or
    // the message. Real wiring belongs in a follow-up that adds an
    // actor field to log entries.
    if let Some((actor, _)) = entry.operation_id.split_once('-')
        && !actor.is_empty()
    {
        return Some(actor.to_string());
    }
    None
}

pub fn actor_from_message(message: &str) -> Option<String> {
    field_value(message, "target")
        .or_else(|| field_value(message, "provider"))
        .filter(|value| !value.is_empty())
}

fn proxy_request_decision(message: &str) -> Option<Decision> {
    let blocked = numeric_field(message, "blocked").unwrap_or(0);
    let replacements = numeric_field(message, "replacements").unwrap_or(0);
    let tokenized = numeric_field(message, "tokenized").unwrap_or(0);
    let detections = numeric_field(message, "detections").unwrap_or(0);
    if blocked > 0 {
        Some(Decision::Denied)
    } else if replacements > 0 || tokenized > 0 || detections > 0 {
        Some(Decision::Sealed)
    } else {
        Some(Decision::Granted)
    }
}

fn kind_for(entry: &dam_log::LogEntry) -> String {
    match (entry.event_type.as_str(), entry.action.as_deref()) {
        ("proxy_forward", Some("request_protection")) => "request".to_string(),
        ("proxy_failure", Some("provider_down")) => "provider".to_string(),
        _ => "unknown".to_string(),
    }
}

fn numeric_field(message: &str, key: &str) -> Option<u64> {
    field_value(message, key)?.parse().ok()
}

fn field_value(message: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    message.split_whitespace().find_map(|part| {
        part.strip_prefix(&prefix)
            .map(|value| value.trim_matches(|c| c == ',' || c == ';').to_string())
    })
}

pub fn day_label(ts: i64) -> String {
    // v1: a coarse YYYY-MM-DD label derived from epoch seconds.
    // The UI groups events by this label without further parsing.
    let secs = ts.max(0) as u64;
    let days = secs / 86_400;
    let (y, m, d) = epoch_days_to_date(days);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn epoch_days_to_date(days: u64) -> (i32, u32, u32) {
    // Adapted from the standard Howard Hinnant algorithm.
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = y + if m <= 2 { 1 } else { 0 };
    (y as i32, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(event_type: &str, action: Option<&str>) -> dam_log::LogEntry {
        dam_log::LogEntry {
            id: 1,
            timestamp: 0,
            operation_id: "anthropic-test".into(),
            level: "info".into(),
            event_type: event_type.into(),
            kind: Some("email".into()),
            reference: None,
            action: action.map(|s| s.into()),
            message: "test".into(),
        }
    }

    #[test]
    fn decision_allow_is_granted() {
        let e = entry("policy_decision", Some("allow"));
        assert!(matches!(decision_for(&e), Some(Decision::Granted)));
    }

    #[test]
    fn decision_tokenize_is_sealed() {
        let e = entry("policy_decision", Some("tokenize"));
        assert!(matches!(decision_for(&e), Some(Decision::Sealed)));
    }

    #[test]
    fn decision_block_is_denied() {
        let e = entry("policy_decision", Some("block"));
        assert!(matches!(decision_for(&e), Some(Decision::Denied)));
    }

    #[test]
    fn non_user_event_returns_none() {
        let e = entry("vault_write", Some("ok"));
        assert!(decision_for(&e).is_none());
    }

    #[test]
    fn proxy_request_without_detections_is_granted_activity() {
        let e = dam_log::LogEntry {
            id: 1,
            timestamp: 0,
            operation_id: "op-1".into(),
            level: "info".into(),
            event_type: "proxy_forward".into(),
            kind: None,
            reference: None,
            action: Some("request_protection".into()),
            message: "request protection detections=0 replacements=0 tokenized=0 blocked=0".into(),
        };

        let event = derive_event_with_actor(&e, Some("openai")).unwrap();

        assert!(matches!(event.decision, Decision::Granted));
        assert_eq!(event.kind, "request");
        assert_eq!(event.actor, "openai");
    }

    #[test]
    fn proxy_request_with_replacements_is_sealed_activity() {
        let e = dam_log::LogEntry {
            id: 1,
            timestamp: 0,
            operation_id: "op-1".into(),
            level: "info".into(),
            event_type: "proxy_forward".into(),
            kind: None,
            reference: None,
            action: Some("request_protection".into()),
            message: "request protection detections=1 replacements=1 tokenized=1 blocked=0".into(),
        };

        assert!(matches!(decision_for(&e), Some(Decision::Sealed)));
    }

    #[test]
    fn actor_can_be_derived_from_route_message() {
        assert_eq!(
            actor_from_message("route target=openai provider=openai-compatible request_bytes=10"),
            Some("openai".to_string())
        );
    }

    #[test]
    fn day_label_is_iso_date() {
        // 2026-05-07 ≈ epoch 1_777_276_800
        let label = day_label(1_777_276_800);
        assert!(label.starts_with("2026-"));
        assert_eq!(label.len(), 10);
    }
}
