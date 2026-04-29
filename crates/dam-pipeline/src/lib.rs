use dam_core::{
    EventSink, LogEvent, LogEventType, LogLevel, PolicyAction, PolicyDecision, ReplacementPlan,
    ReplacementPlanOptions, ResolvePlan, VaultReader, VaultWriter,
};
use dam_policy::PolicyEngine;

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("consent check failed: {0}")]
    Consent(#[from] dam_consent::ConsentError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectTextStatus {
    Protected,
    Blocked,
}

#[derive(Debug, Clone)]
pub struct ProtectTextResult {
    pub status: ProtectTextStatus,
    pub output: Option<String>,
    pub detections: Vec<dam_core::Detection>,
    pub decisions: Vec<PolicyDecision>,
    pub plan: ReplacementPlan,
    pub consent_matches: Vec<dam_consent::ConsentMatch>,
}

impl ProtectTextResult {
    pub fn is_blocked(&self) -> bool {
        self.status == ProtectTextStatus::Blocked
    }
}

#[derive(Debug, Clone)]
pub struct ResolveTextResult {
    pub output: Option<String>,
    pub plan: ResolvePlan,
}

pub fn protect_text(
    input: &str,
    operation_id: &str,
    policy: &dyn PolicyEngine,
    vault: &dyn VaultWriter,
    consent_store: Option<&dam_consent::ConsentStore>,
    event_sink: Option<&dyn EventSink>,
    options: ReplacementPlanOptions,
) -> Result<ProtectTextResult, PipelineError> {
    let detections = dam_detect::detect(input);
    let base_decisions = policy.decide_all(&detections);
    let (decisions, consent_matches) =
        dam_consent::apply_consents_to_decisions(&base_decisions, consent_store)?;

    if decisions
        .iter()
        .any(|decision| decision.action == PolicyAction::Block)
    {
        let plan = blocked_plan_from_decisions(&decisions);
        record_filter_events(
            event_sink,
            operation_id,
            &decisions,
            &plan,
            &consent_matches,
        );
        return Ok(ProtectTextResult {
            status: ProtectTextStatus::Blocked,
            output: None,
            detections,
            decisions,
            plan,
            consent_matches,
        });
    }

    let plan =
        dam_core::build_replacement_plan_from_decisions_with_options(&decisions, vault, options);
    record_filter_events(
        event_sink,
        operation_id,
        &decisions,
        &plan,
        &consent_matches,
    );
    let output = dam_redact::redact(input, &plan.replacements);

    Ok(ProtectTextResult {
        status: ProtectTextStatus::Protected,
        output: Some(output),
        detections,
        decisions,
        plan,
        consent_matches,
    })
}

pub fn resolve_text(
    input: &str,
    operation_id: &str,
    vault: &dyn VaultReader,
    event_sink: Option<&dyn EventSink>,
) -> ResolveTextResult {
    let plan = dam_core::build_resolve_plan(input, vault);
    if plan.references.is_empty() {
        return ResolveTextResult { output: None, plan };
    }

    record_resolve_events(event_sink, operation_id, &plan);
    if plan.resolved_count() == 0 {
        return ResolveTextResult { output: None, plan };
    }

    let output = dam_core::apply_resolve_plan(input, &plan);
    ResolveTextResult {
        output: Some(output),
        plan,
    }
}

pub fn blocked_plan_from_decisions(decisions: &[PolicyDecision]) -> ReplacementPlan {
    ReplacementPlan {
        blocked: decisions
            .iter()
            .filter(|decision| decision.action == PolicyAction::Block)
            .map(|decision| dam_core::BlockedDetection {
                kind: decision.detection.kind,
                span: decision.detection.span,
            })
            .collect(),
        ..ReplacementPlan::default()
    }
}

pub fn record_filter_events(
    event_sink: Option<&dyn EventSink>,
    operation_id: &str,
    decisions: &[PolicyDecision],
    plan: &ReplacementPlan,
    consent_matches: &[dam_consent::ConsentMatch],
) {
    let Some(sink) = event_sink else {
        return;
    };

    for event in dam_core::build_filter_log_events_from_decisions(operation_id, decisions, plan) {
        let _ = sink.record(&event);
    }

    for consent_match in consent_matches {
        let event = LogEvent::new(
            operation_id,
            LogLevel::Info,
            LogEventType::Consent,
            "active consent allowed detected value",
        )
        .with_kind(consent_match.kind)
        .with_action(format!("allow:{}", consent_match.consent_id));
        let _ = sink.record(&event);
    }
}

pub fn record_resolve_events(
    event_sink: Option<&dyn EventSink>,
    operation_id: &str,
    plan: &ResolvePlan,
) {
    let Some(sink) = event_sink else {
        return;
    };

    for event in dam_core::build_resolve_log_events(operation_id, plan) {
        let _ = sink.record(&event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dam_core::{
        Detection, LogEvent, LogWriteError, Reference, SensitiveType, Span, VaultReadError,
        VaultRecord, VaultWriteError,
    };
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingVault {
        records: Mutex<Vec<VaultRecord>>,
    }

    impl VaultWriter for RecordingVault {
        fn write(&self, record: &VaultRecord) -> Result<(), VaultWriteError> {
            self.records.lock().unwrap().push(record.clone());
            Ok(())
        }
    }

    impl VaultReader for RecordingVault {
        fn read(&self, reference: &Reference) -> Result<Option<String>, VaultReadError> {
            Ok(self
                .records
                .lock()
                .unwrap()
                .iter()
                .find(|record| &record.reference == reference)
                .map(|record| record.value.clone()))
        }
    }

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<LogEvent>>,
    }

    impl EventSink for RecordingSink {
        fn record(&self, event: &LogEvent) -> Result<(), LogWriteError> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    fn detection(value: &str) -> Detection {
        Detection {
            kind: SensitiveType::Email,
            span: Span {
                start: 6,
                end: 6 + value.len(),
            },
            value: value.to_string(),
        }
    }

    #[test]
    fn protect_text_tokenizes_and_logs_without_raw_values() {
        let vault = RecordingVault::default();
        let sink = RecordingSink::default();
        let policy = dam_policy::StaticPolicy::new(PolicyAction::Tokenize);

        let result = protect_text(
            "email alice@example.com",
            "op-test",
            &policy,
            &vault,
            None,
            Some(&sink),
            ReplacementPlanOptions::default(),
        )
        .unwrap();

        assert_eq!(result.status, ProtectTextStatus::Protected);
        let output = result.output.unwrap();
        assert!(!output.contains("alice@example.com"));
        assert!(output.contains("[email:"));
        assert_eq!(vault.records.lock().unwrap().len(), 1);

        let event_text = sink
            .events
            .lock()
            .unwrap()
            .iter()
            .map(|event| event.message.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!event_text.contains("alice@example.com"));
    }

    #[test]
    fn protect_text_blocks_before_vault_write() {
        let vault = RecordingVault::default();
        let sink = RecordingSink::default();
        let policy = dam_policy::StaticPolicy::new(PolicyAction::Block);

        let result = protect_text(
            "email alice@example.com",
            "op-test",
            &policy,
            &vault,
            None,
            Some(&sink),
            ReplacementPlanOptions::default(),
        )
        .unwrap();

        assert!(result.is_blocked());
        assert!(result.output.is_none());
        assert_eq!(result.plan.blocked_count(), 1);
        assert!(vault.records.lock().unwrap().is_empty());
    }

    #[test]
    fn protect_text_applies_active_consent() {
        let vault = RecordingVault::default();
        let sink = RecordingSink::default();
        let consent_store = dam_consent::ConsentStore::open_in_memory().unwrap();
        consent_store
            .grant(&dam_consent::GrantConsent {
                kind: SensitiveType::Email,
                value: "alice@example.com".to_string(),
                vault_key: None,
                ttl_seconds: 60,
                created_by: "test".to_string(),
                reason: None,
            })
            .unwrap();
        let policy = dam_policy::StaticPolicy::new(PolicyAction::Tokenize);

        let result = protect_text(
            "email alice@example.com",
            "op-test",
            &policy,
            &vault,
            Some(&consent_store),
            Some(&sink),
            ReplacementPlanOptions::default(),
        )
        .unwrap();

        assert_eq!(result.output.unwrap(), "email alice@example.com");
        assert_eq!(result.consent_matches.len(), 1);
        assert!(vault.records.lock().unwrap().is_empty());
        assert!(sink.events.lock().unwrap().iter().any(|event| {
            event.event_type == LogEventType::Consent
                && event
                    .action
                    .as_deref()
                    .is_some_and(|action| action.starts_with("allow:"))
        }));
    }

    #[test]
    fn resolve_text_restores_known_references_and_logs() {
        let vault = RecordingVault::default();
        let sink = RecordingSink::default();
        let reference = Reference::generate(SensitiveType::Email);
        vault
            .write(&VaultRecord {
                reference: reference.clone(),
                kind: SensitiveType::Email,
                value: "alice@example.com".to_string(),
            })
            .unwrap();
        let input = format!("email {}", reference.display());

        let result = resolve_text(&input, "op-test", &vault, Some(&sink));

        assert_eq!(result.output.unwrap(), "email alice@example.com");
        assert_eq!(result.plan.resolved_count(), 1);
        assert!(sink.events.lock().unwrap().iter().any(|event| {
            event.event_type == LogEventType::Resolve && event.action.as_deref() == Some("resolved")
        }));
    }

    #[test]
    fn resolve_text_leaves_unresolved_output_empty_but_logs_reference() {
        let vault = RecordingVault::default();
        let sink = RecordingSink::default();
        let reference = Reference::generate(SensitiveType::Email);
        let input = format!("email {}", reference.display());

        let result = resolve_text(&input, "op-test", &vault, Some(&sink));

        assert!(result.output.is_none());
        assert_eq!(result.plan.resolved_count(), 0);
        assert_eq!(result.plan.missing.len(), 1);
        assert!(sink.events.lock().unwrap().iter().any(|event| {
            event.event_type == LogEventType::Resolve && event.action.as_deref() == Some("missing")
        }));
    }

    #[test]
    fn blocked_plan_contains_only_blocked_decisions() {
        let decisions = [
            PolicyDecision::new(detection("alice@example.com"), PolicyAction::Block),
            PolicyDecision::new(detection("bob@example.com"), PolicyAction::Tokenize),
        ];

        let plan = blocked_plan_from_decisions(&decisions);

        assert_eq!(plan.blocked_count(), 1);
    }
}
