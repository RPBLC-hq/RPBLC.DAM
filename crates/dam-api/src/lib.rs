use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveKind {
    Email,
    Phone,
    Ssn,
    #[serde(rename = "cc", alias = "credit_card")]
    CreditCard,
}

impl From<dam_core::SensitiveType> for SensitiveKind {
    fn from(kind: dam_core::SensitiveType) -> Self {
        match kind {
            dam_core::SensitiveType::Email => Self::Email,
            dam_core::SensitiveType::Phone => Self::Phone,
            dam_core::SensitiveType::Ssn => Self::Ssn,
            dam_core::SensitiveType::CreditCard => Self::CreditCard,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Tokenize,
    Redact,
    Allow,
    Block,
}

impl From<dam_core::PolicyAction> for PolicyAction {
    fn from(action: dam_core::PolicyAction) -> Self {
        match action {
            dam_core::PolicyAction::Tokenize => Self::Tokenize,
            dam_core::PolicyAction::Redact => Self::Redact,
            dam_core::PolicyAction::Allow => Self::Allow,
            dam_core::PolicyAction::Block => Self::Block,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplacementMode {
    Tokenized,
    Redacted,
    RedactOnlyFallback,
}

impl From<dam_core::ReplacementMode> for ReplacementMode {
    fn from(mode: dam_core::ReplacementMode) -> Self {
        match mode {
            dam_core::ReplacementMode::Tokenized => Self::Tokenized,
            dam_core::ReplacementMode::Redacted => Self::Redacted,
            dam_core::ReplacementMode::RedactOnlyFallback => Self::RedactOnlyFallback,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl From<dam_core::Span> for Span {
    fn from(span: dam_core::Span) -> Self {
        Self {
            start: span.start,
            end: span.end,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    pub kind: SensitiveKind,
    pub id: String,
    pub key: String,
    pub display: String,
}

impl From<&dam_core::Reference> for Reference {
    fn from(reference: &dam_core::Reference) -> Self {
        Self {
            kind: reference.kind.into(),
            id: reference.id.clone(),
            key: reference.key(),
            display: reference.display(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub message: String,
}

impl Diagnostic {
    pub fn new(
        severity: DiagnosticSeverity,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterStatus {
    Completed,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterSummary {
    pub detections: usize,
    pub tokenized: usize,
    pub policy_redactions: usize,
    pub allowed: usize,
    pub blocked: usize,
    pub fallback_redactions: usize,
    pub vault_failures: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionReport {
    pub kind: SensitiveKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecisionReport {
    pub kind: SensitiveKind,
    pub span: Span,
    pub action: PolicyAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplacementReport {
    pub kind: Option<SensitiveKind>,
    pub span: Span,
    pub mode: ReplacementMode,
    pub reference: Option<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultWriteFailureReport {
    pub kind: SensitiveKind,
    pub error: String,
}

pub const VAULT_WRITE_FAILURE_REPORT_ERROR: &str = "vault_write_failed";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedDetectionReport {
    pub kind: SensitiveKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterReport {
    pub operation_id: String,
    pub status: FilterStatus,
    pub summary: FilterSummary,
    pub detections: Vec<DetectionReport>,
    pub decisions: Vec<PolicyDecisionReport>,
    pub replacements: Vec<ReplacementReport>,
    pub vault_failures: Vec<VaultWriteFailureReport>,
    pub blocked: Vec<BlockedDetectionReport>,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn filter_report_from_decisions(
    operation_id: impl Into<String>,
    decisions: &[dam_core::PolicyDecision],
    plan: &dam_core::ReplacementPlan,
) -> FilterReport {
    let detections = decisions
        .iter()
        .map(|decision| DetectionReport {
            kind: decision.detection.kind.into(),
            span: decision.detection.span.into(),
        })
        .collect::<Vec<_>>();

    let decisions_report = decisions
        .iter()
        .map(|decision| PolicyDecisionReport {
            kind: decision.detection.kind.into(),
            span: decision.detection.span.into(),
            action: decision.action.into(),
        })
        .collect::<Vec<_>>();

    let replacements = plan
        .replacements
        .iter()
        .map(|replacement| ReplacementReport {
            kind: kind_for_replacement(replacement, decisions).map(Into::into),
            span: replacement.span.into(),
            mode: replacement.mode.clone().into(),
            reference: replacement.reference.as_ref().map(Into::into),
        })
        .collect::<Vec<_>>();

    let vault_failures = plan
        .vault_failures
        .iter()
        .map(|failure| VaultWriteFailureReport {
            kind: failure.kind.into(),
            error: VAULT_WRITE_FAILURE_REPORT_ERROR.to_string(),
        })
        .collect::<Vec<_>>();

    let blocked = plan
        .blocked
        .iter()
        .map(|blocked| BlockedDetectionReport {
            kind: blocked.kind.into(),
            span: blocked.span.into(),
        })
        .collect::<Vec<_>>();

    let diagnostics = plan
        .vault_failures
        .iter()
        .map(|failure| {
            Diagnostic::new(
                DiagnosticSeverity::Warning,
                "vault_write_failed",
                format!(
                    "{} vault write failed; redact-only fallback used",
                    failure.kind.tag()
                ),
            )
        })
        .collect::<Vec<_>>();

    FilterReport {
        operation_id: operation_id.into(),
        status: if plan.blocked_count() > 0 {
            FilterStatus::Blocked
        } else {
            FilterStatus::Completed
        },
        summary: FilterSummary {
            detections: decisions.len(),
            tokenized: plan.tokenized_count(),
            policy_redactions: plan.redacted_count(),
            allowed: policy_action_count(decisions, dam_core::PolicyAction::Allow),
            blocked: plan.blocked_count(),
            fallback_redactions: plan.fallback_count(),
            vault_failures: plan.vault_failures.len(),
        },
        detections,
        decisions: decisions_report,
        replacements,
        vault_failures,
        blocked,
        diagnostics,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveStatus {
    Completed,
    Unresolved,
    FailedStrict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveSummary {
    pub references: usize,
    pub resolved: usize,
    pub missing: usize,
    pub read_failures: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceReport {
    pub kind: SensitiveKind,
    pub span: Span,
    pub reference: Reference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultReadFailureReport {
    pub kind: SensitiveKind,
    pub span: Span,
    pub reference: Reference,
    pub error: String,
}

pub const VAULT_READ_FAILURE_REPORT_ERROR: &str = "vault_read_failed";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveReport {
    pub operation_id: String,
    pub status: ResolveStatus,
    pub strict: bool,
    pub summary: ResolveSummary,
    pub references: Vec<ReferenceReport>,
    pub resolved: Vec<ReferenceReport>,
    pub missing: Vec<ReferenceReport>,
    pub read_failures: Vec<VaultReadFailureReport>,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn resolve_report(
    operation_id: impl Into<String>,
    plan: &dam_core::ResolvePlan,
    strict: bool,
) -> ResolveReport {
    let references = plan
        .references
        .iter()
        .map(|reference_match| ReferenceReport {
            kind: reference_match.reference.kind.into(),
            span: reference_match.span.into(),
            reference: (&reference_match.reference).into(),
        })
        .collect::<Vec<_>>();

    let resolved = plan
        .replacements
        .iter()
        .map(|replacement| ReferenceReport {
            kind: replacement.reference.kind.into(),
            span: replacement.span.into(),
            reference: (&replacement.reference).into(),
        })
        .collect::<Vec<_>>();

    let missing = plan
        .missing
        .iter()
        .map(|missing| ReferenceReport {
            kind: missing.reference.kind.into(),
            span: missing.span.into(),
            reference: (&missing.reference).into(),
        })
        .collect::<Vec<_>>();

    let read_failures = plan
        .read_failures
        .iter()
        .map(|failure| VaultReadFailureReport {
            kind: failure.reference.kind.into(),
            span: failure.span.into(),
            reference: (&failure.reference).into(),
            error: VAULT_READ_FAILURE_REPORT_ERROR.to_string(),
        })
        .collect::<Vec<_>>();

    let mut diagnostics = Vec::new();
    diagnostics.extend(plan.missing.iter().map(|missing| {
        Diagnostic::new(
            DiagnosticSeverity::Warning,
            "vault_reference_missing",
            format!(
                "{} reference missing from vault",
                missing.reference.kind.tag()
            ),
        )
    }));
    diagnostics.extend(plan.read_failures.iter().map(|failure| {
        Diagnostic::new(
            DiagnosticSeverity::Warning,
            "vault_read_failed",
            format!(
                "{} vault read failed; reference left unresolved",
                failure.reference.kind.tag()
            ),
        )
    }));

    ResolveReport {
        operation_id: operation_id.into(),
        status: if strict && plan.has_unresolved() {
            ResolveStatus::FailedStrict
        } else if plan.has_unresolved() {
            ResolveStatus::Unresolved
        } else {
            ResolveStatus::Completed
        },
        strict,
        summary: ResolveSummary {
            references: plan.references.len(),
            resolved: plan.resolved_count(),
            missing: plan.missing_count(),
            read_failures: plan.read_failure_count(),
        },
        references,
        resolved,
        missing,
        read_failures,
        diagnostics,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyState {
    Protected,
    Bypassing,
    Blocked,
    ProviderDown,
    ConfigRequired,
    DamDown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyReport {
    pub operation_id: Option<String>,
    pub target: Option<String>,
    pub upstream: Option<String>,
    pub state: ProxyState,
    pub message: String,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub component: String,
    pub state: HealthState,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthReport {
    pub state: HealthState,
    pub components: Vec<ComponentHealth>,
    pub diagnostics: Vec<Diagnostic>,
}

fn policy_action_count(
    decisions: &[dam_core::PolicyDecision],
    action: dam_core::PolicyAction,
) -> usize {
    decisions
        .iter()
        .filter(|decision| decision.action == action)
        .count()
}

fn kind_for_replacement(
    replacement: &dam_core::Replacement,
    decisions: &[dam_core::PolicyDecision],
) -> Option<dam_core::SensitiveType> {
    replacement
        .reference
        .as_ref()
        .map(|reference| reference.kind)
        .or_else(|| {
            decisions
                .iter()
                .find(|decision| decision.detection.span == replacement.span)
                .map(|decision| decision.detection.kind)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detection(kind: dam_core::SensitiveType, value: &str) -> dam_core::Detection {
        dam_core::Detection {
            kind,
            value: value.to_string(),
            span: dam_core::Span {
                start: 0,
                end: value.len(),
            },
        }
    }

    #[test]
    fn filter_report_does_not_serialize_raw_detection_values_or_previews() {
        let decision = dam_core::PolicyDecision::new(
            detection(dam_core::SensitiveType::Email, "alice@example.com"),
            dam_core::PolicyAction::Tokenize,
        );
        let plan = dam_core::ReplacementPlan {
            replacements: vec![dam_core::Replacement {
                span: decision.detection.span,
                text: "[email]".to_string(),
                mode: dam_core::ReplacementMode::RedactOnlyFallback,
                reference: None,
            }],
            vault_failures: vec![dam_core::VaultFailure {
                kind: dam_core::SensitiveType::Email,
                value_preview: "alic...".to_string(),
                error: "vault unavailable for alice@example.com".to_string(),
            }],
            blocked: Vec::new(),
        };

        let report = filter_report_from_decisions("op-1", &[decision], &plan);
        let json = serde_json::to_string(&report).unwrap();

        assert_eq!(report.summary.fallback_redactions, 1);
        assert_eq!(
            report.vault_failures[0].error,
            VAULT_WRITE_FAILURE_REPORT_ERROR
        );
        assert!(!json.contains("alice@example.com"));
        assert!(!json.contains("alic..."));
        assert!(!json.contains("vault unavailable"));
    }

    #[test]
    fn resolve_report_marks_strict_unresolved_as_failed_strict() {
        let reference = dam_core::Reference::generate(dam_core::SensitiveType::Ssn);
        let plan = dam_core::ResolvePlan {
            references: vec![dam_core::ReferenceMatch {
                span: dam_core::Span { start: 0, end: 1 },
                reference: reference.clone(),
            }],
            missing: vec![dam_core::MissingReference {
                span: dam_core::Span { start: 0, end: 1 },
                reference,
            }],
            ..dam_core::ResolvePlan::default()
        };

        let report = resolve_report("op-1", &plan, true);

        assert_eq!(report.status, ResolveStatus::FailedStrict);
        assert_eq!(report.summary.references, 1);
        assert_eq!(report.summary.missing, 1);
    }

    #[test]
    fn resolve_report_does_not_serialize_vault_read_error_details() {
        let reference = dam_core::Reference::generate(dam_core::SensitiveType::Email);
        let plan = dam_core::ResolvePlan {
            references: vec![dam_core::ReferenceMatch {
                span: dam_core::Span { start: 0, end: 1 },
                reference: reference.clone(),
            }],
            read_failures: vec![dam_core::VaultReadFailure {
                span: dam_core::Span { start: 0, end: 1 },
                reference,
                error: "backend echoed alice@example.com".to_string(),
            }],
            ..dam_core::ResolvePlan::default()
        };

        let report = resolve_report("op-1", &plan, false);
        let json = serde_json::to_string(&report).unwrap();

        assert_eq!(
            report.read_failures[0].error,
            VAULT_READ_FAILURE_REPORT_ERROR
        );
        assert!(report.diagnostics[0].message.contains("vault read failed"));
        assert!(!json.contains("backend echoed"));
        assert!(!json.contains("alice@example.com"));
    }

    #[test]
    fn credit_card_kind_serializes_as_reference_tag() {
        let json = serde_json::to_string(&SensitiveKind::CreditCard).unwrap();

        assert_eq!(json, r#""cc""#);
    }
}
