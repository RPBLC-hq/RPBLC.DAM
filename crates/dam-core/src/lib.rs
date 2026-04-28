use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SensitiveType {
    Email,
    Phone,
    Ssn,
    CreditCard,
}

impl SensitiveType {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Ssn => "ssn",
            Self::CreditCard => "cc",
        }
    }

    pub fn from_tag(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "email" => Some(Self::Email),
            "phone" => Some(Self::Phone),
            "ssn" => Some(Self::Ssn),
            "cc" | "credit_card" | "credit-card" => Some(Self::CreditCard),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn overlaps(self, other: Span) -> bool {
        self.start < other.end && other.start < self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub kind: SensitiveType,
    pub span: Span,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Reference {
    pub kind: SensitiveType,
    pub id: String,
}

impl Reference {
    pub fn generate(kind: SensitiveType) -> Self {
        loop {
            let uuid = uuid::Uuid::new_v4();
            let id = bs58::encode(uuid.as_bytes()).into_string();
            if id.len() == 22 {
                return Self { kind, id };
            }
        }
    }

    pub fn key(&self) -> String {
        format!("{}:{}", self.kind.tag(), self.id)
    }

    pub fn display(&self) -> String {
        format!("[{}]", self.key())
    }

    pub fn parse_key(value: &str) -> Option<Self> {
        let (kind, id) = value.split_once(':')?;
        let kind = SensitiveType::from_tag(kind)?;
        if !valid_reference_id(id) {
            return None;
        }

        Some(Self {
            kind,
            id: id.to_string(),
        })
    }

    pub fn parse_display(value: &str) -> Option<Self> {
        let key = value.strip_prefix('[')?.strip_suffix(']')?;
        Self::parse_key(key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRecord {
    pub reference: Reference,
    pub kind: SensitiveType,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct VaultWriteError {
    pub message: String,
}

impl VaultWriteError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub trait VaultWriter: Send + Sync {
    fn write(&self, record: &VaultRecord) -> Result<(), VaultWriteError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct VaultReadError {
    pub message: String,
}

impl VaultReadError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub trait VaultReader: Send + Sync {
    fn read(&self, reference: &Reference) -> Result<Option<String>, VaultReadError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogEventType {
    Detection,
    PolicyDecision,
    VaultWrite,
    VaultWriteFailed,
    VaultRead,
    VaultReadFailed,
    Consent,
    Redaction,
    Resolve,
    ProxyForward,
    ProxyBypass,
    ProxyFailure,
}

impl LogEventType {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Detection => "detection",
            Self::PolicyDecision => "policy_decision",
            Self::VaultWrite => "vault_write",
            Self::VaultWriteFailed => "vault_write_failed",
            Self::VaultRead => "vault_read",
            Self::VaultReadFailed => "vault_read_failed",
            Self::Consent => "consent",
            Self::Redaction => "redaction",
            Self::Resolve => "resolve",
            Self::ProxyForward => "proxy_forward",
            Self::ProxyBypass => "proxy_bypass",
            Self::ProxyFailure => "proxy_failure",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEvent {
    pub timestamp: i64,
    pub operation_id: String,
    pub level: LogLevel,
    pub event_type: LogEventType,
    pub kind: Option<SensitiveType>,
    pub reference: Option<Reference>,
    pub action: Option<String>,
    pub message: String,
}

impl LogEvent {
    pub fn new(
        operation_id: impl Into<String>,
        level: LogLevel,
        event_type: LogEventType,
        message: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: now_unix_secs(),
            operation_id: operation_id.into(),
            level,
            event_type,
            kind: None,
            reference: None,
            action: None,
            message: message.into(),
        }
    }

    pub fn with_kind(mut self, kind: SensitiveType) -> Self {
        self.kind = Some(kind);
        self
    }

    pub fn with_reference(mut self, reference: Reference) -> Self {
        self.reference = Some(reference);
        self
    }

    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct LogWriteError {
    pub message: String,
}

impl LogWriteError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub trait EventSink: Send + Sync {
    fn record(&self, event: &LogEvent) -> Result<(), LogWriteError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyAction {
    Tokenize,
    Redact,
    Allow,
    Block,
}

impl PolicyAction {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Tokenize => "tokenize",
            Self::Redact => "redact",
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }

    pub fn from_tag(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "tokenize" => Some(Self::Tokenize),
            "redact" => Some(Self::Redact),
            "allow" => Some(Self::Allow),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub detection: Detection,
    pub action: PolicyAction,
}

impl PolicyDecision {
    pub fn new(detection: Detection, action: PolicyAction) -> Self {
        Self { detection, action }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplacementMode {
    Tokenized,
    Redacted,
    RedactOnlyFallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    pub span: Span,
    pub text: String,
    pub mode: ReplacementMode,
    pub reference: Option<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultFailure {
    pub kind: SensitiveType,
    pub value_preview: String,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedDetection {
    pub kind: SensitiveType,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReplacementPlan {
    pub replacements: Vec<Replacement>,
    pub vault_failures: Vec<VaultFailure>,
    pub blocked: Vec<BlockedDetection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplacementPlanOptions {
    pub deduplicate_replacements: bool,
}

impl Default for ReplacementPlanOptions {
    fn default() -> Self {
        Self {
            deduplicate_replacements: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReplacementDedupKey {
    kind: SensitiveType,
    action: PolicyAction,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CachedReplacement {
    Tokenized(Reference),
    RedactOnlyFallback,
    Redacted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceMatch {
    pub span: Span,
    pub reference: Reference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveReplacement {
    pub span: Span,
    pub text: String,
    pub reference: Reference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingReference {
    pub span: Span,
    pub reference: Reference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultReadFailure {
    pub span: Span,
    pub reference: Reference,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvePlan {
    pub references: Vec<ReferenceMatch>,
    pub replacements: Vec<ResolveReplacement>,
    pub missing: Vec<MissingReference>,
    pub read_failures: Vec<VaultReadFailure>,
}

impl ReplacementPlan {
    pub fn tokenized_count(&self) -> usize {
        self.replacements
            .iter()
            .filter(|r| r.mode == ReplacementMode::Tokenized)
            .count()
    }

    pub fn fallback_count(&self) -> usize {
        self.replacements
            .iter()
            .filter(|r| r.mode == ReplacementMode::RedactOnlyFallback)
            .count()
    }

    pub fn redacted_count(&self) -> usize {
        self.replacements
            .iter()
            .filter(|r| r.mode == ReplacementMode::Redacted)
            .count()
    }

    pub fn blocked_count(&self) -> usize {
        self.blocked.len()
    }

    pub fn vault_write_count(&self) -> usize {
        self.replacements
            .iter()
            .filter_map(|replacement| replacement.reference.as_ref())
            .map(Reference::key)
            .collect::<HashSet<_>>()
            .len()
    }
}

impl ResolvePlan {
    pub fn resolved_count(&self) -> usize {
        self.replacements.len()
    }

    pub fn missing_count(&self) -> usize {
        self.missing.len()
    }

    pub fn read_failure_count(&self) -> usize {
        self.read_failures.len()
    }

    pub fn has_unresolved(&self) -> bool {
        !self.missing.is_empty() || !self.read_failures.is_empty()
    }
}

pub fn find_references(input: &str) -> Vec<ReferenceMatch> {
    let mut matches = Vec::new();
    let mut cursor = 0;

    while cursor < input.len() {
        let Some(start_offset) = input[cursor..].find('[') else {
            break;
        };
        let start = cursor + start_offset;
        let content_start = start + 1;
        let Some(end_offset) = input[content_start..].find(']') else {
            break;
        };
        let end = content_start + end_offset;
        let display_end = end + 1;

        if let Some(reference) = Reference::parse_key(&input[content_start..end]) {
            matches.push(ReferenceMatch {
                span: Span {
                    start,
                    end: display_end,
                },
                reference,
            });
            cursor = display_end;
        } else {
            cursor = content_start;
        }
    }

    matches
}

pub fn build_resolve_plan(input: &str, vault: &(impl VaultReader + ?Sized)) -> ResolvePlan {
    let references = find_references(input);
    let mut plan = ResolvePlan {
        references: references.clone(),
        ..ResolvePlan::default()
    };

    for reference_match in references {
        match vault.read(&reference_match.reference) {
            Ok(Some(value)) => plan.replacements.push(ResolveReplacement {
                span: reference_match.span,
                text: value,
                reference: reference_match.reference,
            }),
            Ok(None) => plan.missing.push(MissingReference {
                span: reference_match.span,
                reference: reference_match.reference,
            }),
            Err(error) => plan.read_failures.push(VaultReadFailure {
                span: reference_match.span,
                reference: reference_match.reference,
                error: error.to_string(),
            }),
        }
    }

    plan
}

pub fn apply_resolve_plan(input: &str, plan: &ResolvePlan) -> String {
    let mut output = input.to_string();
    let mut sorted = plan.replacements.iter().collect::<Vec<_>>();
    sorted.sort_by(|a, b| b.span.start.cmp(&a.span.start));

    for replacement in sorted {
        if replacement.span.start <= output.len()
            && replacement.span.end <= output.len()
            && replacement.span.start <= replacement.span.end
        {
            output.replace_range(
                replacement.span.start..replacement.span.end,
                &replacement.text,
            );
        }
    }

    output
}

pub fn build_resolve_log_events(operation_id: &str, plan: &ResolvePlan) -> Vec<LogEvent> {
    let mut events = Vec::with_capacity(
        plan.replacements.len() * 2 + plan.missing.len() + plan.read_failures.len(),
    );

    for replacement in &plan.replacements {
        events.push(
            LogEvent::new(
                operation_id,
                LogLevel::Info,
                LogEventType::VaultRead,
                "vault read succeeded",
            )
            .with_kind(replacement.reference.kind)
            .with_reference(replacement.reference.clone())
            .with_action("vault_read_succeeded"),
        );
        events.push(
            LogEvent::new(
                operation_id,
                LogLevel::Info,
                LogEventType::Resolve,
                "reference resolved",
            )
            .with_kind(replacement.reference.kind)
            .with_reference(replacement.reference.clone())
            .with_action("resolved"),
        );
    }

    for missing in &plan.missing {
        events.push(
            LogEvent::new(
                operation_id,
                LogLevel::Warn,
                LogEventType::Resolve,
                "reference missing from vault",
            )
            .with_kind(missing.reference.kind)
            .with_reference(missing.reference.clone())
            .with_action("missing"),
        );
    }

    for failure in &plan.read_failures {
        events.push(
            LogEvent::new(
                operation_id,
                LogLevel::Warn,
                LogEventType::VaultReadFailed,
                "vault read failed",
            )
            .with_kind(failure.reference.kind)
            .with_reference(failure.reference.clone())
            .with_action("vault_read_failed"),
        );
    }

    events
}

pub fn build_replacement_plan(
    detections: &[Detection],
    vault: &(impl VaultWriter + ?Sized),
) -> ReplacementPlan {
    build_replacement_plan_with_options(detections, vault, ReplacementPlanOptions::default())
}

pub fn build_replacement_plan_with_options(
    detections: &[Detection],
    vault: &(impl VaultWriter + ?Sized),
    options: ReplacementPlanOptions,
) -> ReplacementPlan {
    let decisions = detections
        .iter()
        .cloned()
        .map(|detection| PolicyDecision::new(detection, PolicyAction::Tokenize))
        .collect::<Vec<_>>();
    build_replacement_plan_from_decisions_with_options(&decisions, vault, options)
}

pub fn build_replacement_plan_from_decisions(
    decisions: &[PolicyDecision],
    vault: &(impl VaultWriter + ?Sized),
) -> ReplacementPlan {
    build_replacement_plan_from_decisions_with_options(
        decisions,
        vault,
        ReplacementPlanOptions::default(),
    )
}

pub fn build_replacement_plan_from_decisions_with_options(
    decisions: &[PolicyDecision],
    vault: &(impl VaultWriter + ?Sized),
    options: ReplacementPlanOptions,
) -> ReplacementPlan {
    let mut plan = ReplacementPlan::default();
    let mut dedup_cache = HashMap::<ReplacementDedupKey, CachedReplacement>::new();

    for decision in decisions {
        let detection = &decision.detection;
        match decision.action {
            PolicyAction::Tokenize => {
                let dedup_key = options
                    .deduplicate_replacements
                    .then(|| ReplacementDedupKey::from_decision(decision));
                if let Some(cached) = dedup_key
                    .as_ref()
                    .and_then(|key| dedup_cache.get(key))
                    .cloned()
                {
                    plan.replacements.push(cached.into_replacement(detection));
                    continue;
                }

                let reference = Reference::generate(detection.kind);
                let record = VaultRecord {
                    reference: reference.clone(),
                    kind: detection.kind,
                    value: detection.value.clone(),
                };

                match vault.write(&record) {
                    Ok(()) => {
                        if let Some(key) = dedup_key {
                            dedup_cache
                                .insert(key, CachedReplacement::Tokenized(reference.clone()));
                        }
                        plan.replacements.push(Replacement {
                            span: detection.span,
                            text: reference.display(),
                            mode: ReplacementMode::Tokenized,
                            reference: Some(reference),
                        });
                    }
                    Err(error) => {
                        if let Some(key) = dedup_key {
                            dedup_cache.insert(key, CachedReplacement::RedactOnlyFallback);
                        }
                        plan.vault_failures.push(VaultFailure {
                            kind: detection.kind,
                            value_preview: preview(&detection.value),
                            error: error.to_string(),
                        });
                        plan.replacements.push(Replacement {
                            span: detection.span,
                            text: redacted_placeholder(detection.kind),
                            mode: ReplacementMode::RedactOnlyFallback,
                            reference: None,
                        });
                    }
                }
            }
            PolicyAction::Redact => {
                let dedup_key = options
                    .deduplicate_replacements
                    .then(|| ReplacementDedupKey::from_decision(decision));
                if let Some(cached) = dedup_key
                    .as_ref()
                    .and_then(|key| dedup_cache.get(key))
                    .cloned()
                {
                    plan.replacements.push(cached.into_replacement(detection));
                    continue;
                }
                if let Some(key) = dedup_key {
                    dedup_cache.insert(key, CachedReplacement::Redacted);
                }
                plan.replacements
                    .push(CachedReplacement::Redacted.into_replacement(detection));
            }
            PolicyAction::Allow => {}
            PolicyAction::Block => {
                plan.blocked.push(BlockedDetection {
                    kind: detection.kind,
                    span: detection.span,
                });
            }
        }
    }

    plan
}

impl ReplacementDedupKey {
    fn from_decision(decision: &PolicyDecision) -> Self {
        Self {
            kind: decision.detection.kind,
            action: decision.action,
            value: decision.detection.value.clone(),
        }
    }
}

impl CachedReplacement {
    fn into_replacement(self, detection: &Detection) -> Replacement {
        match self {
            Self::Tokenized(reference) => Replacement {
                span: detection.span,
                text: reference.display(),
                mode: ReplacementMode::Tokenized,
                reference: Some(reference),
            },
            Self::RedactOnlyFallback => Replacement {
                span: detection.span,
                text: redacted_placeholder(detection.kind),
                mode: ReplacementMode::RedactOnlyFallback,
                reference: None,
            },
            Self::Redacted => Replacement {
                span: detection.span,
                text: redacted_placeholder(detection.kind),
                mode: ReplacementMode::Redacted,
                reference: None,
            },
        }
    }
}

pub fn redacted_placeholder(kind: SensitiveType) -> String {
    format!("[{}]", kind.tag())
}

pub fn generate_operation_id() -> String {
    loop {
        let uuid = uuid::Uuid::new_v4();
        let id = bs58::encode(uuid.as_bytes()).into_string();
        if id.len() == 22 {
            return id;
        }
    }
}

pub fn build_filter_log_events(
    operation_id: &str,
    detections: &[Detection],
    plan: &ReplacementPlan,
) -> Vec<LogEvent> {
    let decisions = detections
        .iter()
        .cloned()
        .map(|detection| PolicyDecision::new(detection, PolicyAction::Tokenize))
        .collect::<Vec<_>>();
    build_filter_log_events_from_decisions(operation_id, &decisions, plan)
}

pub fn build_filter_log_events_from_decisions(
    operation_id: &str,
    decisions: &[PolicyDecision],
    plan: &ReplacementPlan,
) -> Vec<LogEvent> {
    let mut events = Vec::with_capacity(decisions.len() * 2 + plan.replacements.len() * 2);
    let mut logged_vault_writes = HashSet::<String>::new();

    for decision in decisions {
        let detection = &decision.detection;
        events.push(
            LogEvent::new(
                operation_id,
                LogLevel::Info,
                LogEventType::Detection,
                format!(
                    "sensitive value detected at span {}..{}",
                    detection.span.start, detection.span.end
                ),
            )
            .with_kind(detection.kind)
            .with_action("detected"),
        );

        events.push(
            LogEvent::new(
                operation_id,
                LogLevel::Info,
                LogEventType::PolicyDecision,
                "policy decision applied",
            )
            .with_kind(detection.kind)
            .with_action(decision.action.tag()),
        );
    }

    for replacement in &plan.replacements {
        let kind = kind_for_replacement(replacement, decisions);
        match replacement.mode {
            ReplacementMode::Tokenized => {
                let reference = replacement
                    .reference
                    .clone()
                    .expect("tokenized replacements must carry a reference");
                if logged_vault_writes.insert(reference.key()) {
                    let mut vault_event = LogEvent::new(
                        operation_id,
                        LogLevel::Info,
                        LogEventType::VaultWrite,
                        "vault write succeeded",
                    )
                    .with_reference(reference.clone())
                    .with_action("vault_write_succeeded");
                    if let Some(kind) = kind {
                        vault_event = vault_event.with_kind(kind);
                    }
                    events.push(vault_event);
                }

                let mut redaction_event = LogEvent::new(
                    operation_id,
                    LogLevel::Info,
                    LogEventType::Redaction,
                    "replacement applied with tokenized reference",
                )
                .with_reference(reference)
                .with_action("tokenized");
                if let Some(kind) = kind {
                    redaction_event = redaction_event.with_kind(kind);
                }
                events.push(redaction_event);
            }
            ReplacementMode::Redacted => {
                let mut redaction_event = LogEvent::new(
                    operation_id,
                    LogLevel::Info,
                    LogEventType::Redaction,
                    "replacement applied with policy redaction",
                )
                .with_action("redacted");
                if let Some(kind) = kind {
                    redaction_event = redaction_event.with_kind(kind);
                }
                events.push(redaction_event);
            }
            ReplacementMode::RedactOnlyFallback => {
                let mut redaction_event = LogEvent::new(
                    operation_id,
                    LogLevel::Warn,
                    LogEventType::Redaction,
                    "replacement applied with redact-only fallback",
                )
                .with_action("fallback_redacted");
                if let Some(kind) = kind {
                    redaction_event = redaction_event.with_kind(kind);
                }
                events.push(redaction_event);
            }
        }
    }

    for failure in &plan.vault_failures {
        events.push(
            LogEvent::new(
                operation_id,
                LogLevel::Warn,
                LogEventType::VaultWriteFailed,
                "vault write failed; redact-only fallback used",
            )
            .with_kind(failure.kind)
            .with_action("vault_write_failed"),
        );
    }

    events
}

fn kind_for_replacement(
    replacement: &Replacement,
    decisions: &[PolicyDecision],
) -> Option<SensitiveType> {
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

fn preview(value: &str) -> String {
    let mut preview = value.chars().take(4).collect::<String>();
    if value.chars().count() > 4 {
        preview.push_str("...");
    }
    preview
}

fn valid_reference_id(id: &str) -> bool {
    if id.len() != 22 {
        return false;
    }

    bs58::decode(id)
        .into_vec()
        .map(|bytes| bytes.len() == 16)
        .unwrap_or(false)
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct RecordingVault {
        records: Mutex<Vec<VaultRecord>>,
    }

    impl RecordingVault {
        fn new() -> Self {
            Self {
                records: Mutex::new(Vec::new()),
            }
        }
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
                .find(|record| record.reference == *reference)
                .map(|record| record.value.clone()))
        }
    }

    struct FailingVault;

    impl VaultWriter for FailingVault {
        fn write(&self, _record: &VaultRecord) -> Result<(), VaultWriteError> {
            Err(VaultWriteError::new("vault unavailable"))
        }
    }

    impl VaultReader for FailingVault {
        fn read(&self, _reference: &Reference) -> Result<Option<String>, VaultReadError> {
            Err(VaultReadError::new("vault unavailable"))
        }
    }

    fn detection(kind: SensitiveType, value: &str, start: usize, end: usize) -> Detection {
        Detection {
            kind,
            value: value.to_string(),
            span: Span { start, end },
        }
    }

    #[test]
    fn generated_references_use_standard_format() {
        let reference = Reference::generate(SensitiveType::Email);

        assert_eq!(reference.kind, SensitiveType::Email);
        assert_eq!(reference.id.len(), 22);
        assert_eq!(reference.key().len(), "email:".len() + 22);
        assert!(reference.display().starts_with("[email:"));
        assert!(reference.display().ends_with(']'));
    }

    #[test]
    fn replacement_plan_saves_records_and_uses_references() {
        let vault = RecordingVault::new();
        let detections = [detection(SensitiveType::Email, "alice@example.com", 6, 23)];

        let plan = build_replacement_plan(&detections, &vault);

        assert_eq!(plan.tokenized_count(), 1);
        assert_eq!(plan.fallback_count(), 0);
        assert_eq!(plan.vault_failures.len(), 0);
        let records = vault.records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, "alice@example.com");
        assert_eq!(records[0].kind, SensitiveType::Email);
        assert!(plan.replacements[0].text.starts_with("[email:"));
    }

    #[test]
    fn replacement_plan_reuses_references_for_duplicate_values_by_default() {
        let vault = RecordingVault::new();
        let detections = [
            detection(SensitiveType::Email, "alice@example.com", 6, 23),
            detection(SensitiveType::Email, "alice@example.com", 28, 45),
        ];

        let plan = build_replacement_plan(&detections, &vault);

        assert_eq!(plan.tokenized_count(), 2);
        assert_eq!(plan.vault_write_count(), 1);
        assert_eq!(vault.records.lock().unwrap().len(), 1);
        assert_eq!(
            plan.replacements[0].reference,
            plan.replacements[1].reference
        );
        assert_eq!(plan.replacements[0].text, plan.replacements[1].text);
    }

    #[test]
    fn replacement_plan_can_disable_duplicate_value_reuse() {
        let vault = RecordingVault::new();
        let detections = [
            detection(SensitiveType::Email, "alice@example.com", 6, 23),
            detection(SensitiveType::Email, "alice@example.com", 28, 45),
        ];

        let plan = build_replacement_plan_with_options(
            &detections,
            &vault,
            ReplacementPlanOptions {
                deduplicate_replacements: false,
            },
        );

        assert_eq!(plan.tokenized_count(), 2);
        assert_eq!(plan.vault_write_count(), 2);
        assert_eq!(vault.records.lock().unwrap().len(), 2);
        assert_ne!(
            plan.replacements[0].reference,
            plan.replacements[1].reference
        );
        assert_ne!(plan.replacements[0].text, plan.replacements[1].text);
    }

    #[test]
    fn replacement_plan_deduplicates_vault_failures_for_duplicate_values() {
        let detections = [
            detection(SensitiveType::Email, "alice@example.com", 6, 23),
            detection(SensitiveType::Email, "alice@example.com", 28, 45),
        ];

        let plan = build_replacement_plan(&detections, &FailingVault);

        assert_eq!(plan.tokenized_count(), 0);
        assert_eq!(plan.fallback_count(), 2);
        assert_eq!(plan.vault_failures.len(), 1);
        assert_eq!(plan.replacements[0].text, "[email]");
        assert_eq!(plan.replacements[1].text, "[email]");
    }

    #[test]
    fn replacement_plan_uses_redact_only_fallback_on_vault_error() {
        let detections = [detection(SensitiveType::Email, "alice@example.com", 6, 23)];

        let plan = build_replacement_plan(&detections, &FailingVault);

        assert_eq!(plan.tokenized_count(), 0);
        assert_eq!(plan.fallback_count(), 1);
        assert_eq!(plan.replacements[0].text, "[email]");
        assert_eq!(plan.replacements[0].reference, None);
        assert_eq!(plan.vault_failures.len(), 1);
        assert_eq!(plan.vault_failures[0].value_preview, "alic...");
    }

    #[test]
    fn replacement_plan_redacts_without_vault_write_when_policy_says_redact() {
        let vault = RecordingVault::new();
        let decisions = [PolicyDecision::new(
            detection(SensitiveType::Email, "alice@example.com", 6, 23),
            PolicyAction::Redact,
        )];

        let plan = build_replacement_plan_from_decisions(&decisions, &vault);

        assert_eq!(plan.tokenized_count(), 0);
        assert_eq!(plan.redacted_count(), 1);
        assert_eq!(plan.replacements[0].text, "[email]");
        assert_eq!(vault.records.lock().unwrap().len(), 0);
    }

    #[test]
    fn replacement_plan_allows_without_replacement_or_vault_write() {
        let vault = RecordingVault::new();
        let decisions = [PolicyDecision::new(
            detection(SensitiveType::Email, "alice@example.com", 6, 23),
            PolicyAction::Allow,
        )];

        let plan = build_replacement_plan_from_decisions(&decisions, &vault);

        assert_eq!(plan.replacements.len(), 0);
        assert_eq!(plan.blocked_count(), 0);
        assert_eq!(vault.records.lock().unwrap().len(), 0);
    }

    #[test]
    fn replacement_plan_tracks_blocked_detections() {
        let vault = RecordingVault::new();
        let decisions = [PolicyDecision::new(
            detection(SensitiveType::Ssn, "123-45-6789", 6, 17),
            PolicyAction::Block,
        )];

        let plan = build_replacement_plan_from_decisions(&decisions, &vault);

        assert_eq!(plan.replacements.len(), 0);
        assert_eq!(plan.blocked_count(), 1);
        assert_eq!(plan.blocked[0].kind, SensitiveType::Ssn);
        assert_eq!(vault.records.lock().unwrap().len(), 0);
    }

    #[test]
    fn generated_operation_ids_use_standard_length() {
        assert_eq!(generate_operation_id().len(), 22);
    }

    #[test]
    fn filter_log_events_do_not_include_raw_values() {
        let detections = [detection(SensitiveType::Email, "alice@example.com", 6, 23)];
        let plan = build_replacement_plan(&detections, &RecordingVault::new());

        let events = build_filter_log_events("op-1", &detections, &plan);

        assert_eq!(events.len(), 4);
        assert!(
            events
                .iter()
                .any(|event| event.event_type == LogEventType::Detection)
        );
        assert!(
            events
                .iter()
                .any(|event| event.event_type == LogEventType::PolicyDecision)
        );
        assert!(
            events
                .iter()
                .any(|event| event.event_type == LogEventType::VaultWrite)
        );
        assert!(
            events
                .iter()
                .any(|event| event.event_type == LogEventType::Redaction)
        );

        for event in events {
            assert!(!event.message.contains("alice@example.com"));
            assert!(!event.operation_id.contains("alice@example.com"));
            assert!(
                !event
                    .action
                    .unwrap_or_default()
                    .contains("alice@example.com")
            );
        }
    }

    #[test]
    fn filter_log_events_log_deduplicated_vault_write_once() {
        let detections = [
            detection(SensitiveType::Email, "alice@example.com", 6, 23),
            detection(SensitiveType::Email, "alice@example.com", 28, 45),
        ];
        let plan = build_replacement_plan(&detections, &RecordingVault::new());

        let events = build_filter_log_events("op-1", &detections, &plan);

        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == LogEventType::VaultWrite)
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == LogEventType::Redaction)
                .count(),
            2
        );
    }

    #[test]
    fn reference_parse_round_trips_generated_reference() {
        let reference = Reference::generate(SensitiveType::Email);

        assert_eq!(
            Reference::parse_key(&reference.key()),
            Some(reference.clone())
        );
        assert_eq!(
            Reference::parse_display(&reference.display()),
            Some(reference)
        );
    }

    #[test]
    fn reference_parse_rejects_redact_only_and_malformed_values() {
        assert_eq!(Reference::parse_display("[email]"), None);
        assert_eq!(
            Reference::parse_display("[unknown:7B2HkqFn9xR4mWpD3nYvKt]"),
            None
        );
        assert_eq!(Reference::parse_display("[email:not-a-valid-id]"), None);
        assert_eq!(Reference::parse_key("email:short"), None);
    }

    #[test]
    fn find_references_ignores_malformed_and_redact_only_placeholders() {
        let reference = Reference::generate(SensitiveType::Email);
        let input = format!("a [email] b {} c [ssn:not-valid] d", reference.display());

        let matches = find_references(&input);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].reference, reference);
        assert_eq!(
            &input[matches[0].span.start..matches[0].span.end],
            reference.display()
        );
    }

    #[test]
    fn find_references_detects_token_nested_after_json_array_bracket() {
        let reference = Reference::generate(SensitiveType::Email);
        let input = format!(
            r#"{{"messages":[{{"content":"email {}"}}]}}"#,
            reference.display()
        );

        let matches = find_references(&input);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].reference, reference);
    }

    #[test]
    fn resolve_plan_restores_known_references_and_leaves_missing_unresolved() {
        let vault = RecordingVault::new();
        let known = Reference::generate(SensitiveType::Email);
        let missing = Reference::generate(SensitiveType::Ssn);
        vault
            .write(&VaultRecord {
                reference: known.clone(),
                kind: SensitiveType::Email,
                value: "alice@example.com".to_string(),
            })
            .unwrap();
        let input = format!("known {} missing {}", known.display(), missing.display());

        let plan = build_resolve_plan(&input, &vault);
        let output = apply_resolve_plan(&input, &plan);

        assert_eq!(plan.references.len(), 2);
        assert_eq!(plan.resolved_count(), 1);
        assert_eq!(plan.missing_count(), 1);
        assert_eq!(
            output,
            format!("known alice@example.com missing {}", missing.display())
        );
    }

    #[test]
    fn resolve_plan_records_read_failures_without_replacement() {
        let reference = Reference::generate(SensitiveType::Email);
        let input = format!("email {}", reference.display());

        let plan = build_resolve_plan(&input, &FailingVault);

        assert_eq!(plan.resolved_count(), 0);
        assert_eq!(plan.read_failure_count(), 1);
        assert!(plan.has_unresolved());
        assert_eq!(apply_resolve_plan(&input, &plan), input);
    }

    #[test]
    fn resolve_log_events_do_not_include_resolved_raw_values() {
        let vault = RecordingVault::new();
        let reference = Reference::generate(SensitiveType::Email);
        vault
            .write(&VaultRecord {
                reference: reference.clone(),
                kind: SensitiveType::Email,
                value: "alice@example.com".to_string(),
            })
            .unwrap();
        let plan = build_resolve_plan(&reference.display(), &vault);

        let events = build_resolve_log_events("op-1", &plan);

        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .any(|event| event.event_type == LogEventType::VaultRead)
        );
        assert!(
            events
                .iter()
                .any(|event| event.event_type == LogEventType::Resolve)
        );
        for event in events {
            assert!(!event.message.contains("alice@example.com"));
            assert!(
                !event
                    .action
                    .unwrap_or_default()
                    .contains("alice@example.com")
            );
        }
    }
}
