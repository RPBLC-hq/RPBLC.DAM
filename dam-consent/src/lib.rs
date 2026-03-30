pub mod store;

pub use store::{ConsentAction, ConsentRule, ConsentStore};

use dam_core::{DamError, FlowContext, Module, ModuleType, Verdict};
use std::sync::Arc;

/// Consent module — checks each detection against consent rules and sets its verdict.
///
/// Sits between detection modules and action modules in the pipeline.
/// For each detection, queries the consent store and sets:
/// - `Verdict::Pass` if a consent rule allows the data through
/// - `Verdict::Redact` if a rule denies it or no rule exists (for LLM destinations)
///
/// Default policy is destination-aware:
/// - LLM destinations: default deny (no rule = Redact)
/// - Non-LLM destinations: default allow (no rule = Pass, log-only)
pub struct ConsentModule {
    store: Arc<ConsentStore>,
}

impl ConsentModule {
    pub fn new(store: Arc<ConsentStore>) -> Self {
        Self { store }
    }
}

impl Module for ConsentModule {
    fn name(&self) -> &str {
        "consent"
    }

    fn module_type(&self) -> ModuleType {
        ModuleType::Action
    }

    /// Consent module runs on all traffic — it sets verdicts regardless of destination.
    fn matches(&self, _ctx: &FlowContext) -> bool {
        true
    }

    /// For each detection, check consent rules and set the verdict.
    /// Default: LLM destinations = deny (redact), non-LLM = allow (log-only).
    fn process(&self, ctx: &mut FlowContext) -> Result<(), DamError> {
        let destination = ctx.destination.host();
        let default_action = if ctx.destination.is_llm() {
            ConsentAction::Redact // LLM: default deny
        } else {
            ConsentAction::Pass // non-LLM: default allow (scan + log, don't redact)
        };

        for detection in &mut ctx.detections {
            // No token key yet — tokens are minted by the vault module AFTER consent.
            // Token-scoped rules only apply on the resolve/release path.
            let check = self.store.check_with_default(
                None,
                detection.data_type.tag(),
                destination,
                default_action,
            )?;

            detection.verdict = match check.action {
                ConsentAction::Pass => Verdict::Pass,
                ConsentAction::Redact => Verdict::Redact,
            };
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dam_core::{Destination, Detection, LlmProvider, SensitiveDataType, Span};

    fn temp_module() -> (ConsentModule, Arc<ConsentStore>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("consent_test.db");
        let store = Arc::new(ConsentStore::open(&db).unwrap());
        let module = ConsentModule::new(Arc::clone(&store));
        (module, store, dir)
    }

    fn make_detection(data_type: SensitiveDataType, value: &str) -> Detection {
        Detection {
            data_type,
            value: value.to_string(),
            span: Span {
                start: 0,
                end: value.len(),
            },
            confidence: 0.95,
            source_module: "test".to_string(),
            verdict: Verdict::Pending,
        }
    }

    #[test]
    fn test_module_name() {
        let (m, _, _dir) = temp_module();
        assert_eq!(m.name(), "consent");
    }

    #[test]
    fn test_default_deny_all() {
        let (m, _, _dir) = temp_module();
        let mut ctx = FlowContext::new(
            "test@example.com".into(),
            Destination::Llm {
                provider: LlmProvider::Anthropic,
            },
        );
        ctx.detections
            .push(make_detection(SensitiveDataType::Email, "test@example.com"));

        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections[0].verdict, Verdict::Redact);
    }

    #[test]
    fn test_type_level_pass() {
        let (m, store, _dir) = temp_module();
        store
            .grant(
                "email",
                None,
                "api.anthropic.com",
                ConsentAction::Pass,
                None,
            )
            .unwrap();

        let mut ctx = FlowContext::new(
            "test@example.com".into(),
            Destination::Llm {
                provider: LlmProvider::Anthropic,
            },
        );
        ctx.detections
            .push(make_detection(SensitiveDataType::Email, "test@example.com"));

        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections[0].verdict, Verdict::Pass);
    }

    #[test]
    fn test_mixed_verdicts() {
        let (m, store, _dir) = temp_module();
        // Allow emails to Anthropic, but not SSNs
        store
            .grant(
                "email",
                None,
                "api.anthropic.com",
                ConsentAction::Pass,
                None,
            )
            .unwrap();

        let mut ctx = FlowContext::new(
            "email and ssn".into(),
            Destination::Llm {
                provider: LlmProvider::Anthropic,
            },
        );
        ctx.detections
            .push(make_detection(SensitiveDataType::Email, "test@example.com"));
        ctx.detections
            .push(make_detection(SensitiveDataType::Ssn, "123-45-6789"));

        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections[0].verdict, Verdict::Pass); // email passes
        assert_eq!(ctx.detections[1].verdict, Verdict::Redact); // SSN redacted
    }

    #[test]
    fn test_no_detections() {
        let (m, _, _dir) = temp_module();
        let mut ctx = FlowContext::new(
            "clean text".into(),
            Destination::Other {
                host: "example.com".into(),
            },
        );
        m.process(&mut ctx).unwrap();
        assert!(ctx.detections.is_empty());
    }

    #[test]
    fn test_wildcard_destination() {
        let (m, store, _dir) = temp_module();
        store
            .grant("email", None, "*", ConsentAction::Pass, None)
            .unwrap();

        let mut ctx = FlowContext::new(
            "test".into(),
            Destination::Other {
                host: "any-host.com".into(),
            },
        );
        ctx.detections
            .push(make_detection(SensitiveDataType::Email, "test@example.com"));

        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections[0].verdict, Verdict::Pass);
    }

    #[test]
    fn test_always_matches() {
        let (m, _, _dir) = temp_module();
        let ctx = FlowContext::new(
            "x".into(),
            Destination::Other {
                host: "x.com".into(),
            },
        );
        assert!(m.matches(&ctx));
    }

    #[test]
    fn test_non_llm_default_allow() {
        let (m, _, _dir) = temp_module();
        let mut ctx = FlowContext::new(
            "test@example.com".into(),
            Destination::Other {
                host: "salesforce.com".into(),
            },
        );
        ctx.detections
            .push(make_detection(SensitiveDataType::Email, "test@example.com"));

        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections[0].verdict, Verdict::Pass);
    }

    #[test]
    fn test_non_llm_explicit_deny() {
        let (m, store, _dir) = temp_module();
        store
            .grant("email", None, "salesforce.com", ConsentAction::Redact, None)
            .unwrap();

        let mut ctx = FlowContext::new(
            "test@example.com".into(),
            Destination::Other {
                host: "salesforce.com".into(),
            },
        );
        ctx.detections
            .push(make_detection(SensitiveDataType::Email, "test@example.com"));

        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections[0].verdict, Verdict::Redact);
    }
}
