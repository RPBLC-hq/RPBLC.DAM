use dam_core::{DamError, Detection, FlowContext, Module, ModuleType, Verdict};
use dam_vault::VaultStore;
use dam_vault::token_mint::mint_token;
use std::sync::Arc;

/// Redaction module — replaces detected values with vault tokens in the request body.
///
/// Only processes detections with `Verdict::Redact`. Detections with `Verdict::Pass`
/// are left untouched in the body. All detections (pass AND redact) have already been
/// stored in the vault by the vault module before this runs.
///
/// Replaces from end to start to preserve byte offsets.
pub struct RedactModule {
    store: Arc<VaultStore>,
}

impl RedactModule {
    pub fn new(store: Arc<VaultStore>) -> Self {
        Self { store }
    }
}

impl Module for RedactModule {
    fn name(&self) -> &str {
        "redact"
    }

    fn module_type(&self) -> ModuleType {
        ModuleType::Action
    }

    /// Redact module runs on all traffic — verdict drives redaction, not destination.
    fn matches(&self, _ctx: &FlowContext) -> bool {
        true
    }

    fn process(&self, ctx: &mut FlowContext) -> Result<(), DamError> {
        // Only redact detections with Verdict::Redact
        let to_redact: Vec<&Detection> = ctx
            .detections
            .iter()
            .filter(|d| d.verdict == Verdict::Redact)
            .collect();

        if to_redact.is_empty() {
            return Ok(());
        }

        let mut body = ctx
            .modified_body
            .clone()
            .unwrap_or_else(|| ctx.request_body.clone());

        // Sort by span.start descending to replace from end to start
        let mut sorted: Vec<&Detection> = to_redact;
        sorted.sort_by(|a, b| b.span.start.cmp(&a.span.start));

        for detection in sorted {
            let token = mint_token(&self.store, detection.data_type, &detection.value)?;
            let token_str = token.display();

            let start = detection.span.start;
            let end = detection.span.end;

            if start <= body.len() && end <= body.len() && start <= end {
                body.replace_range(start..end, &token_str);
            }

            ctx.tokens_created.push(token);
        }

        ctx.modified_body = Some(body);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dam_core::{Destination, LlmProvider, SensitiveDataType, Span};
    use dam_vault::encrypt::generate_kek;

    fn make_store() -> (tempfile::TempDir, Arc<VaultStore>) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("redact_test.db");
        let kek = generate_kek();
        let store = Arc::new(VaultStore::open(&db, kek).unwrap());
        (dir, store)
    }

    fn llm_dest() -> Destination {
        Destination::Llm {
            provider: LlmProvider::Anthropic,
        }
    }

    fn other_dest() -> Destination {
        Destination::Other {
            host: "example.com".into(),
        }
    }

    fn make_detection(
        dt: SensitiveDataType,
        value: &str,
        start: usize,
        end: usize,
        verdict: Verdict,
    ) -> Detection {
        Detection {
            data_type: dt,
            value: value.to_string(),
            span: Span { start, end },
            confidence: 0.95,
            source_module: "test".into(),
            verdict,
        }
    }

    #[test]
    fn test_module_name() {
        let (_dir, store) = make_store();
        let m = RedactModule::new(store);
        assert_eq!(m.name(), "redact");
    }

    #[test]
    fn test_matches_all_traffic() {
        let (_dir, store) = make_store();
        let m = RedactModule::new(store);
        let ctx_llm = FlowContext::new("x".into(), llm_dest());
        let ctx_other = FlowContext::new("x".into(), other_dest());
        assert!(m.matches(&ctx_llm));
        assert!(m.matches(&ctx_other));
    }

    #[test]
    fn test_non_llm_pass_verdict_no_redaction() {
        let (_dir, store) = make_store();
        let m = RedactModule::new(store);
        let mut ctx = FlowContext::new("test@example.com".into(), other_dest());
        ctx.detections.push(make_detection(
            SensitiveDataType::Email,
            "test@example.com",
            0,
            16,
            Verdict::Pass,
        ));
        m.process(&mut ctx).unwrap();
        assert!(ctx.modified_body.is_none());
        assert!(ctx.tokens_created.is_empty());
    }

    #[test]
    fn test_non_llm_explicit_redact_verdict() {
        let (_dir, store) = make_store();
        let m = RedactModule::new(store);
        let mut ctx = FlowContext::new("test@example.com".into(), other_dest());
        ctx.detections.push(make_detection(
            SensitiveDataType::Email,
            "test@example.com",
            0,
            16,
            Verdict::Redact,
        ));
        m.process(&mut ctx).unwrap();
        let modified = ctx.modified_body.as_ref().unwrap();
        assert!(!modified.contains("test@example.com"));
        assert!(modified.contains("[email:"));
    }

    #[test]
    fn test_redact_only_redact_verdict() {
        let (_dir, store) = make_store();
        let m = RedactModule::new(store.clone());

        // "Email: alice@x.com Phone: +15551234567"
        //         ^          ^       ^            ^
        //         7         18      26           38
        let body = "Email: alice@x.com Phone: +15551234567";
        let mut ctx = FlowContext::new(body.into(), llm_dest());
        ctx.detections.push(make_detection(
            SensitiveDataType::Email,
            "alice@x.com",
            7,
            18,
            Verdict::Pass,
        ));
        ctx.detections.push(make_detection(
            SensitiveDataType::Phone,
            "+15551234567",
            26,
            38,
            Verdict::Redact,
        ));

        m.process(&mut ctx).unwrap();

        let modified = ctx.modified_body.as_ref().unwrap();
        // Email should still be in the body (Pass verdict)
        assert!(modified.contains("alice@x.com"));
        // Phone should be tokenized (Redact verdict)
        assert!(!modified.contains("+15551234567"));
        assert!(modified.contains("[phone:"));
        // Only one token created
        assert_eq!(ctx.tokens_created.len(), 1);
    }

    #[test]
    fn test_all_pass_no_modification() {
        let (_dir, store) = make_store();
        let m = RedactModule::new(store);

        let mut ctx = FlowContext::new("test@example.com".into(), llm_dest());
        ctx.detections.push(make_detection(
            SensitiveDataType::Email,
            "test@example.com",
            0,
            16,
            Verdict::Pass,
        ));

        m.process(&mut ctx).unwrap();
        assert!(ctx.modified_body.is_none()); // No modification
        assert!(ctx.tokens_created.is_empty());
    }

    #[test]
    fn test_all_redact() {
        let (_dir, store) = make_store();
        let m = RedactModule::new(store.clone());

        let body = "Email: test@x.com SSN: 123-45-6789";
        let mut ctx = FlowContext::new(body.into(), llm_dest());
        ctx.detections.push(make_detection(
            SensitiveDataType::Email,
            "test@x.com",
            7,
            17,
            Verdict::Redact,
        ));
        ctx.detections.push(make_detection(
            SensitiveDataType::Ssn,
            "123-45-6789",
            23,
            34,
            Verdict::Redact,
        ));

        m.process(&mut ctx).unwrap();

        let modified = ctx.modified_body.as_ref().unwrap();
        assert!(!modified.contains("test@x.com"));
        assert!(!modified.contains("123-45-6789"));
        assert!(modified.contains("[email:"));
        assert!(modified.contains("[ssn:"));
        assert_eq!(ctx.tokens_created.len(), 2);

        // Verify values stored in vault
        for token in &ctx.tokens_created {
            let val = store.retrieve(token).unwrap();
            assert!(!val.is_empty());
        }
    }

    #[test]
    fn test_no_detections() {
        let (_dir, store) = make_store();
        let m = RedactModule::new(store);
        let mut ctx = FlowContext::new("clean".into(), llm_dest());
        m.process(&mut ctx).unwrap();
        assert!(ctx.modified_body.is_none());
    }

    #[test]
    fn test_pending_verdict_not_redacted() {
        let (_dir, store) = make_store();
        let m = RedactModule::new(store);

        let mut ctx = FlowContext::new("test@example.com".into(), llm_dest());
        ctx.detections.push(make_detection(
            SensitiveDataType::Email,
            "test@example.com",
            0,
            16,
            Verdict::Pending,
        ));

        m.process(&mut ctx).unwrap();
        assert!(ctx.modified_body.is_none()); // Pending = not redacted
    }
}
