pub mod encrypt;
pub mod mcp;
pub mod store;
pub mod token_mint;

pub use encrypt::EnvelopeCrypto;
pub use store::VaultStore;

use crate::token_mint::mint_token;
use dam_core::{DamError, Detection, FlowContext, Module, ModuleType};
use std::sync::Arc;

/// The vault module — an action module that tokenizes detected PII.
///
/// For each detection in the flow context, the vault:
/// 1. Stores the sensitive value encrypted in the vault.
/// 2. Replaces the original span in the request body with a typed token.
///
/// Detections are processed from end to start to preserve byte offsets.
pub struct VaultModule {
    store: Arc<VaultStore>,
}

impl VaultModule {
    /// Create a new vault module backed by the given store.
    pub fn new(store: Arc<VaultStore>) -> Self {
        Self { store }
    }
}

impl Module for VaultModule {
    fn name(&self) -> &str {
        "vault"
    }

    fn module_type(&self) -> ModuleType {
        ModuleType::Action
    }

    /// The vault module activates only for LLM destinations.
    fn matches(&self, ctx: &FlowContext) -> bool {
        ctx.destination.is_llm()
    }

    /// Process all detections: store each in the vault and build a modified
    /// body with tokens replacing the original sensitive spans.
    fn process(&self, ctx: &mut FlowContext) -> Result<(), DamError> {
        if ctx.detections.is_empty() {
            return Ok(());
        }

        // Start from the current body (or the original if no prior modification)
        let mut body = ctx
            .modified_body
            .clone()
            .unwrap_or_else(|| ctx.request_body.clone());

        // Sort detections by span.start descending so we can replace from
        // end to start without invalidating earlier offsets.
        let mut sorted_detections: Vec<&Detection> = ctx.detections.iter().collect();
        sorted_detections.sort_by(|a, b| b.span.start.cmp(&a.span.start));

        for detection in sorted_detections {
            let token = mint_token(&self.store, detection.data_type, &detection.value)?;
            let token_str = token.display();

            // Replace the span in the body
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
    use crate::encrypt::generate_kek;
    use dam_core::{Destination, LlmProvider, SensitiveDataType, Span};

    fn make_store() -> (tempfile::TempDir, Arc<VaultStore>) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("vault_module_test.db");
        let kek = generate_kek();
        let store = Arc::new(VaultStore::open(&db_path, kek).unwrap());
        (dir, store)
    }

    fn llm_destination() -> Destination {
        Destination::Llm {
            provider: LlmProvider::Anthropic,
        }
    }

    fn non_llm_destination() -> Destination {
        Destination::Other {
            host: "example.com".into(),
        }
    }

    fn make_detection(
        data_type: SensitiveDataType,
        value: &str,
        start: usize,
        end: usize,
    ) -> Detection {
        Detection {
            data_type,
            value: value.to_string(),
            span: Span { start, end },
            confidence: 0.95,
            source_module: "test".to_string(),
        }
    }

    #[test]
    fn test_module_type() {
        let (_dir, store) = make_store();
        let module = VaultModule::new(store);
        assert_eq!(module.module_type(), ModuleType::Action);
    }

    #[test]
    fn test_module_name() {
        let (_dir, store) = make_store();
        let module = VaultModule::new(store);
        assert_eq!(module.name(), "vault");
    }

    #[test]
    fn test_matches_llm_destination() {
        let (_dir, store) = make_store();
        let module = VaultModule::new(store);

        let ctx = FlowContext::new("test".into(), llm_destination());
        assert!(module.matches(&ctx));
    }

    #[test]
    fn test_does_not_match_non_llm() {
        let (_dir, store) = make_store();
        let module = VaultModule::new(store);

        let ctx = FlowContext::new("test".into(), non_llm_destination());
        assert!(!module.matches(&ctx));
    }

    #[test]
    fn test_process_no_detections() {
        let (_dir, store) = make_store();
        let module = VaultModule::new(store);

        let mut ctx = FlowContext::new("hello world".into(), llm_destination());
        module.process(&mut ctx).unwrap();

        assert!(ctx.modified_body.is_none());
        assert!(ctx.tokens_created.is_empty());
    }

    #[test]
    fn test_process_single_detection() {
        let (_dir, store) = make_store();
        let module = VaultModule::new(store.clone());

        // "Hello alice@example.com, welcome!"
        //        ^                ^
        //        6               23
        let body = "Hello alice@example.com, welcome!";
        let mut ctx = FlowContext::new(body.into(), llm_destination());
        ctx.detections.push(make_detection(
            SensitiveDataType::Email,
            "alice@example.com",
            6,
            23,
        ));

        module.process(&mut ctx).unwrap();

        let modified = ctx.modified_body.as_ref().unwrap();
        assert!(!modified.contains("alice@example.com"));
        assert!(modified.contains("[email:"));
        assert!(modified.starts_with("Hello "));
        assert!(modified.ends_with(", welcome!"));
        assert_eq!(ctx.tokens_created.len(), 1);
        assert_eq!(ctx.tokens_created[0].data_type, SensitiveDataType::Email);

        // Verify we can retrieve the original value
        let retrieved = store.retrieve(&ctx.tokens_created[0]).unwrap();
        assert_eq!(retrieved, "alice@example.com");
    }

    #[test]
    fn test_process_multiple_detections() {
        let (_dir, store) = make_store();
        let module = VaultModule::new(store.clone());

        // "Email: alice@x.com Phone: +15551234567"
        //         ^         ^         ^          ^
        //         7        18        26         38
        let body = "Email: alice@x.com Phone: +15551234567";
        let mut ctx = FlowContext::new(body.into(), llm_destination());
        ctx.detections.push(make_detection(
            SensitiveDataType::Email,
            "alice@x.com",
            7,
            18,
        ));
        ctx.detections.push(make_detection(
            SensitiveDataType::Phone,
            "+15551234567",
            26,
            38,
        ));

        module.process(&mut ctx).unwrap();

        let modified = ctx.modified_body.as_ref().unwrap();
        assert!(!modified.contains("alice@x.com"));
        assert!(!modified.contains("+15551234567"));
        assert!(modified.contains("[email:"));
        assert!(modified.contains("[phone:"));
        assert_eq!(ctx.tokens_created.len(), 2);

        // Verify retrieval
        for token in &ctx.tokens_created {
            let val = store.retrieve(token).unwrap();
            assert!(!val.is_empty());
        }
    }

    #[test]
    fn test_process_dedup_same_value() {
        let (_dir, store) = make_store();
        let module = VaultModule::new(store.clone());

        // Same email appears twice
        // "From: alice@x.com To: alice@x.com"
        //        ^          ^     ^          ^
        //        6         17    22         33
        let body = "From: alice@x.com To: alice@x.com";
        let mut ctx = FlowContext::new(body.into(), llm_destination());
        ctx.detections.push(make_detection(
            SensitiveDataType::Email,
            "alice@x.com",
            6,
            17,
        ));
        ctx.detections.push(make_detection(
            SensitiveDataType::Email,
            "alice@x.com",
            22,
            33,
        ));

        module.process(&mut ctx).unwrap();

        // Both tokens should have the same key (dedup)
        assert_eq!(ctx.tokens_created.len(), 2);
        assert_eq!(ctx.tokens_created[0].key(), ctx.tokens_created[1].key());

        // Only one entry in the vault
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn test_process_preserves_surrounding_text() {
        let (_dir, store) = make_store();
        let module = VaultModule::new(store);

        let body = "prefix-SECRET-suffix";
        let mut ctx = FlowContext::new(body.into(), llm_destination());
        ctx.detections.push(make_detection(
            SensitiveDataType::ApiKey,
            "SECRET",
            7,
            13,
        ));

        module.process(&mut ctx).unwrap();

        let modified = ctx.modified_body.as_ref().unwrap();
        assert!(modified.starts_with("prefix-"));
        assert!(modified.ends_with("-suffix"));
    }

    #[test]
    fn test_process_at_boundaries() {
        let (_dir, store) = make_store();
        let module = VaultModule::new(store);

        // Detection at the very start
        let body = "SECRET rest of text";
        let mut ctx = FlowContext::new(body.into(), llm_destination());
        ctx.detections.push(make_detection(
            SensitiveDataType::ApiKey,
            "SECRET",
            0,
            6,
        ));

        module.process(&mut ctx).unwrap();

        let modified = ctx.modified_body.as_ref().unwrap();
        assert!(modified.starts_with("[api_key:"));
        assert!(modified.ends_with(" rest of text"));
    }

    #[test]
    fn test_process_detection_at_end() {
        let (_dir, store) = make_store();
        let module = VaultModule::new(store);

        let body = "text ends with SECRET";
        let mut ctx = FlowContext::new(body.into(), llm_destination());
        ctx.detections.push(make_detection(
            SensitiveDataType::ApiKey,
            "SECRET",
            15,
            21,
        ));

        module.process(&mut ctx).unwrap();

        let modified = ctx.modified_body.as_ref().unwrap();
        assert!(modified.starts_with("text ends with "));
        assert!(modified.contains("[api_key:"));
    }
}
