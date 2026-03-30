pub mod encrypt;
pub mod mcp;
pub mod store;
pub mod token_mint;

pub use encrypt::EnvelopeCrypto;
pub use store::VaultStore;

use crate::token_mint::mint_token;
use dam_core::{DamError, FlowContext, Module, ModuleType};
use std::sync::Arc;

/// The vault module — stores ALL detected sensitive values encrypted.
///
/// Stores every detection (both Pass and Redact verdicts) for audit and recovery.
/// Does NOT modify the request body — that's the redact module's job.
pub struct VaultModule {
    store: Arc<VaultStore>,
}

impl VaultModule {
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

    /// Vault runs on all traffic — stores everything for audit.
    fn matches(&self, _ctx: &FlowContext) -> bool {
        true
    }

    /// Store every detected value in the vault. Does not modify the body.
    fn process(&self, ctx: &mut FlowContext) -> Result<(), DamError> {
        for detection in &ctx.detections {
            let token = mint_token(&self.store, detection.data_type, &detection.value)?;
            ctx.tokens_created.push(token);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::generate_kek;
    use dam_core::{Destination, Detection, LlmProvider, SensitiveDataType, Span, Verdict};

    fn make_store() -> (tempfile::TempDir, Arc<VaultStore>) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("vault_module_test.db");
        let kek = generate_kek();
        let store = Arc::new(VaultStore::open(&db_path, kek).unwrap());
        (dir, store)
    }

    fn make_detection(dt: SensitiveDataType, value: &str) -> Detection {
        Detection {
            data_type: dt,
            value: value.to_string(),
            span: Span {
                start: 0,
                end: value.len(),
            },
            confidence: 0.95,
            source_module: "test".into(),
            verdict: Verdict::Pending,
        }
    }

    #[test]
    fn test_module_name_and_type() {
        let (_dir, store) = make_store();
        let m = VaultModule::new(store);
        assert_eq!(m.name(), "vault");
        assert_eq!(m.module_type(), ModuleType::Action);
    }

    #[test]
    fn test_matches_all_traffic() {
        let (_dir, store) = make_store();
        let m = VaultModule::new(store);
        let llm = FlowContext::new(
            "x".into(),
            Destination::Llm {
                provider: LlmProvider::Anthropic,
            },
        );
        let other = FlowContext::new(
            "x".into(),
            Destination::Other {
                host: "example.com".into(),
            },
        );
        assert!(m.matches(&llm));
        assert!(m.matches(&other)); // vault stores everything now
    }

    #[test]
    fn test_stores_all_detections() {
        let (_dir, store) = make_store();
        let m = VaultModule::new(store.clone());

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

        // Both stored in vault
        assert_eq!(ctx.tokens_created.len(), 2);
        assert_eq!(store.count().unwrap(), 2);

        // Retrievable
        for token in &ctx.tokens_created {
            let val = store.retrieve(token).unwrap();
            assert!(!val.is_empty());
        }
    }

    #[test]
    fn test_does_not_modify_body() {
        let (_dir, store) = make_store();
        let m = VaultModule::new(store);

        let mut ctx = FlowContext::new(
            "test@example.com".into(),
            Destination::Llm {
                provider: LlmProvider::Anthropic,
            },
        );
        ctx.detections
            .push(make_detection(SensitiveDataType::Email, "test@example.com"));

        m.process(&mut ctx).unwrap();

        // Vault no longer modifies the body — that's redact's job
        assert!(ctx.modified_body.is_none());
        assert_eq!(ctx.output_body(), "test@example.com");
    }

    #[test]
    fn test_dedup_same_value() {
        let (_dir, store) = make_store();
        let m = VaultModule::new(store.clone());

        let mut ctx = FlowContext::new(
            "x".into(),
            Destination::Other {
                host: "example.com".into(),
            },
        );
        ctx.detections
            .push(make_detection(SensitiveDataType::Email, "alice@x.com"));
        ctx.detections
            .push(make_detection(SensitiveDataType::Email, "alice@x.com"));

        m.process(&mut ctx).unwrap();

        assert_eq!(ctx.tokens_created.len(), 2);
        assert_eq!(ctx.tokens_created[0].key(), ctx.tokens_created[1].key()); // same token (dedup)
        assert_eq!(store.count().unwrap(), 1); // only one entry
    }

    #[test]
    fn test_no_detections() {
        let (_dir, store) = make_store();
        let m = VaultModule::new(store);

        let mut ctx = FlowContext::new(
            "clean".into(),
            Destination::Other {
                host: "x.com".into(),
            },
        );
        m.process(&mut ctx).unwrap();

        assert!(ctx.tokens_created.is_empty());
    }
}
