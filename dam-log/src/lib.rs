pub mod store;

pub use store::{LogEvent, LogStore, StatEntry};

use std::sync::Arc;

use dam_core::{DamError, FlowContext, Module, ModuleType};

/// Action module that logs every detection to a SQLite store.
///
/// Always matches (every request is logged). For each detection in the flow
/// context, records the data type, destination, action taken, source module,
/// and a truncated value preview (first 4 chars + "...").
pub struct LogModule {
    store: Arc<LogStore>,
}

impl LogModule {
    pub fn new(store: Arc<LogStore>) -> Self {
        Self { store }
    }

    /// Build a safe value preview: first 4 characters followed by "...".
    /// Never logs the full sensitive value.
    fn make_preview(value: &str) -> String {
        let prefix: String = value.chars().take(4).collect();
        format!("{prefix}...")
    }
}

impl Module for LogModule {
    fn name(&self) -> &str {
        "dam-log"
    }

    fn module_type(&self) -> ModuleType {
        ModuleType::Action
    }

    /// Always matches — log everything.
    fn matches(&self, _ctx: &FlowContext) -> bool {
        true
    }

    /// Log every detection in the context to the store.
    fn process(&self, ctx: &mut FlowContext) -> Result<(), DamError> {
        let destination = ctx.destination.host();
        let action = if ctx.destination.is_llm() {
            "tokenized"
        } else {
            "logged"
        };

        for detection in &ctx.detections {
            let data_type = detection.data_type.tag();
            let preview = Self::make_preview(&detection.value);
            self.store.log_event(
                data_type,
                destination,
                action,
                &detection.source_module,
                &preview,
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dam_core::{Destination, Detection, SensitiveDataType, Span};
    use std::sync::Arc;

    fn temp_log_module() -> (LogModule, Arc<LogStore>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test_log.db");
        let store = Arc::new(LogStore::open(&db_path).unwrap());
        let module = LogModule::new(Arc::clone(&store));
        (module, store, dir)
    }

    fn make_detection(data_type: SensitiveDataType, value: &str, module: &str) -> Detection {
        Detection {
            data_type,
            value: value.to_string(),
            span: Span { start: 0, end: value.len() },
            confidence: 0.95,
            source_module: module.to_string(),
                verdict: dam_core::Verdict::Pending,
        }
    }

    #[test]
    fn test_module_type_is_action() {
        let (module, _, _dir) = temp_log_module();
        assert_eq!(module.module_type(), ModuleType::Action);
    }

    #[test]
    fn test_module_name() {
        let (module, _, _dir) = temp_log_module();
        assert_eq!(module.name(), "dam-log");
    }

    #[test]
    fn test_always_matches() {
        let (module, _, _dir) = temp_log_module();
        let ctx = FlowContext::new(
            "hello".to_string(),
            Destination::Other { host: "example.com".to_string() },
        );
        assert!(module.matches(&ctx));

        let ctx_llm = FlowContext::new(
            "hello".to_string(),
            Destination::Llm {
                provider: dam_core::LlmProvider::Anthropic,
            },
        );
        assert!(module.matches(&ctx_llm));
    }

    #[test]
    fn test_process_no_detections() {
        let (module, store, _dir) = temp_log_module();
        let mut ctx = FlowContext::new(
            "hello world".to_string(),
            Destination::Other { host: "example.com".to_string() },
        );
        module.process(&mut ctx).unwrap();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn test_process_logs_detections() {
        let (module, store, _dir) = temp_log_module();
        let mut ctx = FlowContext::new(
            "my email is test@example.com".to_string(),
            Destination::Other { host: "example.com".to_string() },
        );
        ctx.detections.push(make_detection(
            SensitiveDataType::Email,
            "test@example.com",
            "detect-pii",
        ));

        module.process(&mut ctx).unwrap();
        assert_eq!(store.count().unwrap(), 1);

        let events = store.query_all(None).unwrap();
        assert_eq!(events[0].data_type, "email");
        assert_eq!(events[0].destination, "example.com");
        assert_eq!(events[0].action, "logged");
        assert_eq!(events[0].module_name, "detect-pii");
        assert_eq!(events[0].value_preview, "test...");
    }

    #[test]
    fn test_process_llm_destination_action_is_tokenized() {
        let (module, store, _dir) = temp_log_module();
        let mut ctx = FlowContext::new(
            "my email is test@example.com".to_string(),
            Destination::Llm {
                provider: dam_core::LlmProvider::OpenAI,
            },
        );
        ctx.detections.push(make_detection(
            SensitiveDataType::Email,
            "test@example.com",
            "detect-pii",
        ));

        module.process(&mut ctx).unwrap();
        let events = store.query_all(None).unwrap();
        assert_eq!(events[0].action, "tokenized");
        assert_eq!(events[0].destination, "api.openai.com");
    }

    #[test]
    fn test_process_multiple_detections() {
        let (module, store, _dir) = temp_log_module();
        let mut ctx = FlowContext::new(
            "email and phone".to_string(),
            Destination::Other { host: "target.com".to_string() },
        );
        ctx.detections.push(make_detection(
            SensitiveDataType::Email,
            "alice@example.com",
            "detect-pii",
        ));
        ctx.detections.push(make_detection(
            SensitiveDataType::Phone,
            "555-123-4567",
            "detect-pii",
        ));

        module.process(&mut ctx).unwrap();
        assert_eq!(store.count().unwrap(), 2);

        let events = store.query_all(None).unwrap();
        // Both logged to the same destination.
        assert!(events.iter().all(|e| e.destination == "target.com"));
    }

    #[test]
    fn test_preview_truncation() {
        assert_eq!(LogModule::make_preview("test@example.com"), "test...");
        assert_eq!(LogModule::make_preview("ab"), "ab...");
        assert_eq!(LogModule::make_preview(""), "...");
        assert_eq!(LogModule::make_preview("abcd"), "abcd...");
        assert_eq!(LogModule::make_preview("abcde"), "abcd...");
    }

    #[test]
    fn test_preview_unicode() {
        // Unicode characters should be treated as individual chars, not bytes.
        assert_eq!(LogModule::make_preview("\u{00e9}mail@test.com"), "\u{00e9}mai...");
    }

    #[test]
    fn test_process_does_not_modify_context() {
        let (module, _, _dir) = temp_log_module();
        let mut ctx = FlowContext::new(
            "original body".to_string(),
            Destination::Other { host: "example.com".to_string() },
        );
        ctx.detections.push(make_detection(
            SensitiveDataType::Email,
            "test@example.com",
            "detect-pii",
        ));

        module.process(&mut ctx).unwrap();

        // Log module should not modify the body or detections.
        assert_eq!(ctx.output_body(), "original body");
        assert!(ctx.modified_body.is_none());
        assert_eq!(ctx.detections.len(), 1);
    }

    #[test]
    fn test_process_various_data_types() {
        let (module, store, _dir) = temp_log_module();
        let mut ctx = FlowContext::new(
            "sensitive data".to_string(),
            Destination::Llm {
                provider: dam_core::LlmProvider::Anthropic,
            },
        );
        ctx.detections.push(make_detection(SensitiveDataType::Ssn, "123-45-6789", "mod-a"));
        ctx.detections.push(make_detection(SensitiveDataType::CreditCard, "4111111111111111", "mod-b"));
        ctx.detections.push(make_detection(SensitiveDataType::ApiKey, "sk-live-abc123def456", "mod-c"));

        module.process(&mut ctx).unwrap();
        assert_eq!(store.count().unwrap(), 3);

        let events = store.query_all(None).unwrap();
        let types: Vec<&str> = events.iter().map(|e| e.data_type.as_str()).collect();
        assert!(types.contains(&"ssn"));
        assert!(types.contains(&"cc"));
        assert!(types.contains(&"api_key"));

        // All actions should be "tokenized" for LLM destination.
        assert!(events.iter().all(|e| e.action == "tokenized"));
    }
}
