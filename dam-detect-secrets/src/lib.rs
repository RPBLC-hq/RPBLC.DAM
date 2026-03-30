pub mod patterns;

use dam_core::{DamError, FlowContext, Module, ModuleType};

pub struct SecretsDetectionModule;

impl SecretsDetectionModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SecretsDetectionModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for SecretsDetectionModule {
    fn name(&self) -> &str {
        "detect-secrets"
    }

    fn module_type(&self) -> ModuleType {
        ModuleType::Detection
    }

    fn matches(&self, _ctx: &FlowContext) -> bool {
        true
    }

    fn process(&self, ctx: &mut FlowContext) -> Result<(), DamError> {
        let detections = patterns::detect_all(&ctx.request_body);
        ctx.detections.extend(detections);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dam_core::{Destination, SensitiveDataType};

    fn make_ctx(body: &str) -> FlowContext {
        FlowContext::new(
            body.to_string(),
            Destination::Other {
                host: "example.com".into(),
            },
        )
    }

    #[test]
    fn test_module_name() {
        let m = SecretsDetectionModule::new();
        assert_eq!(m.name(), "detect-secrets");
    }

    #[test]
    fn test_module_type_is_detection() {
        let m = SecretsDetectionModule::new();
        assert_eq!(m.module_type(), ModuleType::Detection);
    }

    #[test]
    fn test_module_always_matches() {
        let m = SecretsDetectionModule::new();
        let ctx = make_ctx("anything");
        assert!(m.matches(&ctx));
    }

    #[test]
    fn test_process_empty_body() {
        let m = SecretsDetectionModule::new();
        let mut ctx = make_ctx("");
        m.process(&mut ctx).unwrap();
        assert!(ctx.detections.is_empty());
    }

    #[test]
    fn test_process_no_secrets() {
        let m = SecretsDetectionModule::new();
        let mut ctx = make_ctx("Just a normal message with no secrets at all.");
        m.process(&mut ctx).unwrap();
        assert!(ctx.detections.is_empty());
    }

    #[test]
    fn test_process_detects_aws_key() {
        let m = SecretsDetectionModule::new();
        let mut ctx = make_ctx("My key is AKIAIOSFODNN7EXAMPLE here");
        m.process(&mut ctx).unwrap();
        assert!(!ctx.detections.is_empty());
        assert!(
            ctx.detections
                .iter()
                .any(|d| d.data_type == SensitiveDataType::AwsKey)
        );
    }

    #[test]
    fn test_process_detects_multiple_secrets() {
        let m = SecretsDetectionModule::new();
        let body = "aws=AKIAIOSFODNN7EXAMPLE stripe=sk_live_abcdefghijklmnopqrstuvwx";
        let mut ctx = make_ctx(body);
        m.process(&mut ctx).unwrap();
        let types: Vec<_> = ctx.detections.iter().map(|d| d.data_type).collect();
        assert!(types.contains(&SensitiveDataType::AwsKey));
        assert!(types.contains(&SensitiveDataType::StripeKey));
    }

    #[test]
    fn test_process_appends_to_existing_detections() {
        let m = SecretsDetectionModule::new();
        let mut ctx = make_ctx("AKIAIOSFODNN7EXAMPLE");
        // Pre-populate with one detection
        ctx.detections.push(dam_core::Detection {
            data_type: SensitiveDataType::Email,
            value: "test@example.com".into(),
            span: dam_core::Span {
                start: 100,
                end: 116,
            },
            confidence: 0.99,
            source_module: "detect-pii".into(),
            verdict: dam_core::Verdict::Pending,
        });
        m.process(&mut ctx).unwrap();
        assert!(ctx.detections.len() >= 2);
    }

    #[test]
    fn test_process_does_not_modify_body() {
        let m = SecretsDetectionModule::new();
        let mut ctx = make_ctx("AKIAIOSFODNN7EXAMPLE");
        m.process(&mut ctx).unwrap();
        assert!(ctx.modified_body.is_none());
        assert_eq!(ctx.output_body(), "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn test_default_impl() {
        let m = SecretsDetectionModule::default();
        assert_eq!(m.name(), "detect-secrets");
    }

    #[test]
    fn test_source_module_matches_name() {
        let m = SecretsDetectionModule::new();
        let mut ctx = make_ctx("AKIAIOSFODNN7EXAMPLE");
        m.process(&mut ctx).unwrap();
        for d in &ctx.detections {
            assert_eq!(d.source_module, m.name());
        }
    }
}
