pub mod normalize;
pub mod patterns;
pub mod validators;

use dam_core::{DamError, FlowContext, Module, ModuleType};

/// PII detection module — scans request bodies for personally identifiable information.
///
/// Normalizes text (zero-width stripping, NFKC, dash normalization, URL-decoding),
/// then runs regex patterns with validation (Luhn, Mod97, SSN area, phone length,
/// private IP rejection) and appends results to the flow context.
pub struct PiiDetectionModule;

impl PiiDetectionModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PiiDetectionModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for PiiDetectionModule {
    fn name(&self) -> &str {
        "detect-pii"
    }

    fn module_type(&self) -> ModuleType {
        ModuleType::Detection
    }

    fn matches(&self, _ctx: &FlowContext) -> bool {
        true // PII detection always runs
    }

    fn process(&self, ctx: &mut FlowContext) -> Result<(), DamError> {
        let normalized = normalize::normalize(&ctx.request_body);
        let detections = patterns::detect_all(&normalized);
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
            body.into(),
            Destination::Other {
                host: "example.com".into(),
            },
        )
    }

    #[test]
    fn module_name() {
        let m = PiiDetectionModule::new();
        assert_eq!(m.name(), "detect-pii");
    }

    #[test]
    fn module_type_is_detection() {
        let m = PiiDetectionModule::new();
        assert_eq!(m.module_type(), ModuleType::Detection);
    }

    #[test]
    fn module_matches_always() {
        let m = PiiDetectionModule::new();
        let ctx = make_ctx("anything");
        assert!(m.matches(&ctx));
    }

    #[test]
    fn process_detects_email() {
        let m = PiiDetectionModule::new();
        let mut ctx = make_ctx("send to user@example.com please");
        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections.len(), 1);
        assert_eq!(ctx.detections[0].data_type, SensitiveDataType::Email);
        assert_eq!(ctx.detections[0].value, "user@example.com");
    }

    #[test]
    fn process_detects_phone() {
        let m = PiiDetectionModule::new();
        let mut ctx = make_ctx("call +14155551234");
        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections.len(), 1);
        assert_eq!(ctx.detections[0].data_type, SensitiveDataType::Phone);
    }

    #[test]
    fn process_detects_ssn() {
        let m = PiiDetectionModule::new();
        let mut ctx = make_ctx("ssn 123-45-6789");
        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections.len(), 1);
        assert_eq!(ctx.detections[0].data_type, SensitiveDataType::Ssn);
    }

    #[test]
    fn process_detects_credit_card() {
        let m = PiiDetectionModule::new();
        let mut ctx = make_ctx("card 4111111111111111");
        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections.len(), 1);
        assert_eq!(ctx.detections[0].data_type, SensitiveDataType::CreditCard);
    }

    #[test]
    fn process_detects_ip() {
        let m = PiiDetectionModule::new();
        let mut ctx = make_ctx("from 203.0.113.42");
        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections.len(), 1);
        assert_eq!(ctx.detections[0].data_type, SensitiveDataType::IpAddress);
    }

    #[test]
    fn process_skips_private_ip() {
        let m = PiiDetectionModule::new();
        let mut ctx = make_ctx("internal 10.0.0.1 server");
        m.process(&mut ctx).unwrap();
        assert!(ctx.detections.is_empty());
    }

    #[test]
    fn process_empty_body() {
        let m = PiiDetectionModule::new();
        let mut ctx = make_ctx("");
        m.process(&mut ctx).unwrap();
        assert!(ctx.detections.is_empty());
    }

    #[test]
    fn process_no_pii() {
        let m = PiiDetectionModule::new();
        let mut ctx = make_ctx("just a regular sentence with no personal data");
        m.process(&mut ctx).unwrap();
        assert!(ctx.detections.is_empty());
    }

    #[test]
    fn process_normalizes_zero_width_before_detection() {
        let m = PiiDetectionModule::new();
        // Zero-width chars injected into email
        let mut ctx = make_ctx("user\u{200B}@\u{200C}example\u{200D}.com");
        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections.len(), 1);
        assert_eq!(ctx.detections[0].data_type, SensitiveDataType::Email);
    }

    #[test]
    fn process_normalizes_unicode_dashes_for_ssn() {
        let m = PiiDetectionModule::new();
        // SSN with en-dashes instead of hyphens
        let mut ctx = make_ctx("ssn 123\u{2013}45\u{2013}6789");
        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections.len(), 1);
        assert_eq!(ctx.detections[0].data_type, SensitiveDataType::Ssn);
    }

    #[test]
    fn process_normalizes_url_encoded_email() {
        let m = PiiDetectionModule::new();
        let mut ctx = make_ctx("user%40example.com");
        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections.len(), 1);
        assert_eq!(ctx.detections[0].data_type, SensitiveDataType::Email);
    }

    #[test]
    fn process_multiple_pii_types() {
        let m = PiiDetectionModule::new();
        let mut ctx = make_ctx(
            "Email: user@test.com, Phone: +14155551234, SSN: 123-45-6789, IP: 8.8.8.8",
        );
        m.process(&mut ctx).unwrap();

        let types: Vec<_> = ctx.detections.iter().map(|d| d.data_type).collect();
        assert!(types.contains(&SensitiveDataType::Email));
        assert!(types.contains(&SensitiveDataType::Phone));
        assert!(types.contains(&SensitiveDataType::Ssn));
        assert!(types.contains(&SensitiveDataType::IpAddress));
    }

    #[test]
    fn default_impl() {
        let m = PiiDetectionModule::default();
        assert_eq!(m.name(), "detect-pii");
    }
}
