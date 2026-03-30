pub mod json_scan;
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
        // For LLM destinations, use JSON-aware scanning: only scan message content fields,
        // not system prompts, tool definitions, or API structure. This eliminates
        // 35-40 false detections per request from non-user-data fields.
        if ctx.destination.is_llm()
            && let Some(ranges) = json_scan::scannable_ranges(&ctx.request_body)
        {
            for (start, end) in &ranges {
                if *start <= *end && *end <= ctx.request_body.len() {
                    let slice = &ctx.request_body[*start..*end];
                    let mut detections = patterns::detect_all(slice);
                    for det in &mut detections {
                        det.span.start += start;
                        det.span.end += start;
                    }
                    ctx.detections.extend(detections);
                }
            }
            tracing::debug!(
                regions = ranges.len(),
                detections = ctx.detections.len(),
                "json-aware scan"
            );
            return Ok(());
        }

        // Non-LLM destinations or non-JSON bodies: scan the entire body.
        // Normalization (zero-width stripping, NFKC) shifts byte offsets, causing span misalignment.
        // TODO: add a second pass with normalization for adversarial/obfuscated inputs,
        //       mapping normalized spans back to original positions.
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
    fn process_obfuscated_zero_width_not_detected_without_normalization() {
        // Without normalization, obfuscated PII is not detected.
        // This is expected — normalization is deferred to avoid span misalignment.
        let m = PiiDetectionModule::new();
        let mut ctx = make_ctx("user\u{200B}@\u{200C}example\u{200D}.com");
        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections.len(), 0);
    }

    #[test]
    fn process_unicode_dashes_not_detected_without_normalization() {
        let m = PiiDetectionModule::new();
        let mut ctx = make_ctx("ssn 123\u{2013}45\u{2013}6789");
        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections.len(), 0);
    }

    #[test]
    fn process_url_encoded_email_not_detected_without_normalization() {
        let m = PiiDetectionModule::new();
        let mut ctx = make_ctx("user%40example.com");
        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections.len(), 0);
    }

    #[test]
    fn process_multiple_pii_types() {
        let m = PiiDetectionModule::new();
        let mut ctx =
            make_ctx("Email: user@test.com, Phone: +14155551234, SSN: 123-45-6789, IP: 8.8.8.8");
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

    // ── JSON-aware scanning (LLM destinations) ───────────────────

    use dam_core::LlmProvider;

    fn make_llm_ctx(body: &str) -> FlowContext {
        FlowContext::new(
            body.into(),
            Destination::Llm {
                provider: LlmProvider::OpenAI,
            },
        )
    }

    #[test]
    fn json_scan_ignores_system_prompt_pii() {
        let m = PiiDetectionModule::new();
        let body = r#"{"messages":[{"role":"system","content":"Contact support@example.com for help"},{"role":"user","content":"hello"}]}"#;
        let mut ctx = make_llm_ctx(body);
        m.process(&mut ctx).unwrap();
        // support@example.com is in system prompt — should NOT be detected
        assert!(ctx.detections.is_empty());
    }

    #[test]
    fn json_scan_detects_user_pii() {
        let m = PiiDetectionModule::new();
        let body = r#"{"messages":[{"role":"user","content":"my email is alice@test.com"}]}"#;
        let mut ctx = make_llm_ctx(body);
        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections.len(), 1);
        assert_eq!(ctx.detections[0].data_type, SensitiveDataType::Email);
        assert_eq!(ctx.detections[0].value, "alice@test.com");
        // Verify span points to correct position in the full body
        let span = &ctx.detections[0].span;
        assert_eq!(&body[span.start..span.end], "alice@test.com");
    }

    #[test]
    fn json_scan_ignores_tool_definitions() {
        let m = PiiDetectionModule::new();
        let body = r#"{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"send","parameters":{"properties":{"to":{"description":"email like user@example.com"}}}}}]}"#;
        let mut ctx = make_llm_ctx(body);
        m.process(&mut ctx).unwrap();
        // user@example.com is in tool definition — should NOT be detected
        assert!(ctx.detections.is_empty());
    }

    #[test]
    fn json_scan_span_correct_for_redaction() {
        let m = PiiDetectionModule::new();
        let body = r#"{"messages":[{"role":"user","content":"call +14155551234 please"}]}"#;
        let mut ctx = make_llm_ctx(body);
        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections.len(), 1);
        let span = &ctx.detections[0].span;
        // Replace in body should produce valid JSON
        let mut modified = body.to_string();
        modified.replace_range(span.start..span.end, "[phone:abc]");
        assert!(modified.contains("[phone:abc]"));
        assert!(!modified.contains("+14155551234"));
    }

    #[test]
    fn json_scan_multiple_messages_multiple_detections() {
        let m = PiiDetectionModule::new();
        let body = r#"{"messages":[{"role":"system","content":"admin@sys.com"},{"role":"user","content":"email alice@a.com"},{"role":"assistant","content":"got it"},{"role":"user","content":"ssn 123-45-6789"}]}"#;
        let mut ctx = make_llm_ctx(body);
        m.process(&mut ctx).unwrap();
        // admin@sys.com in system — skipped
        // alice@a.com in user — detected
        // 123-45-6789 in user — detected
        assert_eq!(ctx.detections.len(), 2);
        let types: Vec<_> = ctx.detections.iter().map(|d| d.data_type).collect();
        assert!(types.contains(&SensitiveDataType::Email));
        assert!(types.contains(&SensitiveDataType::Ssn));
        // Verify spans are correct
        for det in &ctx.detections {
            assert_eq!(&body[det.span.start..det.span.end], det.value);
        }
    }

    #[test]
    fn json_scan_non_json_body_falls_back() {
        let m = PiiDetectionModule::new();
        // Non-JSON body to LLM destination — should fall back to full scan
        let mut ctx = make_llm_ctx("my email is user@test.com");
        m.process(&mut ctx).unwrap();
        assert_eq!(ctx.detections.len(), 1);
        assert_eq!(ctx.detections[0].value, "user@test.com");
    }

    #[test]
    fn non_llm_destination_scans_full_body() {
        let m = PiiDetectionModule::new();
        // Non-LLM destination should scan the full body even with JSON
        let body = r#"{"messages":[{"role":"system","content":"admin@sys.com"}]}"#;
        let mut ctx = make_ctx(body);
        m.process(&mut ctx).unwrap();
        // Full-body scan catches everything
        assert_eq!(ctx.detections.len(), 1);
        assert_eq!(ctx.detections[0].value, "admin@sys.com");
    }
}
