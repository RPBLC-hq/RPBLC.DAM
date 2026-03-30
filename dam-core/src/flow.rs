use crate::error::DamError;
use crate::module_trait::{FlowContext, Module, ModuleType, Verdict};
use std::sync::Arc;

/// Executes a chain of modules on a FlowContext.
pub struct FlowExecutor {
    modules: Vec<Arc<dyn Module>>,
}

impl FlowExecutor {
    pub fn new(modules: Vec<Arc<dyn Module>>) -> Self {
        Self { modules }
    }

    /// Run the full module flow:
    /// 1. Run all detection modules (populate detections)
    /// 2. Deduplicate overlapping detections
    /// 3. Run all action modules (tokenize, log, etc.)
    pub fn run(&self, ctx: &mut FlowContext) -> Result<(), DamError> {
        // Phase 1: Detection modules
        for module in &self.modules {
            if module.module_type() != ModuleType::Detection {
                continue;
            }
            if !module.matches(ctx) {
                continue;
            }
            if let Err(e) = module.process(ctx) {
                tracing::warn!(module = module.name(), error = %e, "detection module failed, continuing");
            }
        }

        // Phase 2: Deduplicate
        ctx.dedup_detections();

        // Phase 3: Action modules
        for module in &self.modules {
            if module.module_type() != ModuleType::Action {
                continue;
            }
            if !module.matches(ctx) {
                continue;
            }
            if let Err(e) = module.process(ctx) {
                let name = module.name();
                let is_safety_critical = name == "consent" || name == "redact";
                if is_safety_critical {
                    // Fail-closed: force all pending detections to Redact.
                    // A consent/redact failure must not allow sensitive data through.
                    tracing::error!(
                        module = name,
                        error = %e,
                        "safety-critical action module failed — forcing pending detections to Redact"
                    );
                    for detection in &mut ctx.detections {
                        if detection.verdict == Verdict::Pending {
                            detection.verdict = Verdict::Redact;
                        }
                    }
                } else {
                    // Fail-open for non-critical action modules (vault, log)
                    tracing::warn!(module = name, error = %e, "action module failed, continuing");
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::Destination;
    use crate::module_trait::{Detection, Span};
    use crate::types::SensitiveDataType;

    /// A mock detection module that always adds a fixed detection.
    struct MockDetector {
        name: &'static str,
        detection: Option<Detection>,
        should_match: bool,
    }

    impl Module for MockDetector {
        fn name(&self) -> &str {
            self.name
        }
        fn module_type(&self) -> ModuleType {
            ModuleType::Detection
        }
        fn matches(&self, _ctx: &FlowContext) -> bool {
            self.should_match
        }
        fn process(&self, ctx: &mut FlowContext) -> Result<(), DamError> {
            if let Some(d) = &self.detection {
                ctx.detections.push(d.clone());
            }
            Ok(())
        }
    }

    /// A mock action module that uppercases the body.
    struct MockAction {
        should_match: bool,
    }

    impl Module for MockAction {
        fn name(&self) -> &str {
            "mock-action"
        }
        fn module_type(&self) -> ModuleType {
            ModuleType::Action
        }
        fn matches(&self, _ctx: &FlowContext) -> bool {
            self.should_match
        }
        fn process(&self, ctx: &mut FlowContext) -> Result<(), DamError> {
            if !ctx.detections.is_empty() {
                ctx.modified_body = Some(ctx.request_body.to_uppercase());
            }
            Ok(())
        }
    }

    /// A mock module that always errors.
    struct FailingModule;

    impl Module for FailingModule {
        fn name(&self) -> &str {
            "failing"
        }
        fn module_type(&self) -> ModuleType {
            ModuleType::Detection
        }
        fn matches(&self, _ctx: &FlowContext) -> bool {
            true
        }
        fn process(&self, _ctx: &mut FlowContext) -> Result<(), DamError> {
            Err(DamError::Module {
                name: "failing".into(),
                message: "boom".into(),
            })
        }
    }

    fn det(start: usize, end: usize, conf: f32, module: &str) -> Detection {
        Detection {
            data_type: SensitiveDataType::Email,
            value: "test@test.com".into(),
            span: Span { start, end },
            confidence: conf,
            source_module: module.into(),
            verdict: crate::module_trait::Verdict::Pending,
        }
    }

    fn ctx(body: &str) -> FlowContext {
        FlowContext::new(
            body.into(),
            Destination::Other {
                host: "example.com".into(),
            },
        )
    }

    #[test]
    fn test_empty_flow() {
        let exec = FlowExecutor::new(vec![]);
        let mut c = ctx("hello world");
        exec.run(&mut c).unwrap();
        assert!(c.detections.is_empty());
        assert_eq!(c.output_body(), "hello world");
    }

    #[test]
    fn test_single_detection_module() {
        let m = Arc::new(MockDetector {
            name: "det",
            detection: Some(det(0, 5, 0.9, "det")),
            should_match: true,
        });
        let exec = FlowExecutor::new(vec![m]);
        let mut c = ctx("hello");
        exec.run(&mut c).unwrap();
        assert_eq!(c.detections.len(), 1);
    }

    #[test]
    fn test_two_detection_modules_merge() {
        let m1 = Arc::new(MockDetector {
            name: "det1",
            detection: Some(det(0, 5, 0.9, "det1")),
            should_match: true,
        });
        let m2 = Arc::new(MockDetector {
            name: "det2",
            detection: Some(det(10, 15, 0.8, "det2")),
            should_match: true,
        });
        let exec = FlowExecutor::new(vec![m1, m2]);
        let mut c = ctx("hello worldtest!");
        exec.run(&mut c).unwrap();
        assert_eq!(c.detections.len(), 2);
    }

    #[test]
    fn test_detection_then_action() {
        let det_mod = Arc::new(MockDetector {
            name: "det",
            detection: Some(det(0, 5, 0.9, "det")),
            should_match: true,
        });
        let act_mod: Arc<dyn Module> = Arc::new(MockAction { should_match: true });
        let exec = FlowExecutor::new(vec![det_mod, act_mod]);
        let mut c = ctx("hello");
        exec.run(&mut c).unwrap();
        assert_eq!(c.output_body(), "HELLO");
    }

    #[test]
    fn test_module_not_matching_skipped() {
        let m = Arc::new(MockDetector {
            name: "det",
            detection: Some(det(0, 5, 0.9, "det")),
            should_match: false,
        });
        let exec = FlowExecutor::new(vec![m]);
        let mut c = ctx("hello");
        exec.run(&mut c).unwrap();
        assert!(c.detections.is_empty());
    }

    #[test]
    fn test_module_error_continues() {
        let failing: Arc<dyn Module> = Arc::new(FailingModule);
        let good = Arc::new(MockDetector {
            name: "good",
            detection: Some(det(0, 5, 0.9, "good")),
            should_match: true,
        });
        let exec = FlowExecutor::new(vec![failing, good]);
        let mut c = ctx("hello");
        exec.run(&mut c).unwrap();
        assert_eq!(c.detections.len(), 1);
    }

    #[test]
    fn test_no_detection_modules() {
        let act: Arc<dyn Module> = Arc::new(MockAction { should_match: true });
        let exec = FlowExecutor::new(vec![act]);
        let mut c = ctx("hello");
        exec.run(&mut c).unwrap();
        // No detections, so action should not modify body
        assert_eq!(c.output_body(), "hello");
    }

    #[test]
    fn test_no_action_modules() {
        let det_mod = Arc::new(MockDetector {
            name: "det",
            detection: Some(det(0, 5, 0.9, "det")),
            should_match: true,
        });
        let exec = FlowExecutor::new(vec![det_mod]);
        let mut c = ctx("hello");
        exec.run(&mut c).unwrap();
        assert_eq!(c.detections.len(), 1);
        assert_eq!(c.output_body(), "hello"); // not modified
    }

    #[test]
    fn test_dedup_after_detection() {
        let m1 = Arc::new(MockDetector {
            name: "det1",
            detection: Some(det(0, 10, 0.7, "det1")),
            should_match: true,
        });
        let m2 = Arc::new(MockDetector {
            name: "det2",
            detection: Some(det(5, 15, 0.95, "det2")),
            should_match: true,
        });
        let exec = FlowExecutor::new(vec![m1, m2]);
        let mut c = ctx("hello world!!!!");
        exec.run(&mut c).unwrap();
        // Overlapping — keep highest confidence
        assert_eq!(c.detections.len(), 1);
        assert_eq!(c.detections[0].confidence, 0.95);
    }

    /// A mock action module that always errors, with a configurable name.
    struct FailingActionModule {
        module_name: &'static str,
    }

    impl Module for FailingActionModule {
        fn name(&self) -> &str {
            self.module_name
        }
        fn module_type(&self) -> ModuleType {
            ModuleType::Action
        }
        fn matches(&self, _ctx: &FlowContext) -> bool {
            true
        }
        fn process(&self, _ctx: &mut FlowContext) -> Result<(), DamError> {
            Err(DamError::Module {
                name: self.module_name.into(),
                message: "boom".into(),
            })
        }
    }

    #[test]
    fn test_consent_failure_forces_redact() {
        let det_mod = Arc::new(MockDetector {
            name: "det",
            detection: Some(det(0, 5, 0.9, "det")),
            should_match: true,
        });
        let failing_consent: Arc<dyn Module> = Arc::new(FailingActionModule {
            module_name: "consent",
        });
        let exec = FlowExecutor::new(vec![det_mod, failing_consent]);
        let mut c = ctx("hello");
        exec.run(&mut c).unwrap();
        // Consent failure should force pending detections to Redact
        assert_eq!(c.detections.len(), 1);
        assert_eq!(c.detections[0].verdict, Verdict::Redact);
    }

    #[test]
    fn test_redact_failure_forces_redact() {
        let det_mod = Arc::new(MockDetector {
            name: "det",
            detection: Some(det(0, 5, 0.9, "det")),
            should_match: true,
        });
        let failing_redact: Arc<dyn Module> = Arc::new(FailingActionModule {
            module_name: "redact",
        });
        let exec = FlowExecutor::new(vec![det_mod, failing_redact]);
        let mut c = ctx("hello");
        exec.run(&mut c).unwrap();
        assert_eq!(c.detections[0].verdict, Verdict::Redact);
    }

    #[test]
    fn test_vault_failure_is_fail_open() {
        let det_mod = Arc::new(MockDetector {
            name: "det",
            detection: Some(det(0, 5, 0.9, "det")),
            should_match: true,
        });
        let failing_vault: Arc<dyn Module> = Arc::new(FailingActionModule {
            module_name: "vault",
        });
        let exec = FlowExecutor::new(vec![det_mod, failing_vault]);
        let mut c = ctx("hello");
        exec.run(&mut c).unwrap();
        // Vault failure should NOT force Redact (fail-open)
        assert_eq!(c.detections[0].verdict, Verdict::Pending);
    }

    #[test]
    fn test_consent_failure_preserves_existing_verdicts() {
        let det_mod = Arc::new(MockDetector {
            name: "det",
            detection: Some(det(0, 5, 0.9, "det")),
            should_match: true,
        });
        let failing_consent: Arc<dyn Module> = Arc::new(FailingActionModule {
            module_name: "consent",
        });
        let exec = FlowExecutor::new(vec![det_mod, failing_consent]);
        let mut c = ctx("hello");
        // Pre-set a Pass verdict — consent failure should only force Pending → Redact
        exec.run(&mut c).unwrap();
        // Since detection starts as Pending, it gets forced to Redact
        assert_eq!(c.detections[0].verdict, Verdict::Redact);
    }
}
