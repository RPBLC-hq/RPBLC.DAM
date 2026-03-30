use crate::destination::Destination;
use crate::error::DamError;
use crate::token::Token;
use crate::types::SensitiveDataType;

/// Whether a module detects data or acts on detections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleType {
    Detection,
    Action,
}

/// A byte span in the request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn overlaps(&self, other: &Span) -> bool {
        self.start < other.end && other.start < self.end
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// Verdict set by the consent module for each detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verdict {
    /// No consent check yet — detection just found.
    #[default]
    Pending,
    /// Consent says: tokenize/redact this value.
    Redact,
    /// Consent says: let the real value pass through.
    Pass,
}

/// A single detection of sensitive data in the request body.
#[derive(Debug, Clone)]
pub struct Detection {
    pub data_type: SensitiveDataType,
    pub value: String,
    pub span: Span,
    pub confidence: f32,
    pub source_module: String,
    /// Set by the consent module. Defaults to Pending.
    pub verdict: Verdict,
}

/// Context passed through the module flow for a single request.
pub struct FlowContext {
    pub request_body: String,
    pub destination: Destination,
    pub detections: Vec<Detection>,
    /// Set by action modules when they modify the body (e.g., vault tokenizes).
    pub modified_body: Option<String>,
    /// Tokens created by the vault module.
    pub tokens_created: Vec<Token>,
}

impl FlowContext {
    pub fn new(request_body: String, destination: Destination) -> Self {
        Self {
            request_body,
            destination,
            detections: Vec::new(),
            modified_body: None,
            tokens_created: Vec::new(),
        }
    }

    /// The body to forward upstream (modified if an action module changed it).
    pub fn output_body(&self) -> &str {
        self.modified_body.as_deref().unwrap_or(&self.request_body)
    }

    /// Deduplicate overlapping detections, keeping highest confidence.
    pub fn dedup_detections(&mut self) {
        if self.detections.len() <= 1 {
            return;
        }
        // Sort by confidence descending — highest confidence wins
        self.detections.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut kept: Vec<Detection> = Vec::with_capacity(self.detections.len());
        for det in self.detections.drain(..) {
            let overlaps_existing = kept.iter().any(|k| k.span.overlaps(&det.span));
            if !overlaps_existing {
                kept.push(det);
            }
        }
        // Sort final list by start position for deterministic output
        kept.sort_by_key(|d| d.span.start);
        self.detections = kept;
    }
}

/// The module trait — implemented by every vertebra (detection or action).
pub trait Module: Send + Sync {
    fn name(&self) -> &str;
    fn module_type(&self) -> ModuleType;
    fn matches(&self, ctx: &FlowContext) -> bool;
    fn process(&self, ctx: &mut FlowContext) -> Result<(), DamError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_overlap() {
        let a = Span { start: 0, end: 10 };
        let b = Span { start: 5, end: 15 };
        assert!(a.overlaps(&b));
        assert!(b.overlaps(&a));
    }

    #[test]
    fn test_span_no_overlap() {
        let a = Span { start: 0, end: 5 };
        let b = Span { start: 5, end: 10 };
        assert!(!a.overlaps(&b));
    }

    #[test]
    fn test_span_adjacent_no_overlap() {
        let a = Span { start: 0, end: 5 };
        let b = Span { start: 5, end: 10 };
        assert!(!a.overlaps(&b));
        assert!(!b.overlaps(&a));
    }

    fn make_detection(start: usize, end: usize, confidence: f32, module: &str) -> Detection {
        Detection {
            data_type: SensitiveDataType::Email,
            value: "test".into(),
            span: Span { start, end },
            confidence,
            source_module: module.into(),
            verdict: Verdict::Pending,
        }
    }

    #[test]
    fn test_flow_context_dedup_overlapping() {
        let mut ctx = FlowContext::new(
            "test".into(),
            Destination::Other {
                host: "example.com".into(),
            },
        );
        ctx.detections.push(make_detection(0, 10, 0.8, "a"));
        ctx.detections.push(make_detection(5, 15, 0.9, "b"));
        ctx.dedup_detections();
        assert_eq!(ctx.detections.len(), 1);
        assert_eq!(ctx.detections[0].confidence, 0.9);
    }

    #[test]
    fn test_flow_context_dedup_no_overlap() {
        let mut ctx = FlowContext::new(
            "test".into(),
            Destination::Other {
                host: "example.com".into(),
            },
        );
        ctx.detections.push(make_detection(0, 5, 0.8, "a"));
        ctx.detections.push(make_detection(10, 15, 0.9, "b"));
        ctx.dedup_detections();
        assert_eq!(ctx.detections.len(), 2);
    }

    #[test]
    fn test_flow_context_dedup_across_modules() {
        let mut ctx = FlowContext::new(
            "test".into(),
            Destination::Other {
                host: "example.com".into(),
            },
        );
        // Same span from two modules — keep highest confidence
        ctx.detections.push(make_detection(0, 10, 0.7, "mod-a"));
        ctx.detections.push(make_detection(0, 10, 0.95, "mod-b"));
        ctx.dedup_detections();
        assert_eq!(ctx.detections.len(), 1);
        assert_eq!(ctx.detections[0].confidence, 0.95);
    }

    #[test]
    fn test_flow_context_empty() {
        let mut ctx = FlowContext::new(
            "hello".into(),
            Destination::Other {
                host: "x.com".into(),
            },
        );
        ctx.dedup_detections();
        assert!(ctx.detections.is_empty());
        assert_eq!(ctx.output_body(), "hello");
    }

    #[test]
    fn test_flow_context_modified_body() {
        let mut ctx = FlowContext::new(
            "original".into(),
            Destination::Other {
                host: "x.com".into(),
            },
        );
        assert_eq!(ctx.output_body(), "original");
        ctx.modified_body = Some("modified".into());
        assert_eq!(ctx.output_body(), "modified");
    }
}
