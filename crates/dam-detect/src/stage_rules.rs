use crate::stage_regex::Detection;
use dam_core::PiiType;
use dam_core::config::CustomRule;
use regex::Regex;
use std::collections::HashMap;

/// User-defined rules engine for custom PII patterns.
pub struct RulesEngine {
    rules: Vec<CompiledRule>,
}

#[allow(dead_code)]
struct CompiledRule {
    name: String,
    regex: Regex,
    pii_type: PiiType,
}

impl RulesEngine {
    /// Compile user-defined rules from config.
    pub fn new(rules: &HashMap<String, CustomRule>) -> Self {
        let compiled = rules
            .iter()
            .filter_map(|(name, rule)| {
                Regex::new(&rule.pattern).ok().map(|regex| CompiledRule {
                    name: name.clone(),
                    regex,
                    pii_type: rule.pii_type,
                })
            })
            .collect();

        Self { rules: compiled }
    }

    /// Create an empty rules engine (no custom rules).
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Run all custom rules against text.
    pub fn detect(&self, text: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        for rule in &self.rules {
            for mat in rule.regex.find_iter(text) {
                detections.push(Detection {
                    value: mat.as_str().to_string(),
                    pii_type: rule.pii_type,
                    start: mat.start(),
                    end: mat.end(),
                    confidence: 1.0, // User-defined rules are high confidence
                });
            }
        }

        detections
    }

    /// Returns true if there are no custom rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_rule_detection() {
        let mut rules = HashMap::new();
        rules.insert(
            "employee_id".to_string(),
            CustomRule {
                pattern: r"EMP-\d{6}".to_string(),
                pii_type: PiiType::Custom,
                description: Some("Employee ID".to_string()),
            },
        );

        let engine = RulesEngine::new(&rules);
        let detections = engine.detect("Employee EMP-123456 was assigned");
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].value, "EMP-123456");
        assert_eq!(detections[0].pii_type, PiiType::Custom);
    }

    #[test]
    fn empty_engine() {
        let engine = RulesEngine::empty();
        assert!(engine.is_empty());
        let detections = engine.detect("any text here");
        assert!(detections.is_empty());
    }
}
