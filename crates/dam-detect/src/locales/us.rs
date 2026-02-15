use crate::stage_regex::Pattern;
use crate::validators::validate_ssn;
use dam_core::PiiType;
use regex::Regex;

/// US-specific PII patterns.
pub(crate) fn patterns() -> Vec<Pattern> {
    vec![
        // SSN (with dashes or spaces, not in obviously non-SSN contexts)
        Pattern {
            regex: Regex::new(r"\b(\d{3}[-\s]\d{2}[-\s]\d{4})\b").unwrap(),
            pii_type: PiiType::Ssn,
            confidence: 0.9,
            validator: Some(validate_ssn),
        },
        // US Phone numbers
        Pattern {
            regex: Regex::new(r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap(),
            pii_type: PiiType::Phone,
            confidence: 0.85,
            validator: None,
        },
    ]
}
