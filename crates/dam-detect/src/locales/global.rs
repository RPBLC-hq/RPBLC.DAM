use crate::stage_regex::Pattern;
use crate::validators::{validate_iban, validate_ip, validate_luhn_cc};
use dam_core::PiiType;
use regex::Regex;

/// Patterns that apply regardless of locale — not country-specific PII.
pub(crate) fn patterns() -> Vec<Pattern> {
    vec![
        // Email addresses
        Pattern {
            regex: Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap(),
            pii_type: PiiType::Email,
            confidence: 0.95,
            validator: None,
        },
        // Credit card numbers (common formats, 13-19 digits with optional separators)
        Pattern {
            regex: Regex::new(
                r"\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{4}[-\s]?\d{6}[-\s]?\d{5})\b",
            )
            .unwrap(),
            pii_type: PiiType::CreditCard,
            confidence: 0.85,
            validator: Some(validate_luhn_cc),
        },
        // International phone — E.164 with optional separators
        // 7-15 digits total, first digit non-zero, separators (space/dash/dot) allowed
        Pattern {
            regex: Regex::new(r"\+[1-9]\d(?:[\s\-.]?\d){5,13}\b").unwrap(),
            pii_type: PiiType::Phone,
            confidence: 0.9,
            validator: None,
        },
        // IPv4 addresses
        Pattern {
            regex: Regex::new(
                r"\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b",
            )
            .unwrap(),
            pii_type: PiiType::IpAddress,
            confidence: 0.8,
            validator: Some(validate_ip),
        },
        // Date of birth patterns (various formats)
        Pattern {
            regex: Regex::new(r"\b(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b").unwrap(),
            pii_type: PiiType::DateOfBirth,
            confidence: 0.5,
            validator: None,
        },
        // IBAN — 2 letters + 2 digits + 11-30 alphanumeric (case-insensitive)
        Pattern {
            regex: Regex::new(r"(?i)\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").unwrap(),
            pii_type: PiiType::Iban,
            confidence: 0.90,
            validator: Some(validate_iban),
        },
    ]
}
