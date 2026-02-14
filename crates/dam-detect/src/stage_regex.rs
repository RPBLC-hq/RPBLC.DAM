use dam_core::PiiType;
use once_cell::sync::Lazy;
use regex::Regex;

/// A single PII detection with location and confidence.
#[derive(Debug, Clone)]
pub struct Detection {
    pub value: String,
    pub pii_type: PiiType,
    pub start: usize,
    pub end: usize,
    pub confidence: f32,
}

struct Pattern {
    regex: Regex,
    pii_type: PiiType,
    confidence: f32,
    validator: Option<fn(&str) -> bool>,
}

static PATTERNS: Lazy<Vec<Pattern>> = Lazy::new(|| {
    vec![
        // Email addresses
        Pattern {
            regex: Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap(),
            pii_type: PiiType::Email,
            confidence: 0.95,
            validator: None,
        },
        // SSN (with dashes or spaces, not in obviously non-SSN contexts)
        Pattern {
            regex: Regex::new(r"\b(\d{3}[-\s]\d{2}[-\s]\d{4})\b").unwrap(),
            pii_type: PiiType::Ssn,
            confidence: 0.9,
            validator: Some(validate_ssn),
        },
        // Credit card numbers (common formats, 13-19 digits with optional separators)
        Pattern {
            regex: Regex::new(
                r"\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{4}[-\s]?\d{6}[-\s]?\d{5})\b",
            )
            .unwrap(),
            pii_type: PiiType::CreditCard,
            confidence: 0.85,
            validator: Some(validate_luhn),
        },
        // Phone numbers — international and US formats
        Pattern {
            regex: Regex::new(
                r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            )
            .unwrap(),
            pii_type: PiiType::Phone,
            confidence: 0.85,
            validator: None,
        },
        // International phone (starts with +)
        Pattern {
            regex: Regex::new(r"\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b").unwrap(),
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
            regex: Regex::new(
                r"\b(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b",
            )
            .unwrap(),
            pii_type: PiiType::DateOfBirth,
            confidence: 0.5, // Low confidence — needs context
            validator: None,
        },
    ]
});

/// Run regex-based PII detection on text.
pub fn detect(text: &str) -> Vec<Detection> {
    let mut detections = Vec::new();

    for pattern in PATTERNS.iter() {
        for mat in pattern.regex.find_iter(text) {
            let value = mat.as_str().to_string();

            // Run validator if present
            if let Some(validator) = pattern.validator
                && !validator(&value)
            {
                continue;
            }

            detections.push(Detection {
                value,
                pii_type: pattern.pii_type,
                start: mat.start(),
                end: mat.end(),
                confidence: pattern.confidence,
            });
        }
    }

    detections
}

/// Validate SSN: exclude known invalid ranges (000, 666, 900-999 for area).
fn validate_ssn(value: &str) -> bool {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 9 {
        return false;
    }
    let area: u32 = digits[..3].parse().unwrap_or(0);
    let group: u32 = digits[3..5].parse().unwrap_or(0);
    let serial: u32 = digits[5..].parse().unwrap_or(0);

    // Invalid area numbers
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }
    // Group and serial can't be all zeros
    if group == 0 || serial == 0 {
        return false;
    }
    true
}

/// Luhn algorithm for credit card validation.
fn validate_luhn(value: &str) -> bool {
    let digits: Vec<u32> = value
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut n = d;
        if double {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// Validate that an IP is not a common non-PII address (localhost, broadcast, etc.).
fn validate_ip(value: &str) -> bool {
    let parts: Vec<u8> = value.split('.').filter_map(|p| p.parse().ok()).collect();

    if parts.len() != 4 {
        return false;
    }

    // Exclude common non-PII IPs
    match (parts[0], parts[1], parts[2], parts[3]) {
        (127, _, _, _) => false,       // loopback
        (0, 0, 0, 0) => false,         // unspecified
        (255, 255, 255, 255) => false, // broadcast
        (10, _, _, _) => false,        // private class A
        (172, 16..=31, _, _) => false, // private class B
        (192, 168, _, _) => false,     // private class C
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_email() {
        let detections = detect("Contact me at john@example.com please");
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pii_type, PiiType::Email);
        assert_eq!(detections[0].value, "john@example.com");
    }

    #[test]
    fn detect_phone() {
        let detections = detect("Call me at 555-123-4567");
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Phone));
    }

    #[test]
    fn detect_ssn() {
        let detections = detect("SSN: 123-45-6789");
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    #[test]
    fn reject_invalid_ssn() {
        // 000 area is invalid
        let detections = detect("Number: 000-12-3456");
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    #[test]
    fn detect_credit_card_with_luhn() {
        // Valid Visa test number
        let detections = detect("Card: 4111 1111 1111 1111");
        assert!(detections.iter().any(|d| d.pii_type == PiiType::CreditCard));
    }

    #[test]
    fn detect_multiple() {
        let text = "Email me at john@acme.com, SSN 123-45-6789";
        let detections = detect(text);
        assert!(detections.len() >= 2);
    }

    // --- SSN edge cases ---

    #[test]
    fn ssn_space_separated() {
        let detections = detect("SSN: 123 45 6789");
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    #[test]
    fn ssn_no_separators_not_detected() {
        // The regex requires dashes or spaces — bare digits should not match
        let detections = detect("SSN: 123456789");
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    #[test]
    fn reject_ssn_area_666() {
        let detections = detect("Number: 666-12-3456");
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    #[test]
    fn reject_ssn_area_900_plus() {
        let detections = detect("Number: 900-12-3456");
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::Ssn));

        let detections = detect("Number: 999-12-3456");
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    #[test]
    fn reject_ssn_zero_group() {
        let detections = detect("Number: 123-00-6789");
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    #[test]
    fn reject_ssn_zero_serial() {
        let detections = detect("Number: 123-45-0000");
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    // --- Credit card edge cases ---

    #[test]
    fn reject_luhn_failing_card() {
        // 4111 1111 1111 1112 fails Luhn
        let detections = detect("Card: 4111 1111 1111 1112");
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::CreditCard));
    }

    // --- IP edge cases ---

    #[test]
    fn reject_localhost_ip() {
        let detections = detect("IP: 127.0.0.1");
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::IpAddress));
    }

    #[test]
    fn reject_private_ip() {
        let detections = detect("IP: 192.168.1.1");
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::IpAddress));

        let detections = detect("IP: 10.0.0.1");
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::IpAddress));
    }

    #[test]
    fn detect_public_ip() {
        let detections = detect("IP: 8.8.8.8");
        assert!(detections.iter().any(|d| d.pii_type == PiiType::IpAddress));
    }

    // --- General edge cases ---

    #[test]
    fn empty_input() {
        let detections = detect("");
        assert!(detections.is_empty());
    }

    #[test]
    fn pii_at_string_boundaries() {
        // Email at the very start
        let detections = detect("john@example.com is here");
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Email));

        // Email at the very end
        let detections = detect("contact john@example.com");
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Email));
    }

    #[test]
    fn no_false_positive_on_plain_text() {
        let detections = detect("Hello, this is a normal sentence with no PII.");
        assert!(detections.is_empty());
    }
}
