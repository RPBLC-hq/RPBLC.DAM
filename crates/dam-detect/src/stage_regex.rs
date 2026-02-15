use dam_core::PiiType;
use once_cell::sync::Lazy;
use regex::Regex;
use unicode_normalization::UnicodeNormalization;

/// Normalize text for consistent PII detection.
/// - Strips zero-width characters (U+200B, U+200C, U+200D, U+FEFF, U+00AD)
/// - Applies NFKC normalization to convert fullwidth and other variants to ASCII
/// - Replaces Unicode dash variants with ASCII hyphen-minus
/// - URL-decodes percent-encoded sequences
/// - Attempts to decode potential Base64 strings
fn normalize_text(text: &str) -> String {
    // First pass: strip zero-width chars and replace dash variants
    let cleaned: String = text.chars()
        .filter(|c| {
            // Strip zero-width characters
            !matches!(
                *c,
                '\u{200B}' | // zero-width space
                '\u{200C}' | // zero-width non-joiner
                '\u{200D}' | // zero-width joiner
                '\u{FEFF}' | // zero-width no-break space
                '\u{00AD}'   // soft hyphen
            )
        })
        .map(|c| {
            // Replace Unicode dash variants with ASCII hyphen-minus
            match c {
                '\u{2010}' | // hyphen
                '\u{2011}' | // non-breaking hyphen
                '\u{2012}' | // figure dash
                '\u{2013}' | // en dash
                '\u{2014}' | // em dash
                '\u{2015}' | // horizontal bar
                '\u{2212}' => '-', // minus sign
                _ => c,
            }
        })
        .nfkc() // NFKC normalization converts fullwidth, ligatures, etc. to ASCII
        .collect();

    // URL-decode
    let url_decoded = url_decode(&cleaned);

    // Try to decode potential Base64 strings and add them to detection
    let with_base64 = decode_base64_segments(&url_decoded);

    with_base64
}

/// Simple URL decoding for percent-encoded sequences
fn url_decode(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            // Try to decode %XX sequence
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    if let Some(decoded) = char::from_u32(byte as u32) {
                        result.push(decoded);
                        continue;
                    }
                }
            }
            // If decode failed, keep original
            result.push('%');
            result.push_str(&hex);
        } else {
            result.push(c);
        }
    }

    result
}

/// Detect and decode potential Base64 strings in text.
/// Looks for sequences of 20+ Base64 characters and attempts to decode them.
fn decode_base64_segments(text: &str) -> String {
    use once_cell::sync::Lazy;
    use regex::Regex;

    // Match potential Base64 strings (20+ chars, alphanumeric + / + = padding)
    static BASE64_PATTERN: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").unwrap()
    });

    let mut result = String::with_capacity(text.len());
    let mut last_end = 0;

    for mat in BASE64_PATTERN.find_iter(text) {
        result.push_str(&text[last_end..mat.start()]);

        // Try to decode as Base64
        if let Ok(decoded_bytes) = base64_decode(mat.as_str()) {
            if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                // Add both original and decoded (decoded might contain PII)
                result.push_str(mat.as_str());
                result.push(' ');
                result.push_str(&decoded_str);
            } else {
                result.push_str(mat.as_str());
            }
        } else {
            result.push_str(mat.as_str());
        }

        last_end = mat.end();
    }

    result.push_str(&text[last_end..]);
    result
}

/// Simple Base64 decoding
fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    // Simple Base64 alphabet
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;

    for &byte in s.as_bytes() {
        if byte == b'=' {
            break;
        }

        let value = ALPHABET.iter().position(|&c| c == byte).ok_or(())?;
        buffer = (buffer << 6) | (value as u32);
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Ok(result)
}

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
/// Text is normalized (zero-width chars removed, NFKC applied) before detection.
pub fn detect(text: &str) -> Vec<Detection> {
    let mut detections = Vec::new();

    // Normalize text to handle Unicode variants and zero-width characters
    let normalized = normalize_text(text);

    for pattern in PATTERNS.iter() {
        for mat in pattern.regex.find_iter(&normalized) {
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
        (169, 254, _, _) => false,     // link-local
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

    #[test]
    fn reject_link_local_ip() {
        let detections = detect("IP: 169.254.1.1");
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::IpAddress));

        let detections = detect("IP: 169.254.169.254");
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::IpAddress));
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

    // --- Unicode normalization tests (issues #9, #10, #12) ---

    #[test]
    fn detect_email_with_zero_width_space() {
        // Zero-width space (U+200B) after @
        let detections = detect("email: alice@\u{200B}example.com");
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Email));
    }

    #[test]
    fn detect_ssn_with_unicode_dashes() {
        // En-dash (U+2010)
        let detections = detect("SSN: 123\u{2010}45\u{2010}6789");
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Ssn));

        // Em-dash (U+2013)
        let detections = detect("SSN: 123\u{2013}45\u{2013}6789");
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    #[test]
    fn detect_email_with_fullwidth_at() {
        // Fullwidth @ (U+FF20)
        let detections = detect("email: bob\u{FF20}test.org");
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Email));
    }

    // --- Encoding bypass tests (issue #11) ---

    #[test]
    fn detect_url_encoded_email() {
        // URL-encoded @ (%40)
        let detections = detect("Email: alice%40example.com");
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Email));
    }

    #[test]
    fn detect_url_encoded_phone() {
        // URL-encoded dashes (%2D)
        let detections = detect("Phone: 555%2D867%2D5309");
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Phone));
    }

    #[test]
    fn detect_base64_encoded_email() {
        // Base64 of "alice@example.com" is "YWxpY2VAZXhhbXBsZS5jb20="
        let detections = detect("Contact: YWxpY2VAZXhhbXBsZS5jb20= is encoded");
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Email));
    }

    #[test]
    fn detect_email_with_cyrillic_homoglyph() {
        // Cyrillic 'а' (U+0430) looks identical to Latin 'a' (U+0061)
        let detections = detect("email: \u{0430}lice@example.com");
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Email),
            "should detect email even with Cyrillic 'а' prefix"
        );
    }

    #[test]
    fn base64_non_pii_no_false_positive() {
        // Base64 of "This is just random text" — should not produce PII detections
        let detections = detect("Token: VGhpcyBpcyBqdXN0IHJhbmRvbSB0ZXh0");
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Email
                || d.pii_type == PiiType::Ssn
                || d.pii_type == PiiType::Phone),
            "non-PII Base64 should not produce false positives"
        );
    }
}
