use dam_core::PiiType;
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
    let cleaned: String = text
        .chars()
        .filter(|c| {
            // Strip zero-width characters
            !matches!(
                *c,
                '\u{200B}' | // zero-width space
                '\u{200C}' | // zero-width non-joiner
                '\u{200D}' | // zero-width joiner
                '\u{FEFF}' | // zero-width no-break space
                '\u{00AD}' // soft hyphen
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
    decode_base64_segments(&url_decoded)
}

/// Simple URL decoding for percent-encoded sequences
fn url_decode(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            // Try to decode %XX sequence
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2
                && let Ok(byte) = u8::from_str_radix(&hex, 16)
                && let Some(decoded) = char::from_u32(byte as u32)
            {
                result.push(decoded);
                continue;
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
    static BASE64_PATTERN: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").unwrap());

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

pub(crate) struct Pattern {
    pub(crate) regex: Regex,
    pub(crate) pii_type: PiiType,
    pub(crate) confidence: f32,
    pub(crate) validator: Option<fn(&str) -> bool>,
}

/// Run regex-based PII detection on text using the given patterns.
/// Text is normalized (zero-width chars removed, NFKC applied) before detection.
///
/// Returns `(normalized_text, detections)` — offsets in `Detection` refer to
/// the normalized text, not the original input. Callers must use the normalized
/// text when performing span-based replacements.
pub(crate) fn detect(text: &str, patterns: &[Pattern]) -> (String, Vec<Detection>) {
    let mut detections = Vec::new();

    // Normalize text to handle Unicode variants and zero-width characters
    let normalized = normalize_text(text);

    for pattern in patterns {
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

    (normalized, detections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locales;

    fn all_patterns() -> Vec<Pattern> {
        locales::build_patterns(dam_core::Locale::all())
    }

    #[test]
    fn detect_email() {
        let (_, detections) = detect("Contact me at john@example.com please", &all_patterns());
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pii_type, PiiType::Email);
        assert_eq!(detections[0].value, "john@example.com");
    }

    #[test]
    fn detect_phone() {
        let (_, detections) = detect("Call me at 555-123-4567", &all_patterns());
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Phone));
    }

    #[test]
    fn detect_ssn() {
        let (_, detections) = detect("SSN: 123-45-6789", &all_patterns());
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    #[test]
    fn reject_invalid_ssn() {
        // 000 area is invalid
        let (_, detections) = detect("Number: 000-12-3456", &all_patterns());
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    #[test]
    fn detect_credit_card_with_luhn() {
        // Valid Visa test number
        let (_, detections) = detect("Card: 4111 1111 1111 1111", &all_patterns());
        assert!(detections.iter().any(|d| d.pii_type == PiiType::CreditCard));
    }

    #[test]
    fn detect_multiple() {
        let text = "Email me at john@acme.com, SSN 123-45-6789";
        let (_, detections) = detect(text, &all_patterns());
        assert!(detections.len() >= 2);
    }

    // --- SSN edge cases ---

    #[test]
    fn ssn_space_separated() {
        let (_, detections) = detect("SSN: 123 45 6789", &all_patterns());
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    #[test]
    fn ssn_no_separators_not_detected() {
        // The regex requires dashes or spaces — bare digits should not match
        let (_, detections) = detect("SSN: 123456789", &all_patterns());
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    #[test]
    fn reject_ssn_area_666() {
        let (_, detections) = detect("Number: 666-12-3456", &all_patterns());
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    #[test]
    fn reject_ssn_area_900_plus() {
        let (_, detections) = detect("Number: 900-12-3456", &all_patterns());
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::Ssn));

        let (_, detections) = detect("Number: 999-12-3456", &all_patterns());
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    #[test]
    fn reject_ssn_zero_group() {
        let (_, detections) = detect("Number: 123-00-6789", &all_patterns());
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    #[test]
    fn reject_ssn_zero_serial() {
        let (_, detections) = detect("Number: 123-45-0000", &all_patterns());
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    // --- Credit card edge cases ---

    #[test]
    fn reject_luhn_failing_card() {
        // 4111 1111 1111 1112 fails Luhn
        let (_, detections) = detect("Card: 4111 1111 1111 1112", &all_patterns());
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::CreditCard));
    }

    // --- IP edge cases ---

    #[test]
    fn reject_localhost_ip() {
        let (_, detections) = detect("IP: 127.0.0.1", &all_patterns());
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::IpAddress));
    }

    #[test]
    fn reject_private_ip() {
        let (_, detections) = detect("IP: 192.168.1.1", &all_patterns());
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::IpAddress));

        let (_, detections) = detect("IP: 10.0.0.1", &all_patterns());
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::IpAddress));
    }

    #[test]
    fn detect_public_ip() {
        let (_, detections) = detect("IP: 8.8.8.8", &all_patterns());
        assert!(detections.iter().any(|d| d.pii_type == PiiType::IpAddress));
    }

    #[test]
    fn reject_link_local_ip() {
        let (_, detections) = detect("IP: 169.254.1.1", &all_patterns());
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::IpAddress));

        let (_, detections) = detect("IP: 169.254.169.254", &all_patterns());
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::IpAddress));
    }

    // --- General edge cases ---

    #[test]
    fn empty_input() {
        let (_, detections) = detect("", &all_patterns());
        assert!(detections.is_empty());
    }

    #[test]
    fn pii_at_string_boundaries() {
        // Email at the very start
        let (_, detections) = detect("john@example.com is here", &all_patterns());
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Email));

        // Email at the very end
        let (_, detections) = detect("contact john@example.com", &all_patterns());
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Email));
    }

    #[test]
    fn no_false_positive_on_plain_text() {
        let (_, detections) = detect(
            "Hello, this is a normal sentence with no PII.",
            &all_patterns(),
        );
        assert!(detections.is_empty());
    }

    // --- Unicode normalization tests (issues #9, #10, #12) ---

    #[test]
    fn detect_email_with_zero_width_space() {
        // Zero-width space (U+200B) after @
        let (_, detections) = detect("email: alice@\u{200B}example.com", &all_patterns());
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Email));
    }

    #[test]
    fn detect_ssn_with_unicode_dashes() {
        // En-dash (U+2010)
        let (_, detections) = detect("SSN: 123\u{2010}45\u{2010}6789", &all_patterns());
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Ssn));

        // Em-dash (U+2013)
        let (_, detections) = detect("SSN: 123\u{2013}45\u{2013}6789", &all_patterns());
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Ssn));
    }

    #[test]
    fn detect_email_with_fullwidth_at() {
        // Fullwidth @ (U+FF20)
        let (_, detections) = detect("email: bob\u{FF20}test.org", &all_patterns());
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Email));
    }

    // --- Encoding bypass tests (issue #11) ---

    #[test]
    fn detect_url_encoded_email() {
        // URL-encoded @ (%40)
        let (_, detections) = detect("Email: alice%40example.com", &all_patterns());
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Email));
    }

    #[test]
    fn detect_url_encoded_phone() {
        // URL-encoded dashes (%2D)
        let (_, detections) = detect("Phone: 555%2D867%2D5309", &all_patterns());
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Phone));
    }

    #[test]
    fn detect_base64_encoded_email() {
        // Base64 of "alice@example.com" is "YWxpY2VAZXhhbXBsZS5jb20="
        let (_, detections) = detect(
            "Contact: YWxpY2VAZXhhbXBsZS5jb20= is encoded",
            &all_patterns(),
        );
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Email));
    }

    #[test]
    fn detect_email_with_cyrillic_homoglyph() {
        // Cyrillic 'а' (U+0430) looks identical to Latin 'a' (U+0061)
        let (_, detections) = detect("email: \u{0430}lice@example.com", &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Email),
            "should detect email even with Cyrillic 'а' prefix"
        );
    }

    #[test]
    fn base64_non_pii_no_false_positive() {
        // Base64 of "This is just random text" — should not produce PII detections
        let (_, detections) = detect("Token: VGhpcyBpcyBqdXN0IHJhbmRvbSB0ZXh0", &all_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Email
                || d.pii_type == PiiType::Ssn
                || d.pii_type == PiiType::Phone),
            "non-PII Base64 should not produce false positives"
        );
    }
}
