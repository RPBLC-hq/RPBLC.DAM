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

/// Decode percent-encoded sequences (e.g. `%40` → `@`).
///
/// Handles standard `%XX` hex pairs. If a `%` is not followed by two valid
/// hex digits the original characters are preserved.
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

/// Detect and inline-decode potential Base64 segments in text.
///
/// Finds sequences of 20+ Base64 characters (`[A-Za-z0-9+/]{20,}={0,2}`)
/// and attempts to decode them. On success, the decoded UTF-8 string is
/// appended after the original segment so that downstream regex patterns
/// can match PII hidden inside Base64 payloads. The 20-char minimum avoids
/// false positives on short alphanumeric tokens.
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

        // Skip JWT segments — `eyJ` is base64url for `{"`, the start of every JWT
        // header and payload. Decoding them inline would destroy the JWT structure
        // that the JWT regex pattern relies on.
        if mat.as_str().starts_with("eyJ") {
            result.push_str(mat.as_str());
            last_end = mat.end();
            continue;
        }

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

/// Minimal Base64 decoder using the standard alphabet (`A-Za-z0-9+/`).
///
/// Processes input until `=` padding or end of string. Returns `Err(())`
/// if any byte is not in the Base64 alphabet. This avoids pulling in a
/// full Base64 crate for a single normalization step.
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

/// A single PII detection with byte offsets into the normalized text.
#[derive(Debug, Clone)]
pub struct Detection {
    /// The matched PII value.
    pub value: String,
    /// Category of PII detected.
    pub pii_type: PiiType,
    /// Start byte offset in the normalized text.
    pub start: usize,
    /// End byte offset in the normalized text.
    pub end: usize,
    /// Confidence score (0.0–1.0).
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
    fn detect_phone_ca_with_country_code_dashes() {
        let (_, detections) = detect("Call me at +1-514-555-0199", &all_patterns());
        assert!(detections.iter().any(|d| d.pii_type == PiiType::Phone));
    }

    #[test]
    fn detect_phone_ca_with_parentheses() {
        let (_, detections) = detect("Call me at +1 (514) 555-0199", &all_patterns());
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

    // ── JWT ──────────────────────────────────────────────────────────────────

    #[test]
    fn detect_jwt() {
        // Standard HS256 JWT from jwt.io
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let (_, detections) = detect(&format!("Authorization: Bearer {jwt}"), &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::JwtToken),
            "should detect JWT in authorization header"
        );
    }

    #[test]
    fn reject_jwt_only_two_segments() {
        // A JWT must have exactly three segments separated by dots
        let (_, detections) = detect(
            "token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0",
            &all_patterns(),
        );
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::JwtToken),
            "two-segment base64url string is not a JWT"
        );
    }

    #[test]
    fn reject_jwt_payload_not_eyj() {
        // Header starts with eyJ but payload doesn't — not a well-formed JWT
        let (_, detections) = detect(
            "token: eyJhbGciOiJIUzI1NiJ9.dXNlcjEyMw.SflKxwRJSMeKKF2QT4fw",
            &all_patterns(),
        );
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::JwtToken),
            "payload not starting with eyJ should not match"
        );
    }

    // ── AWS ───────────────────────────────────────────────────────────────────

    #[test]
    fn detect_aws_access_key() {
        let (_, detections) =
            detect("aws_access_key_id = AKIAIOSFODNN7EXAMPLE", &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::AwsKey),
            "should detect AWS access key ID"
        );
    }

    #[test]
    fn reject_aws_key_wrong_prefix() {
        let (_, detections) = detect("key: BKIAIOSFODNN7EXAMPLE", &all_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::AwsKey),
            "BKIA prefix is not an AWS key"
        );
    }

    #[test]
    fn reject_aws_key_too_short() {
        // AKIA + 15 chars (needs 16)
        let (_, detections) = detect("key: AKIAIOSFODNN7EXAMPL", &all_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::AwsKey),
            "AKIA + 15 chars is too short"
        );
    }

    #[test]
    fn detect_aws_arn() {
        let (_, detections) = detect(
            "resource: arn:aws:iam::123456789012:user/johndoe",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::AwsArn),
            "should detect IAM user ARN"
        );
    }

    #[test]
    fn detect_aws_arn_s3() {
        let (_, detections) = detect(
            "bucket: arn:aws:s3:::my-private-bucket/data/customers.csv",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::AwsArn),
            "should detect S3 ARN"
        );
    }

    #[test]
    fn reject_aws_arn_wrong_provider() {
        let (_, detections) = detect("resource: arn:gcp:storage:::my-bucket", &all_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::AwsArn),
            "GCP ARN should not match"
        );
    }

    // ── GitHub token ─────────────────────────────────────────────────────────

    #[test]
    fn detect_github_personal_token() {
        let (_, detections) = detect(
            "GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::GitHubToken),
            "should detect GitHub personal access token"
        );
    }

    #[test]
    fn detect_github_oauth_token() {
        let (_, detections) = detect(
            "token: gho_1234567890abcdef1234567890abcdef1234",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::GitHubToken),
            "should detect GitHub OAuth token"
        );
    }

    #[test]
    fn reject_github_token_invalid_type_char() {
        // ghx_ is not a valid GitHub token prefix
        let (_, detections) = detect(
            "token: ghx_1234567890abcdef1234567890abcdef1234",
            &all_patterns(),
        );
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::GitHubToken),
            "ghx_ prefix is not a GitHub token"
        );
    }

    #[test]
    fn reject_github_token_too_short() {
        // needs 36+ chars after the prefix
        let (_, detections) = detect("token: ghp_shorttoken", &all_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::GitHubToken),
            "too-short token should not match"
        );
    }

    // ── Stripe ────────────────────────────────────────────────────────────────

    #[test]
    fn detect_stripe_secret_key() {
        let (_, detections) = detect(
            "STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::StripeKey),
            "should detect Stripe secret key"
        );
    }

    #[test]
    fn detect_stripe_test_key() {
        let (_, detections) = detect(
            "stripe_key: pk_test_4eC39HqLyjWDarjtT1zdp7dc",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::StripeKey),
            "should detect Stripe test publishable key"
        );
    }

    #[test]
    fn detect_stripe_customer_id() {
        let (_, detections) = detect("customer: cus_1234567890abcdef", &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::StripeKey),
            "should detect Stripe customer ID"
        );
    }

    #[test]
    fn detect_stripe_payment_intent() {
        let (_, detections) = detect("payment_method: pm_1234567890abcdef", &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::StripeKey),
            "should detect Stripe payment method ID"
        );
    }

    #[test]
    fn reject_stripe_key_wrong_env() {
        // sk_staging_ is not a valid Stripe key environment
        let (_, detections) = detect(
            "key: sk_staging_4eC39HqLyjWDarjtT1zdp7dc",
            &all_patterns(),
        );
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::StripeKey),
            "sk_staging_ prefix is not valid"
        );
    }

    // ── Generic API keys ──────────────────────────────────────────────────────

    #[test]
    fn detect_google_api_key() {
        // AIza + 35 chars = 39 total
        let (_, detections) = detect(
            "api_key: AIzaSyD-9tSrke72I6e7H7tywPPVmHsN5BBBBBB",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::ApiKey),
            "should detect Google API key"
        );
    }

    #[test]
    fn reject_google_api_key_too_short() {
        // AIza + 34 chars (needs 35)
        let (_, detections) = detect("key: AIzaSyD-9tSrke72I6e7H7tywPPVmHsN5BBB", &all_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::ApiKey),
            "AIza + 34 chars is too short"
        );
    }

    #[test]
    fn detect_slack_webhook() {
        let (_, detections) = detect(
            "webhook: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::ApiKey),
            "should detect Slack incoming webhook URL"
        );
    }

    #[test]
    fn detect_slack_bot_token() {
        let (_, detections) = detect(
            "SLACK_TOKEN=xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::ApiKey),
            "should detect Slack bot token"
        );
    }

    #[test]
    fn reject_slack_token_wrong_prefix() {
        // xoxz- is not a valid Slack token prefix (valid: b=bot, a=app, p=personal, r=refresh, s=server)
        let (_, detections) = detect(
            "token: xoxz-123456789012-123456789012-abcdefghijklmnopqrstuvwx",
            &all_patterns(),
        );
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::ApiKey),
            "xoxz- prefix is not valid"
        );
    }

    #[test]
    fn detect_sendgrid_key() {
        // SG. + 22 + . + 43
        let key = "SG.ABCDEFGHIJKLMNOPQRSTUv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
        let (_, detections) = detect(&format!("SENDGRID_API_KEY={key}"), &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::ApiKey),
            "should detect SendGrid API key"
        );
    }

    #[test]
    fn detect_npm_token() {
        let (_, detections) = detect(
            "NPM_TOKEN=npm_1234567890ABCDEFGHIJKLMNOPQRSTUVwxyz",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::ApiKey),
            "should detect npm access token"
        );
    }

    #[test]
    fn detect_mailgun_key() {
        let (_, detections) = detect(
            "MAILGUN_API_KEY=key-1234567890abcdef1234567890abcdef",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::ApiKey),
            "should detect Mailgun API key"
        );
    }

    #[test]
    fn detect_twilio_key() {
        // SK + 32 lowercase alphanum
        let (_, detections) = detect(
            "TWILIO_API_KEY=SK1234567890abcdef1234567890abcdef",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::ApiKey),
            "should detect Twilio API key SID"
        );
    }

    // ── LLM provider API keys ─────────────────────────────────────────────────

    #[test]
    fn detect_anthropic_key() {
        // sk-ant-api03- + 92 alphanumeric chars (90 minimum required)
        let key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz1234";
        let (_, detections) = detect(&format!("ANTHROPIC_API_KEY={key}"), &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::LlmApiKey),
            "should detect Anthropic API key"
        );
    }

    #[test]
    fn detect_openai_project_key() {
        // sk-proj- + 58 alphanumeric chars
        let key = "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
        let (_, detections) = detect(&format!("OPENAI_API_KEY={key}"), &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::LlmApiKey),
            "should detect OpenAI project key"
        );
    }

    #[test]
    fn detect_openai_svcacct_key() {
        let key = "sk-svcacct-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
        let (_, detections) = detect(&format!("OPENAI_API_KEY={key}"), &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::LlmApiKey),
            "should detect OpenAI service-account key"
        );
    }

    #[test]
    fn detect_openai_legacy_key() {
        // sk- + exactly 48 alphanumeric chars
        let key = "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV";
        let (_, detections) = detect(&format!("OPENAI_API_KEY={key}"), &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::LlmApiKey),
            "should detect OpenAI legacy key"
        );
    }

    #[test]
    fn reject_openai_legacy_key_too_short() {
        // sk- + 47 chars — one short of the required 48
        let key = "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTU";
        let (_, detections) = detect(&format!("key={key}"), &all_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::LlmApiKey),
            "sk- + 47 chars should not match OpenAI legacy format"
        );
    }

    #[test]
    fn reject_openai_legacy_key_too_long() {
        // sk- + 49 chars — one over the required 48
        let key = "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW";
        let (_, detections) = detect(&format!("key={key}"), &all_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::LlmApiKey),
            "sk- + 49 chars should not match OpenAI legacy format"
        );
    }

    #[test]
    fn detect_huggingface_token() {
        // hf_ + 36 alphanumeric chars
        let key = "hf_abcdefghijklmnopqrstuvwxyzABCDEFGH";
        let (_, detections) = detect(&format!("HF_TOKEN={key}"), &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::LlmApiKey),
            "should detect Hugging Face token"
        );
    }

    #[test]
    fn reject_huggingface_token_too_short() {
        // hf_ + 33 chars — below 34 minimum
        let key = "hf_abcdefghijklmnopqrstuvwxyzABCD";
        let (_, detections) = detect(&format!("HF_TOKEN={key}"), &all_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::LlmApiKey),
            "hf_ + 33 chars should not match"
        );
    }

    #[test]
    fn detect_replicate_token() {
        // r8_ + 40 alphanumeric chars
        let key = "r8_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL";
        let (_, detections) = detect(&format!("REPLICATE_API_TOKEN={key}"), &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::LlmApiKey),
            "should detect Replicate API token"
        );
    }

    #[test]
    fn detect_xai_key() {
        // xai- + 50 alphanumeric chars
        let key = "xai-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV";
        let (_, detections) = detect(&format!("XAI_API_KEY={key}"), &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::LlmApiKey),
            "should detect xAI API key"
        );
    }

    #[test]
    fn detect_groq_key() {
        // gsk_ + 54 alphanumeric chars
        let key = "gsk_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01";
        let (_, detections) = detect(&format!("GROQ_API_KEY={key}"), &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::LlmApiKey),
            "should detect Groq API key"
        );
    }

    #[test]
    fn detect_perplexity_key() {
        // pplx- + 50 alphanumeric chars
        let key = "pplx-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV";
        let (_, detections) = detect(&format!("PERPLEXITY_API_KEY={key}"), &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::LlmApiKey),
            "should detect Perplexity API key"
        );
    }

    // ── Private keys ──────────────────────────────────────────────────────────

    #[test]
    fn detect_rsa_private_key() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN\nOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP\n-----END RSA PRIVATE KEY-----";
        let (_, detections) = detect(pem, &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::PrivateKey),
            "should detect RSA private key PEM block"
        );
    }

    #[test]
    fn detect_ec_private_key() {
        let pem = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIBkg4LHSK4xJxHGwMTvHIijyOq6dFCFfJlFGsX3SrWscoAoGCCqGSM49\nAwEHoWQDYgAExxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n-----END EC PRIVATE KEY-----";
        let (_, detections) = detect(pem, &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::PrivateKey),
            "should detect EC private key PEM block"
        );
    }

    #[test]
    fn detect_openssh_private_key() {
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nBG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcnNh\nAAAAAwEAAQAAAIEA1234567890abcdefghijklmnopqrstuvwxyz\n-----END OPENSSH PRIVATE KEY-----";
        let (_, detections) = detect(pem, &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::PrivateKey),
            "should detect OpenSSH private key PEM block"
        );
    }

    #[test]
    fn reject_pem_header_only() {
        // Header present but body is too short (< 50 chars between markers)
        let (_, detections) = detect(
            "-----BEGIN RSA PRIVATE KEY-----\nshort\n-----END RSA PRIVATE KEY-----",
            &all_patterns(),
        );
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::PrivateKey),
            "PEM block with < 50 body chars should not match"
        );
    }

    // ── Credential URLs ───────────────────────────────────────────────────────

    #[test]
    fn detect_postgres_credential_url() {
        let (_, detections) = detect(
            "DATABASE_URL=postgres://admin:s3cr3t@db.prod.example.com:5432/mydb",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::CredentialUrl),
            "should detect postgres URL with credentials"
        );
    }

    #[test]
    fn detect_mongodb_credential_url() {
        let (_, detections) = detect(
            "MONGO_URI=mongodb+srv://user:password@cluster0.mongodb.net/production",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::CredentialUrl),
            "should detect MongoDB Atlas URL with credentials"
        );
    }

    #[test]
    fn detect_https_credential_url() {
        let (_, detections) = detect(
            "endpoint: https://deployer:gh_pat_abc123@api.internal.corp/deploy",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::CredentialUrl),
            "should detect HTTPS URL with embedded credentials"
        );
    }

    #[test]
    fn reject_db_url_without_credentials() {
        let (_, detections) = detect(
            "DATABASE_URL=postgres://db.example.com:5432/mydb",
            &all_patterns(),
        );
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::CredentialUrl),
            "DB URL without user:pass@ should not match"
        );
    }

    // ── Cryptocurrency wallets ────────────────────────────────────────────────

    #[test]
    fn detect_ethereum_address() {
        let (_, detections) = detect(
            "wallet: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::CryptoWallet),
            "should detect Ethereum address"
        );
    }

    #[test]
    fn reject_ethereum_too_short() {
        let (_, detections) = detect("addr: 0x742d35Cc6634C0532925a3b844Bc454e4438f4", &all_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::CryptoWallet),
            "0x + 39 hex chars is too short for an Ethereum address"
        );
    }

    #[test]
    fn reject_ethereum_no_prefix() {
        let (_, detections) = detect(
            "addr: 742d35Cc6634C0532925a3b844Bc454e4438f44e",
            &all_patterns(),
        );
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::CryptoWallet),
            "Ethereum address without 0x prefix should not match"
        );
    }

    #[test]
    fn detect_bitcoin_bech32() {
        let (_, detections) = detect(
            "receive: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::CryptoWallet),
            "should detect Bitcoin bech32 address"
        );
    }

    #[test]
    fn reject_bitcoin_bech32_too_short() {
        // bc1 + 38 chars (needs 39 minimum)
        let (_, detections) = detect(
            "addr: bc1qar0srrr7xfkvy5l643lydnw9re59gtzz",
            &all_patterns(),
        );
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::CryptoWallet),
            "bc1 + 38 chars is too short"
        );
    }

    #[test]
    fn detect_bitcoin_legacy_p2pkh() {
        // Genesis block coinbase address
        let (_, detections) = detect(
            "donated to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::CryptoWallet),
            "should detect Bitcoin legacy P2PKH address"
        );
    }

    #[test]
    fn reject_bitcoin_legacy_starts_with_zero() {
        // 0 is not in the base58 alphabet — the regex character class excludes it
        let (_, detections) = detect(
            "addr: 0A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            &all_patterns(),
        );
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::CryptoWallet),
            "address starting with 0 is not valid base58"
        );
    }

    // ── Network identifiers ───────────────────────────────────────────────────

    #[test]
    fn detect_ipv6_address() {
        let (_, detections) = detect(
            "source: 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            &all_patterns(),
        );
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::IPv6Address),
            "should detect public IPv6 address"
        );
    }

    #[test]
    fn reject_ipv6_loopback() {
        let (_, detections) = detect(
            "addr: 0000:0000:0000:0000:0000:0000:0000:0001",
            &all_patterns(),
        );
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::IPv6Address),
            "IPv6 loopback should be rejected"
        );
    }

    #[test]
    fn reject_ipv6_link_local() {
        let (_, detections) = detect(
            "addr: fe80:0000:0000:0000:0202:b3ff:fe1e:8329",
            &all_patterns(),
        );
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::IPv6Address),
            "IPv6 link-local (fe80::/10) should be rejected"
        );
    }

    #[test]
    fn reject_ipv6_multicast() {
        let (_, detections) = detect(
            "addr: ff02:0000:0000:0000:0000:0000:0000:0001",
            &all_patterns(),
        );
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::IPv6Address),
            "IPv6 multicast (ff00::/8) should be rejected"
        );
    }

    #[test]
    fn reject_ipv6_unspecified() {
        let (_, detections) = detect(
            "addr: 0000:0000:0000:0000:0000:0000:0000:0000",
            &all_patterns(),
        );
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::IPv6Address),
            "IPv6 unspecified address should be rejected"
        );
    }

    #[test]
    fn detect_mac_address_colon() {
        let (_, detections) = detect("mac: 00:1A:2B:3C:4D:5E", &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::MacAddress),
            "should detect MAC address with colon separators"
        );
    }

    #[test]
    fn detect_mac_address_hyphen() {
        let (_, detections) = detect("mac: 00-1A-2B-3C-4D-5E", &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::MacAddress),
            "should detect MAC address with hyphen separators"
        );
    }

    #[test]
    fn reject_mac_all_zeros() {
        let (_, detections) = detect("mac: 00:00:00:00:00:00", &all_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::MacAddress),
            "all-zero MAC (unspecified) should be rejected"
        );
    }

    #[test]
    fn reject_mac_broadcast() {
        let (_, detections) = detect("mac: ff:ff:ff:ff:ff:ff", &all_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::MacAddress),
            "broadcast MAC should be rejected"
        );
    }

    // ── Passport MRZ ─────────────────────────────────────────────────────────

    #[test]
    fn detect_passport_mrz_td3() {
        // TD3 two-line MRZ: 44 chars per line
        // Line 1: P + subtype + issuer(3) + name(39)
        // Line 2: doc_no(9) + chk + nationality(3) + dob(6) + chk + sex + expiry(6) + chk + optional(14) + chk + composite
        let mrz = "P<USASMITH<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<\nL898902C36UZA6508066M1401014ZE184226B<<<<<10";
        let (_, detections) = detect(mrz, &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::PassportMrz),
            "should detect TD3 passport MRZ"
        );
    }

    #[test]
    fn reject_mrz_wrong_document_type() {
        // 'V' is a visa, not a passport — our pattern only matches P
        let mrz = "V<USASMITH<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<\nL898902C36UZA6508066M1401014ZE184226B<<<<<10";
        let (_, detections) = detect(mrz, &all_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::PassportMrz),
            "visa MRZ (type V) should not match passport pattern"
        );
    }

    #[test]
    fn reject_mrz_line_too_short() {
        // Line 1 only 43 chars — not a valid TD3 MRZ
        let mrz = "P<USASMITH<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<\nL898902C36UZA6508066M1401014ZE184226B<<<<<10";
        let (_, detections) = detect(mrz, &all_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::PassportMrz),
            "43-char MRZ line should not match"
        );
    }

    // ── UPS tracking ──────────────────────────────────────────────────────────

    #[test]
    fn detect_ups_tracking_number() {
        let (_, detections) = detect("tracking: 1Z999AA10123456784", &all_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::UpsTracking),
            "should detect UPS tracking number"
        );
    }

    #[test]
    fn reject_ups_tracking_too_short() {
        // 1Z + 15 chars (needs 16)
        let (_, detections) = detect("tracking: 1Z999AA101234567", &all_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::UpsTracking),
            "1Z + 15 chars is too short for UPS tracking"
        );
    }

    #[test]
    fn reject_ups_tracking_wrong_prefix() {
        let (_, detections) = detect("tracking: 2Z999AA10123456784", &all_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::UpsTracking),
            "2Z prefix is not a UPS tracking number"
        );
    }
}
