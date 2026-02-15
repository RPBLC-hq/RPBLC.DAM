use crate::stage_regex::Pattern;
use crate::validators::validate_luhn_sin;
use dam_core::PiiType;
use regex::Regex;

/// Canada-specific PII patterns.
pub(crate) fn patterns() -> Vec<Pattern> {
    vec![
        // Social Insurance Number (SIN) — 9 digits with optional separators
        Pattern {
            regex: Regex::new(r"\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b").unwrap(),
            pii_type: PiiType::Sin,
            confidence: 0.85,
            validator: Some(validate_luhn_sin),
        },
        // Canadian postal code — letter-digit-letter (space/dash optional) digit-letter-digit
        // Excludes D, F, I, O, Q, U in any position; W and Z only in second/third positions
        Pattern {
            regex: Regex::new(
                r"(?i)\b[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z][\s-]?\d[ABCEGHJ-NPRSTV-Z]\d\b",
            )
            .unwrap(),
            pii_type: PiiType::PostalCode,
            confidence: 0.80,
            validator: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use crate::locales;
    use crate::stage_regex::detect;
    use dam_core::{Locale, PiiType};

    fn ca_patterns() -> Vec<crate::stage_regex::Pattern> {
        locales::build_patterns(&[Locale::Global, Locale::Ca])
    }

    // --- SIN tests ---

    #[test]
    fn detect_sin_with_dashes() {
        let (_, detections) = detect("SIN: 130-692-544", &ca_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Sin),
            "should detect SIN with dashes"
        );
    }

    #[test]
    fn detect_sin_with_spaces() {
        let (_, detections) = detect("SIN: 130 692 544", &ca_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Sin),
            "should detect SIN with spaces"
        );
    }

    #[test]
    fn detect_sin_no_separators() {
        let (_, detections) = detect("SIN: 130692544", &ca_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Sin),
            "should detect SIN without separators"
        );
    }

    #[test]
    fn reject_sin_fails_luhn() {
        let (_, detections) = detect("SIN: 123-456-780", &ca_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Sin),
            "should reject SIN that fails Luhn"
        );
    }

    #[test]
    fn reject_sin_starts_with_zero() {
        // 046-454-286 passes Luhn but starts with 0
        let (_, detections) = detect("SIN: 046-454-286", &ca_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Sin),
            "should reject SIN starting with 0"
        );
    }

    #[test]
    fn reject_sin_starts_with_eight() {
        let (_, detections) = detect("SIN: 800-000-002", &ca_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Sin),
            "should reject SIN starting with 8"
        );
    }

    // --- Postal code tests ---

    #[test]
    fn detect_postal_code_with_space() {
        let (_, detections) = detect("Postal: K1A 0B1", &ca_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::PostalCode),
            "should detect postal code with space"
        );
    }

    #[test]
    fn detect_postal_code_without_space() {
        let (_, detections) = detect("Postal: K1A0B1", &ca_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::PostalCode),
            "should detect postal code without space"
        );
    }

    #[test]
    fn detect_postal_code_with_dash() {
        let (_, detections) = detect("Postal: K1A-0B1", &ca_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::PostalCode),
            "should detect postal code with dash"
        );
    }

    #[test]
    fn detect_postal_code_lowercase() {
        let (_, detections) = detect("Postal: k1a 0b1", &ca_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::PostalCode),
            "should detect lowercase postal code"
        );
    }

    #[test]
    fn reject_postal_code_invalid_first_letter() {
        // D, F, I, O, Q, U, W, Z are not valid first letters
        let (_, detections) = detect("Postal: D1A 0B1", &ca_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::PostalCode),
            "should reject postal code starting with D"
        );
    }

    #[test]
    fn reject_postal_code_invalid_letters() {
        // I and O are never valid in postal codes
        let (_, detections) = detect("Postal: K1I 0B1", &ca_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::PostalCode),
            "should reject postal code with I"
        );
    }
}
