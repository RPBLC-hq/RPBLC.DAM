use crate::stage_regex::Pattern;
use crate::validators::validate_emirates_id;
use dam_core::PiiType;
use regex::Regex;

/// UAE PII patterns.
pub(crate) fn patterns() -> Vec<Pattern> {
    vec![
        // UAE Emirates ID — 784-YYYY-NNNNNNN-C format (15 digits, Luhn-validated)
        // 784 = UAE country code; optional hyphens or spaces as separators
        Pattern {
            regex: Regex::new(r"\b784[-\s]?\d{4}[-\s]?\d{7}[-\s]?\d\b").unwrap(),
            pii_type: PiiType::EmiratesId,
            confidence: 0.97,
            validator: Some(validate_emirates_id),
        },
    ]
}

#[cfg(test)]
mod tests {
    use crate::locales;
    use crate::stage_regex::detect;
    use dam_core::{Locale, PiiType};

    fn ae_patterns() -> Vec<crate::stage_regex::Pattern> {
        locales::build_patterns(&[Locale::Global, Locale::Ae])
    }

    // --- Emirates ID tests ---

    #[test]
    fn detect_emirates_id_with_hyphens() {
        // 784-1234-1234567-2: stripped = 784123412345672, Luhn sum=60, 60%10=0 ✓
        let (_, detections) = detect("EID: 784-1234-1234567-2", &ae_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::EmiratesId),
            "should detect Emirates ID with hyphens"
        );
    }

    #[test]
    fn detect_emirates_id_no_separators() {
        let (_, detections) = detect("EID: 784123412345672", &ae_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::EmiratesId),
            "should detect Emirates ID without separators"
        );
    }

    #[test]
    fn reject_emirates_id_luhn_fail() {
        // 784-1234-1234567-0: Luhn sum=58, 58%10=8 ≠ 0
        let (_, detections) = detect("EID: 784-1234-1234567-0", &ae_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::EmiratesId),
            "should reject Emirates ID with invalid Luhn check"
        );
    }

    // --- Locale isolation ---

    #[test]
    fn emirates_id_not_detected_without_ae_locale() {
        let patterns = locales::build_patterns(&[Locale::Global]);
        let (_, detections) = detect("EID: 784-1234-1234567-2", &patterns);
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::EmiratesId),
            "Emirates ID should not detect without UAE locale"
        );
    }
}
