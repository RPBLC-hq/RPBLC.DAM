use crate::stage_regex::Pattern;
use crate::validators::{validate_dea_number, validate_ssn};
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
        // DEA registration number — 2-letter code + 7 digits, position-7 check digit
        // First letter: registrant type (A-P, R-V, X-Z); second letter: last-name initial or '9'
        Pattern {
            regex: Regex::new(r"(?i)\b[A-PR-VXYZ][A-Z9]\d{7}\b").unwrap(),
            pii_type: PiiType::DeaNumber,
            confidence: 0.88,
            validator: Some(validate_dea_number),
        },
    ]
}

#[cfg(test)]
mod tests {
    use crate::locales;
    use crate::stage_regex::detect;
    use dam_core::{Locale, PiiType};

    fn us_patterns() -> Vec<crate::stage_regex::Pattern> {
        locales::build_patterns(&[Locale::Global, Locale::Us])
    }

    // --- DEA number tests ---

    #[test]
    fn detect_dea_number() {
        // AB1234563: (1+3+5) + 2*(2+4+6) = 33, 33%10=3=d[6] ✓
        let (_, detections) = detect("DEA: AB1234563", &us_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::DeaNumber),
            "should detect valid DEA number"
        );
    }

    #[test]
    fn reject_dea_wrong_check() {
        let (_, detections) = detect("DEA: AB1234560", &us_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::DeaNumber),
            "should reject DEA with wrong check digit"
        );
    }

    #[test]
    fn dea_not_detected_without_us_locale() {
        let patterns = locales::build_patterns(&[Locale::Global]);
        let (_, detections) = detect("DEA: AB1234563", &patterns);
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::DeaNumber),
            "DEA should not detect without US locale"
        );
    }
}
