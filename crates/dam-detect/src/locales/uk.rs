use crate::stage_regex::Pattern;
use crate::validators::{validate_dvla_license, validate_nhs_mod11, validate_ni_prefix};
use dam_core::PiiType;
use regex::Regex;

/// United Kingdom PII patterns.
pub(crate) fn patterns() -> Vec<Pattern> {
    vec![
        // National Insurance Number — 2 letters + 6 digits + 1 letter (A-D)
        Pattern {
            regex: Regex::new(r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b").unwrap(),
            pii_type: PiiType::NiNumber,
            confidence: 0.90,
            validator: Some(validate_ni_prefix),
        },
        // NHS Number — 10 digits with optional separators (3-3-4 format)
        Pattern {
            regex: Regex::new(r"\b\d{3}[-\s]?\d{3}[-\s]?\d{4}\b").unwrap(),
            pii_type: PiiType::NhsNumber,
            confidence: 0.90,
            validator: Some(validate_nhs_mod11),
        },
        // UK Driving Licence (DVLA) — 16 alphanumeric characters
        Pattern {
            regex: Regex::new(r"\b[A-Z9]{5}\d{6}[A-Z9]{2}[A-Z0-9]{3}\b").unwrap(),
            pii_type: PiiType::DriversLicense,
            confidence: 0.85,
            validator: Some(validate_dvla_license),
        },
    ]
}

#[cfg(test)]
mod tests {
    use crate::locales;
    use crate::stage_regex::detect;
    use dam_core::{Locale, PiiType};

    fn uk_patterns() -> Vec<crate::stage_regex::Pattern> {
        locales::build_patterns(&[Locale::Global, Locale::Uk])
    }

    // --- NI Number tests ---

    #[test]
    fn detect_ni_number() {
        let (_, detections) = detect("NI: AB123456C", &uk_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::NiNumber),
            "should detect NI number"
        );
    }

    #[test]
    fn detect_ni_suffix_d() {
        let (_, detections) = detect("NI: CE654321D", &uk_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::NiNumber),
            "should detect NI number with suffix D"
        );
    }

    #[test]
    fn reject_ni_invalid_prefix_bg() {
        let (_, detections) = detect("NI: BG123456A", &uk_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::NiNumber),
            "should reject NI with BG prefix"
        );
    }

    #[test]
    fn reject_ni_invalid_prefix_gb() {
        let (_, detections) = detect("NI: GB123456A", &uk_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::NiNumber),
            "should reject NI with GB prefix"
        );
    }

    #[test]
    fn reject_ni_first_letter_d() {
        let (_, detections) = detect("NI: DA123456A", &uk_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::NiNumber),
            "should reject NI starting with D"
        );
    }

    #[test]
    fn reject_ni_suffix_e() {
        // Suffix must be A-D; E is invalid. Regex already excludes this.
        let (_, detections) = detect("NI: AB123456E", &uk_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::NiNumber),
            "should reject NI with suffix E"
        );
    }

    // --- NHS Number tests ---

    #[test]
    fn detect_nhs_number() {
        let (_, detections) = detect("NHS: 9434765919", &uk_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::NhsNumber),
            "should detect NHS number"
        );
    }

    #[test]
    fn detect_nhs_with_spaces() {
        let (_, detections) = detect("NHS: 943 476 5919", &uk_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::NhsNumber),
            "should detect NHS number with spaces"
        );
    }

    #[test]
    fn reject_nhs_invalid_check() {
        let (_, detections) = detect("NHS: 9434765910", &uk_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::NhsNumber),
            "should reject NHS number with wrong check digit"
        );
    }

    // --- DVLA Licence tests ---

    #[test]
    fn detect_dvla_licence() {
        let (_, detections) = detect("DL: MORGA657054SM9IJ", &uk_patterns());
        assert!(
            detections
                .iter()
                .any(|d| d.pii_type == PiiType::DriversLicense),
            "should detect DVLA licence"
        );
    }

    #[test]
    fn detect_dvla_male() {
        let (_, detections) = detect("DL: SMITH701010JJ9AA", &uk_patterns());
        assert!(
            detections
                .iter()
                .any(|d| d.pii_type == PiiType::DriversLicense),
            "should detect male DVLA licence"
        );
    }

    #[test]
    fn reject_dvla_invalid_month() {
        let (_, detections) = detect("DL: SMITH713010JJ9AA", &uk_patterns());
        assert!(
            !detections
                .iter()
                .any(|d| d.pii_type == PiiType::DriversLicense),
            "should reject DVLA with invalid month"
        );
    }

    #[test]
    fn reject_dvla_invalid_day() {
        let (_, detections) = detect("DL: SMITH701000JJ9AA", &uk_patterns());
        assert!(
            !detections
                .iter()
                .any(|d| d.pii_type == PiiType::DriversLicense),
            "should reject DVLA with day 00"
        );
    }

    // --- Edge cases ---

    #[test]
    fn detect_nhs_with_dashes() {
        let (_, detections) = detect("NHS: 943-476-5919", &uk_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::NhsNumber),
            "should detect NHS number with dashes"
        );
    }

    #[test]
    fn reject_ni_remaining_excluded_prefixes() {
        // NK, KN, TN, NT also excluded
        let (_, detections) = detect("NI: NK123456A", &uk_patterns());
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::NiNumber));

        let (_, detections) = detect("NI: TN123456A", &uk_patterns());
        assert!(!detections.iter().any(|d| d.pii_type == PiiType::NiNumber));
    }

    #[test]
    fn detect_dvla_female_boundary_months() {
        // Month 51 = female January
        let (_, detections) = detect("DL: SMITH751010JJ9AA", &uk_patterns());
        assert!(
            detections
                .iter()
                .any(|d| d.pii_type == PiiType::DriversLicense),
            "should detect DVLA with female month 51"
        );

        // Month 62 = female December
        let (_, detections) = detect("DL: SMITH762010JJ9AA", &uk_patterns());
        assert!(
            detections
                .iter()
                .any(|d| d.pii_type == PiiType::DriversLicense),
            "should detect DVLA with female month 62"
        );
    }

    #[test]
    fn reject_dvla_month_in_gap() {
        // Month 49 is between male (1-12) and female (51-62) — invalid
        let (_, detections) = detect("DL: SMITH749010JJ9AA", &uk_patterns());
        assert!(
            !detections
                .iter()
                .any(|d| d.pii_type == PiiType::DriversLicense),
            "should reject DVLA with month 49"
        );
    }

    #[test]
    fn nhs_not_detected_without_uk_locale() {
        // Without UK locale, NHS pattern should not be active
        let patterns = locales::build_patterns(&[Locale::Global]);
        let (_, detections) = detect("NHS: 9434765919", &patterns);
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::NhsNumber),
            "NHS should not detect without UK locale"
        );
    }
}
