use crate::stage_regex::Pattern;
use crate::validators::{validate_icao_check, validate_steuer_id};
use dam_core::PiiType;
use regex::Regex;

/// Germany-specific PII patterns.
pub(crate) fn patterns() -> Vec<Pattern> {
    vec![
        // Personalausweis (national ID card) — 10-character ICAO format
        // First char is a letter from the valid set, followed by 8 alphanumeric + 1 check digit
        Pattern {
            regex: Regex::new(r"(?i)\b[CFGHJKLMNPRTVWXYZ][0-9CFGHJKLMNPRTVWXYZ]{8}\d\b").unwrap(),
            pii_type: PiiType::NationalId,
            confidence: 0.85,
            validator: Some(validate_icao_check),
        },
        // Steuer-ID (tax identification number) — 11 digits, first digit not 0
        Pattern {
            regex: Regex::new(r"\b[1-9]\d{10}\b").unwrap(),
            pii_type: PiiType::TaxId,
            confidence: 0.85,
            validator: Some(validate_steuer_id),
        },
    ]
}

#[cfg(test)]
mod tests {
    use crate::locales;
    use crate::stage_regex::detect;
    use dam_core::{Locale, PiiType};

    fn de_patterns() -> Vec<crate::stage_regex::Pattern> {
        locales::build_patterns(&[Locale::Global, Locale::De])
    }

    // --- Personalausweis tests ---

    #[test]
    fn detect_personalausweis() {
        // T22000129 with check digit 3
        let (_, detections) = detect("ID: T220001293", &de_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::NationalId),
            "should detect Personalausweis"
        );
    }

    #[test]
    fn reject_personalausweis_wrong_check() {
        let (_, detections) = detect("ID: T220001290", &de_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::NationalId),
            "should reject Personalausweis with wrong check digit"
        );
    }

    #[test]
    fn reject_personalausweis_invalid_first_char() {
        // 'A' is not in the valid first-character set — regex rejects
        let (_, detections) = detect("ID: A220001293", &de_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::NationalId),
            "should reject Personalausweis starting with A"
        );
    }

    // --- Steuer-ID tests ---

    #[test]
    fn detect_steuer_id() {
        let (_, detections) = detect("Tax ID: 65929970489", &de_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::TaxId),
            "should detect Steuer-ID"
        );
    }

    #[test]
    fn reject_steuer_id_starts_with_zero() {
        // Regex already prevents this (first digit [1-9])
        let (_, detections) = detect("Tax ID: 05929970489", &de_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::TaxId),
            "should reject Steuer-ID starting with 0"
        );
    }

    #[test]
    fn reject_steuer_id_all_same_digits() {
        // 11111111111 — fails digit frequency check
        let (_, detections) = detect("Tax ID: 11111111111", &de_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::TaxId),
            "should reject Steuer-ID with all same digits"
        );
    }

    #[test]
    fn reject_steuer_id_wrong_check_digit() {
        // Change last digit of valid 65929970489 -> 65929970480
        let (_, detections) = detect("Tax ID: 65929970480", &de_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::TaxId),
            "should reject Steuer-ID with wrong check digit"
        );
    }

    #[test]
    fn reject_steuer_id_too_short() {
        let (_, detections) = detect("Tax ID: 6592997048", &de_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::TaxId),
            "should not detect 10-digit Steuer-ID"
        );
    }

    #[test]
    fn reject_steuer_id_too_long() {
        // 12 digits should not match as a single Steuer-ID
        let (_, detections) = detect("Tax ID: 659299704899", &de_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::TaxId),
            "should not detect 12-digit Steuer-ID"
        );
    }
}
