use crate::stage_regex::Pattern;
use crate::validators::{validate_eu_vat, validate_swift_bic};
use dam_core::PiiType;
use regex::Regex;

/// EU-wide PII patterns (not specific to any single EU member state).
pub(crate) fn patterns() -> Vec<Pattern> {
    vec![
        // EU VAT identification number — country prefix (2 letters) + 2-13 alphanumeric chars
        Pattern {
            regex: Regex::new(
                r"\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[A-Z0-9]{2,13}\b",
            )
            .unwrap(),
            pii_type: PiiType::VatNumber,
            confidence: 0.85,
            validator: Some(validate_eu_vat),
        },
        // SWIFT/BIC code — 8 or 11 alphanumeric characters
        // 4 bank code (letters) + 2 country (letters) + 2 location (alphanumeric) + optional 3 branch
        Pattern {
            regex: Regex::new(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b").unwrap(),
            pii_type: PiiType::SwiftBic,
            confidence: 0.80,
            validator: Some(validate_swift_bic),
        },
    ]
}

#[cfg(test)]
mod tests {
    use crate::locales;
    use crate::stage_regex::detect;
    use dam_core::{Locale, PiiType};

    fn eu_patterns() -> Vec<crate::stage_regex::Pattern> {
        locales::build_patterns(&[Locale::Global, Locale::Eu])
    }

    // --- VAT Number tests ---

    #[test]
    fn detect_vat_de() {
        let (_, detections) = detect("VAT: DE123456789", &eu_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::VatNumber),
            "should detect German VAT"
        );
    }

    #[test]
    fn detect_vat_at() {
        let (_, detections) = detect("VAT: ATU12345678", &eu_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::VatNumber),
            "should detect Austrian VAT"
        );
    }

    #[test]
    fn detect_vat_fr() {
        let (_, detections) = detect("VAT: FR12345678901", &eu_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::VatNumber),
            "should detect French VAT"
        );
    }

    #[test]
    fn detect_vat_be() {
        let (_, detections) = detect("VAT: BE0123456789", &eu_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::VatNumber),
            "should detect Belgian VAT"
        );
    }

    #[test]
    fn detect_vat_nl() {
        let (_, detections) = detect("VAT: NL123456789B01", &eu_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::VatNumber),
            "should detect Dutch VAT"
        );
    }

    #[test]
    fn reject_vat_wrong_length() {
        // DE needs exactly 9 digits after prefix
        let (_, detections) = detect("VAT: DE12345678", &eu_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::VatNumber),
            "should reject DE VAT with only 8 digits"
        );
    }

    #[test]
    fn reject_vat_unknown_country() {
        // XX is not a valid EU VAT country prefix — regex rejects
        let (_, detections) = detect("VAT: XX123456789", &eu_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::VatNumber),
            "should reject VAT with unknown country prefix"
        );
    }

    #[test]
    fn reject_vat_gb_post_brexit() {
        // GB is no longer an EU VAT prefix
        let (_, detections) = detect("VAT: GB123456789", &eu_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::VatNumber),
            "should reject GB VAT (post-Brexit)"
        );
    }

    // --- SWIFT/BIC tests ---

    #[test]
    fn detect_swift_8_char() {
        let (_, detections) = detect("SWIFT: DEUTDEFF", &eu_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::SwiftBic),
            "should detect 8-char SWIFT code"
        );
    }

    #[test]
    fn detect_swift_11_char() {
        let (_, detections) = detect("SWIFT: DEUTDEFF500", &eu_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::SwiftBic),
            "should detect 11-char SWIFT code"
        );
    }

    #[test]
    fn detect_swift_bnp_paribas() {
        let (_, detections) = detect("BIC: BNPAFRPP", &eu_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::SwiftBic),
            "should detect BNP Paribas SWIFT"
        );
    }

    #[test]
    fn detect_swift_jpmorgan() {
        let (_, detections) = detect("BIC: CHASUS33", &eu_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::SwiftBic),
            "should detect JPMorgan Chase SWIFT"
        );
    }

    #[test]
    fn reject_swift_invalid_country() {
        let (_, detections) = detect("SWIFT: DEUTXXFF", &eu_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::SwiftBic),
            "should reject SWIFT with invalid country code"
        );
    }

    #[test]
    fn reject_swift_wrong_length() {
        // 10 chars is neither 8 nor 11
        let (_, detections) = detect("SWIFT: DEUTDEFF50", &eu_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::SwiftBic),
            "should reject SWIFT with wrong length"
        );
    }

    // --- Edge cases ---

    #[test]
    fn reject_swift_common_word() {
        // TESTXXAB — 8 uppercase letters but XX is not a valid country
        let (_, detections) = detect("word: TESTXXAB", &eu_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::SwiftBic),
            "should reject 8-letter word with invalid country code"
        );
    }

    #[test]
    fn vat_not_detected_without_eu_locale() {
        let patterns = locales::build_patterns(&[Locale::Global]);
        let (_, detections) = detect("VAT: DE123456789", &patterns);
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::VatNumber),
            "VAT should not detect without EU locale"
        );
    }

    #[test]
    fn detect_vat_es_mixed_format() {
        // Spanish VAT can have letters: ESX1234567A
        let (_, detections) = detect("VAT: ESX12345678", &eu_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::VatNumber),
            "should detect Spanish VAT with mixed format"
        );
    }
}
