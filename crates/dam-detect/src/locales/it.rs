use crate::stage_regex::Pattern;
use crate::validators::validate_codice_fiscale;
use dam_core::PiiType;
use regex::Regex;

/// Italy PII patterns.
pub(crate) fn patterns() -> Vec<Pattern> {
    vec![
        // Italian Codice Fiscale — 6 letters + 2 digits + month letter + 2 digits + municipality + 3 digits + check
        // Month letters: A=Jan, B=Feb, C=Mar, D=Apr, E=May, H=Jun, L=Jul, M=Aug, P=Sep, R=Oct, S=Nov, T=Dec
        Pattern {
            regex: Regex::new(r"(?i)\b[A-Z]{6}\d{2}[ABCDEHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b").unwrap(),
            pii_type: PiiType::CodiceFiscale,
            confidence: 0.95,
            validator: Some(validate_codice_fiscale),
        },
    ]
}

#[cfg(test)]
mod tests {
    use crate::locales;
    use crate::stage_regex::detect;
    use dam_core::{Locale, PiiType};

    fn it_patterns() -> Vec<crate::stage_regex::Pattern> {
        locales::build_patterns(&[Locale::Global, Locale::It])
    }

    // --- Codice Fiscale tests ---

    #[test]
    fn detect_codice_fiscale() {
        // RSSMRA85T10A562S — Mario Rossi born 10 Nov 1985 in Rome
        // Verified: sum=122, 122%26=18, 'A'+18='S' ✓
        let (_, detections) = detect("CF: RSSMRA85T10A562S", &it_patterns());
        assert!(
            detections
                .iter()
                .any(|d| d.pii_type == PiiType::CodiceFiscale),
            "should detect valid Codice Fiscale"
        );
    }

    #[test]
    fn reject_codice_fiscale_wrong_check() {
        let (_, detections) = detect("CF: RSSMRA85T10A562X", &it_patterns());
        assert!(
            !detections
                .iter()
                .any(|d| d.pii_type == PiiType::CodiceFiscale),
            "should reject Codice Fiscale with wrong check letter"
        );
    }

    #[test]
    fn detect_codice_fiscale_case_insensitive() {
        let (_, detections) = detect("CF: rssmra85t10a562s", &it_patterns());
        assert!(
            detections
                .iter()
                .any(|d| d.pii_type == PiiType::CodiceFiscale),
            "should detect Codice Fiscale case-insensitively"
        );
    }

    #[test]
    fn reject_codice_fiscale_invalid_month() {
        // Month letter 'O' is not valid (valid: ABCDEHLMPRST)
        let (_, detections) = detect("CF: RSSMRA85O10A562S", &it_patterns());
        assert!(
            !detections
                .iter()
                .any(|d| d.pii_type == PiiType::CodiceFiscale),
            "should reject Codice Fiscale with invalid month letter"
        );
    }

    // --- Locale isolation ---

    #[test]
    fn cf_not_detected_without_it_locale() {
        let patterns = locales::build_patterns(&[Locale::Global]);
        let (_, detections) = detect("CF: RSSMRA85T10A562S", &patterns);
        assert!(
            !detections
                .iter()
                .any(|d| d.pii_type == PiiType::CodiceFiscale),
            "Codice Fiscale should not detect without Italy locale"
        );
    }
}
