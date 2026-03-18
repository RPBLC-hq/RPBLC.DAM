use crate::stage_regex::Pattern;
use crate::validators::{validate_nie, validate_nif};
use dam_core::PiiType;
use regex::Regex;

/// Spain PII patterns.
pub(crate) fn patterns() -> Vec<Pattern> {
    vec![
        // Spanish NIF (Número de Identificación Fiscal) — 8 digits + check letter
        // Check letter = TABLE[n % 23] where TABLE = "TRWAGMYFPDXBNJZSQVHLCKE"
        // Valid check letters are a subset of A-Z (excludes I, O, U)
        Pattern {
            regex: Regex::new(r"(?i)\b\d{8}[A-HJ-NP-TV-Z]\b").unwrap(),
            pii_type: PiiType::Nif,
            confidence: 0.96,
            validator: Some(validate_nif),
        },
        // Spanish NIE (Número de Identidad de Extranjero) — [XYZ] + 7 digits + check letter
        // Replace X→0, Y→1, Z→2, then same check as NIF
        Pattern {
            regex: Regex::new(r"(?i)\b[XYZ]\d{7}[A-HJ-NP-TV-Z]\b").unwrap(),
            pii_type: PiiType::Nie,
            confidence: 0.96,
            validator: Some(validate_nie),
        },
    ]
}

#[cfg(test)]
mod tests {
    use crate::locales;
    use crate::stage_regex::detect;
    use dam_core::{Locale, PiiType};

    fn es_patterns() -> Vec<crate::stage_regex::Pattern> {
        locales::build_patterns(&[Locale::Global, Locale::Es])
    }

    // --- NIF tests ---

    #[test]
    fn detect_nif_valid() {
        // 12345678 % 23 = 14, TABLE[14] = 'Z'
        let (_, detections) = detect("NIF: 12345678Z", &es_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Nif),
            "should detect valid NIF"
        );
    }

    #[test]
    fn reject_nif_wrong_check() {
        let (_, detections) = detect("NIF: 12345678A", &es_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Nif),
            "should reject NIF with wrong check letter"
        );
    }

    #[test]
    fn detect_nif_case_insensitive() {
        let (_, detections) = detect("nif: 12345678z", &es_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Nif),
            "should detect NIF case-insensitively"
        );
    }

    // --- NIE tests ---

    #[test]
    fn detect_nie_x_prefix() {
        // X1234567: replace X→0 → 01234567=1234567, 1234567%23=19, TABLE[19]='L'
        let (_, detections) = detect("NIE: X1234567L", &es_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Nie),
            "should detect NIE with X prefix"
        );
    }

    #[test]
    fn detect_nie_y_prefix() {
        // Y1234567: replace Y→1 → 11234567, 11234567%23=?
        // 23*488461=11234603 → 11234567-11234603 negative, try 23*488459=11234557
        // 11234567-11234557=10, TABLE[10]='X'
        let (_, detections) = detect("NIE: Y1234567X", &es_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Nie),
            "should detect NIE with Y prefix"
        );
    }

    #[test]
    fn detect_nie_z_prefix() {
        // Z1234567: replace Z→2 → 21234567, 21234567%23=?
        // 23*923242=21234566 → 21234567-21234566=1, TABLE[1]='R'
        let (_, detections) = detect("NIE: Z1234567R", &es_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Nie),
            "should detect NIE with Z prefix"
        );
    }

    #[test]
    fn reject_nie_wrong_check() {
        let (_, detections) = detect("NIE: X1234567A", &es_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Nie),
            "should reject NIE with wrong check letter"
        );
    }

    // --- Locale isolation ---

    #[test]
    fn nif_not_detected_without_es_locale() {
        let patterns = locales::build_patterns(&[Locale::Global]);
        let (_, detections) = detect("NIF: 12345678Z", &patterns);
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Nif),
            "NIF should not detect without Spain locale"
        );
    }

    #[test]
    fn nie_not_detected_without_es_locale() {
        let patterns = locales::build_patterns(&[Locale::Global]);
        let (_, detections) = detect("NIE: X1234567L", &patterns);
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Nie),
            "NIE should not detect without Spain locale"
        );
    }
}
