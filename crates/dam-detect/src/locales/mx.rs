use crate::stage_regex::Pattern;
use crate::validators::validate_curp;
use dam_core::PiiType;
use regex::Regex;

/// Mexico PII patterns.
pub(crate) fn patterns() -> Vec<Pattern> {
    vec![
        // Mexican CURP (Clave Única de Registro de Población) — 18-character identity code
        // Structure: [A-Z][vowel][A-Z]{2} + YYMMDD + [HM] + state(2) + consonants(3) + diff + check
        // Check digit = (sum of char_value * 1-indexed position for chars 1-17) % 10
        Pattern {
            regex: Regex::new(r"(?i)\b[A-Z][AEIOU][A-Z]{2}\d{6}[HM][A-Z]{2}[A-Z]{3}[0-9A-Z]\d\b")
                .unwrap(),
            pii_type: PiiType::Curp,
            confidence: 0.95,
            validator: Some(validate_curp),
        },
    ]
}

#[cfg(test)]
mod tests {
    use crate::locales;
    use crate::stage_regex::detect;
    use dam_core::{Locale, PiiType};

    fn mx_patterns() -> Vec<crate::stage_regex::Pattern> {
        locales::build_patterns(&[Locale::Global, Locale::Mx])
    }

    // --- CURP tests ---

    #[test]
    fn detect_curp_valid() {
        // AAEA010101HDFFFF09
        // sum = Σ char_value(s[i]) * (i+1) for i in 0..17 = 1349
        // check = 1349 % 10 = 9 ✓
        let (_, detections) = detect("CURP: AAEA010101HDFFFF09", &mx_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Curp),
            "should detect valid CURP"
        );
    }

    #[test]
    fn reject_curp_wrong_check() {
        // Same CURP but with check digit 1 instead of 9
        let (_, detections) = detect("CURP: AAEA010101HDFFFF01", &mx_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Curp),
            "should reject CURP with wrong check digit"
        );
    }

    #[test]
    fn detect_curp_case_insensitive() {
        let (_, detections) = detect("curp: aaea010101hdffff09", &mx_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Curp),
            "should detect CURP case-insensitively"
        );
    }

    // --- Locale isolation ---

    #[test]
    fn curp_not_detected_without_mx_locale() {
        let patterns = locales::build_patterns(&[Locale::Global]);
        let (_, detections) = detect("CURP: AAEA010101HDFFFF09", &patterns);
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Curp),
            "CURP should not detect without Mexico locale"
        );
    }
}
