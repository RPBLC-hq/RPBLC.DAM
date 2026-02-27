use crate::stage_regex::Pattern;
use crate::validators::validate_cpf;
use dam_core::PiiType;
use regex::Regex;

/// Brazil PII patterns.
pub(crate) fn patterns() -> Vec<Pattern> {
    vec![
        // Brazilian CPF (Cadastro de Pessoas Físicas) — ddd.ddd.ddd-dd
        // Double mod-11 check: two-digit suffix validates first 9 digits
        Pattern {
            regex: Regex::new(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b").unwrap(),
            pii_type: PiiType::Cpf,
            confidence: 0.97,
            validator: Some(validate_cpf),
        },
    ]
}

#[cfg(test)]
mod tests {
    use crate::locales;
    use crate::stage_regex::detect;
    use dam_core::{Locale, PiiType};

    fn br_patterns() -> Vec<crate::stage_regex::Pattern> {
        locales::build_patterns(&[Locale::Global, Locale::Br])
    }

    // --- CPF tests ---

    #[test]
    fn detect_cpf_valid() {
        // 123.456.789-09: first check=0 (d[9]), second check=9 (d[10]) ✓
        let (_, detections) = detect("CPF: 123.456.789-09", &br_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Cpf),
            "should detect valid CPF"
        );
    }

    #[test]
    fn reject_cpf_wrong_check() {
        // 123.456.789-10 — d[9]=1 but expected 0
        let (_, detections) = detect("CPF: 123.456.789-10", &br_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Cpf),
            "should reject CPF with wrong check digits"
        );
    }

    #[test]
    fn reject_cpf_all_same_digits() {
        // 111.111.111-11 — all same digit, always rejected
        let (_, detections) = detect("CPF: 111.111.111-11", &br_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Cpf),
            "should reject CPF with all same digits"
        );
    }

    #[test]
    fn reject_cpf_zeroes() {
        // 000.000.000-00 — all zeros, all-same-digit rejection
        let (_, detections) = detect("CPF: 000.000.000-00", &br_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Cpf),
            "should reject CPF with all zeros"
        );
    }

    // --- Locale isolation ---

    #[test]
    fn cpf_not_detected_without_br_locale() {
        let patterns = locales::build_patterns(&[Locale::Global]);
        let (_, detections) = detect("CPF: 123.456.789-09", &patterns);
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Cpf),
            "CPF should not detect without Brazil locale"
        );
    }
}
