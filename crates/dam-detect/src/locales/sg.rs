use crate::stage_regex::Pattern;
use crate::validators::validate_nric;
use dam_core::PiiType;
use regex::Regex;

/// Singapore PII patterns.
pub(crate) fn patterns() -> Vec<Pattern> {
    vec![
        // Singapore NRIC/FIN — prefix [STFGM] + 7 digits + MOD-11 check letter
        // S/T = citizens/PRs born in Singapore; F/G = foreigners; M = recent work pass holders
        Pattern {
            regex: Regex::new(r"(?i)\b[STFGM]\d{7}[A-Z]\b").unwrap(),
            pii_type: PiiType::Nric,
            confidence: 0.97,
            validator: Some(validate_nric),
        },
    ]
}

#[cfg(test)]
mod tests {
    use crate::locales;
    use crate::stage_regex::detect;
    use dam_core::{Locale, PiiType};

    fn sg_patterns() -> Vec<crate::stage_regex::Pattern> {
        locales::build_patterns(&[Locale::Global, Locale::Sg])
    }

    // --- S-series (citizen/PR born in Singapore) ---

    #[test]
    fn detect_nric_s_series() {
        // S1234567D: sum=106, S offset=0, 106%11=7, S_LETTERS[7]='D'
        let (_, detections) = detect("NRIC: S1234567D", &sg_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Nric),
            "should detect S-series NRIC"
        );
    }

    #[test]
    fn reject_nric_s_wrong_check() {
        let (_, detections) = detect("NRIC: S1234567E", &sg_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Nric),
            "should reject S-series NRIC with wrong check letter"
        );
    }

    // --- T-series ---

    #[test]
    fn detect_nric_t_series() {
        // T1234567G: sum=106, T offset=4, (106+4)%11=0, T_LETTERS[0]='G'
        let (_, detections) = detect("NRIC: T1234567G", &sg_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Nric),
            "should detect T-series NRIC"
        );
    }

    #[test]
    fn reject_nric_t_wrong_check() {
        let (_, detections) = detect("NRIC: T1234567A", &sg_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Nric),
            "should reject T-series NRIC with wrong check letter"
        );
    }

    // --- F-series (foreigner) ---

    #[test]
    fn detect_nric_f_series() {
        // F1234567N: sum=106, F offset=0, 106%11=7, F_LETTERS[7]='N'
        let (_, detections) = detect("NRIC: F1234567N", &sg_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Nric),
            "should detect F-series FIN"
        );
    }

    #[test]
    fn reject_nric_f_wrong_check() {
        let (_, detections) = detect("NRIC: F1234567A", &sg_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Nric),
            "should reject F-series FIN with wrong check letter"
        );
    }

    // --- G-series (foreigner, issued after 2000) ---

    #[test]
    fn detect_nric_g_series() {
        // G1234567R: sum=106, G offset=4, (106+4)%11=0, G_LETTERS[0]='R'
        let (_, detections) = detect("NRIC: G1234567R", &sg_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Nric),
            "should detect G-series FIN"
        );
    }

    #[test]
    fn reject_nric_g_wrong_check() {
        let (_, detections) = detect("NRIC: G1234567A", &sg_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Nric),
            "should reject G-series FIN with wrong check letter"
        );
    }

    // --- M-series (recent work pass holder) ---

    #[test]
    fn detect_nric_m_series() {
        // M1234567X: sum=106, M offset=3, (106+3)%11=10, M_LETTERS[10]='X'
        let (_, detections) = detect("NRIC: M1234567X", &sg_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::Nric),
            "should detect M-series FIN"
        );
    }

    #[test]
    fn reject_nric_m_wrong_check() {
        let (_, detections) = detect("NRIC: M1234567A", &sg_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Nric),
            "should reject M-series FIN with wrong check letter"
        );
    }

    // --- Locale isolation ---

    #[test]
    fn nric_not_detected_without_sg_locale() {
        let patterns = locales::build_patterns(&[Locale::Global]);
        let (_, detections) = detect("NRIC: S1234567D", &patterns);
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::Nric),
            "NRIC should not detect without Singapore locale"
        );
    }
}
