use crate::stage_regex::Pattern;
use crate::validators::validate_nir_key;
use dam_core::PiiType;
use regex::Regex;

/// France-specific PII patterns.
pub(crate) fn patterns() -> Vec<Pattern> {
    vec![
        // INSEE/NIR (numéro de sécurité sociale) — 15 characters
        // Format: sex(1) + year(2) + month(2) + dept(2, may be 2A/2B) + commune(3) + order(3) + key(2)
        Pattern {
            regex: Regex::new(
                r"\b[12]\d{2}(?:0[1-9]|1[0-2]|[2-9]\d)(?:\d{2}|2[AB])\d{3}\d{3}\d{2}\b",
            )
            .unwrap(),
            pii_type: PiiType::InseeNir,
            confidence: 0.90,
            validator: Some(validate_nir_key),
        },
    ]
}

#[cfg(test)]
mod tests {
    use crate::locales;
    use crate::stage_regex::detect;
    use dam_core::{Locale, PiiType};

    fn fr_patterns() -> Vec<crate::stage_regex::Pattern> {
        locales::build_patterns(&[Locale::Global, Locale::Fr])
    }

    #[test]
    fn detect_nir_male() {
        // Male born May 1985 in dept 78
        // base=1850578006084, mod 97=6, key=91
        let (_, detections) = detect("NIR: 185057800608491", &fr_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::InseeNir),
            "should detect male NIR"
        );
    }

    #[test]
    fn detect_nir_female() {
        // Female: sex digit = 2
        // 2 85 05 78 006 084 -> base=2850578006084
        // 2850578006084 mod 97: let's compute
        // 2850578006084 / 97 = 29387402124 * 97 = 2850577806028
        // remainder = 2850578006084 - 2850577806028 = 200056... that's wrong, let me just compute
        // Actually we need a correct test value. Let's compute:
        // base = 2850578006084, mod 97:
        // 2850578006084 mod 97 = ?
        // 29387 * 97 = 2850539, so 285057800 mod 97...
        // Let's just use a programmatic approach in the test
        let base: u64 = 2_850_578_006_084;
        let key = 97 - (base % 97);
        let nir = format!("2850578006084{key:02}");
        let text = format!("NIR: {nir}");
        let (_, detections) = detect(&text, &fr_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::InseeNir),
            "should detect female NIR"
        );
    }

    #[test]
    fn detect_nir_corsica_2a() {
        // Corsica 2A département
        let base_with_19: u64 = 2_930_719_000_100;
        let key = 97 - (base_with_19 % 97);
        let nir = format!("293072A000100{key:02}");
        let text = format!("NIR: {nir}");
        let (_, detections) = detect(&text, &fr_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::InseeNir),
            "should detect Corsica 2A NIR"
        );
    }

    #[test]
    fn detect_nir_corsica_2b() {
        let base_with_18: u64 = 1_880_318_000_200;
        let key = 97 - (base_with_18 % 97);
        let nir = format!("188032B000200{key:02}");
        let text = format!("NIR: {nir}");
        let (_, detections) = detect(&text, &fr_patterns());
        assert!(
            detections.iter().any(|d| d.pii_type == PiiType::InseeNir),
            "should detect Corsica 2B NIR"
        );
    }

    #[test]
    fn reject_nir_invalid_key() {
        let (_, detections) = detect("NIR: 185057800608400", &fr_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::InseeNir),
            "should reject NIR with wrong key"
        );
    }

    #[test]
    fn reject_nir_invalid_sex_digit() {
        // Sex digit must be 1 or 2; 3 is invalid — regex rejects this
        let (_, detections) = detect("NIR: 385057800608436", &fr_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::InseeNir),
            "should reject NIR with sex digit 3"
        );
    }

    #[test]
    fn reject_nir_invalid_month() {
        // Month 13 is invalid (regex allows only 01-12 and 20-99 for special codes)
        let (_, detections) = detect("NIR: 185137800608400", &fr_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::InseeNir),
            "should reject NIR with month 13"
        );
    }

    #[test]
    fn reject_nir_month_00() {
        // Month 00 is invalid
        let (_, detections) = detect("NIR: 185007800608400", &fr_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::InseeNir),
            "should reject NIR with month 00"
        );
    }

    #[test]
    fn reject_nir_too_short() {
        // 14 digits should not match
        let (_, detections) = detect("NIR: 18505780060843", &fr_patterns());
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::InseeNir),
            "should not detect 14-digit NIR"
        );
    }

    #[test]
    fn reject_nir_too_long() {
        // 16 digits embedded in text should not match the 15-digit pattern
        let (_, detections) = detect("NIR: 1850578006084361", &fr_patterns());
        // The regex uses \b boundaries, so this 16-digit string could match
        // the first 15 digits if the 16th char is a word boundary. But since
        // all digits are \w, the boundary won't fire mid-number. So no match.
        assert!(
            !detections.iter().any(|d| d.pii_type == PiiType::InseeNir),
            "should not detect 16-digit NIR"
        );
    }
}
