mod global;
mod us;

use crate::stage_regex::Pattern;
use dam_core::Locale;

/// Build the combined pattern list for the given set of locales.
///
/// `Global` patterns are included whenever `Locale::Global` is in the set.
/// Locale-specific patterns (e.g. US SSN) are only included when their locale is active.
/// Duplicate patterns (same PiiType + regex string) are removed.
pub fn build_patterns(locales: &[Locale]) -> Vec<Pattern> {
    let mut patterns = Vec::new();

    for locale in locales {
        match locale {
            Locale::Global => patterns.extend(global::patterns()),
            Locale::Us => patterns.extend(us::patterns()),
            // Placeholder locales — no patterns yet
            Locale::Ca
            | Locale::Uk
            | Locale::Fr
            | Locale::De
            | Locale::Jp
            | Locale::Kr
            | Locale::In
            | Locale::Cn => {}
        }
    }

    dedup_patterns(patterns)
}

/// Remove duplicate patterns (same PiiType + regex string).
fn dedup_patterns(patterns: Vec<Pattern>) -> Vec<Pattern> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();

    for p in patterns {
        let key = (p.pii_type, p.regex.as_str().to_string());
        if seen.insert(key) {
            result.push(p);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use dam_core::PiiType;

    #[test]
    fn global_only_has_no_ssn() {
        let patterns = build_patterns(&[Locale::Global]);
        assert!(
            !patterns.iter().any(|p| p.pii_type == PiiType::Ssn),
            "Global-only patterns should not include SSN"
        );
    }

    #[test]
    fn us_includes_ssn() {
        let patterns = build_patterns(&[Locale::Global, Locale::Us]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::Ssn),
            "US locale should include SSN pattern"
        );
    }

    #[test]
    fn empty_locales_yields_empty_patterns() {
        let patterns = build_patterns(&[]);
        assert!(patterns.is_empty());
    }

    #[test]
    fn no_duplicates_with_all_locales() {
        let patterns = build_patterns(Locale::all());
        let mut seen = std::collections::HashSet::new();
        for p in &patterns {
            let key = (p.pii_type, p.regex.as_str().to_string());
            assert!(seen.insert(key), "duplicate pattern found: {:?}", p.pii_type);
        }
    }

    #[test]
    fn all_locales_includes_email_and_ssn() {
        let patterns = build_patterns(Locale::all());
        assert!(patterns.iter().any(|p| p.pii_type == PiiType::Email));
        assert!(patterns.iter().any(|p| p.pii_type == PiiType::Ssn));
    }
}
