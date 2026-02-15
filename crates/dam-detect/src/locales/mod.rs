mod ca;
mod de;
mod eu;
mod fr;
mod global;
mod uk;
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
            Locale::Ca => patterns.extend(ca::patterns()),
            Locale::Eu => patterns.extend(eu::patterns()),
            Locale::Uk => patterns.extend(uk::patterns()),
            Locale::Fr => patterns.extend(fr::patterns()),
            Locale::De => patterns.extend(de::patterns()),
            // Placeholder locales — no patterns yet
            Locale::Jp | Locale::Kr | Locale::In | Locale::Cn => {}
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
            assert!(
                seen.insert(key),
                "duplicate pattern found: {:?}",
                p.pii_type
            );
        }
    }

    #[test]
    fn ca_includes_sin() {
        let patterns = build_patterns(&[Locale::Global, Locale::Ca]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::Sin),
            "Canada locale should include SIN pattern"
        );
    }

    #[test]
    fn ca_includes_postal_code() {
        let patterns = build_patterns(&[Locale::Global, Locale::Ca]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::PostalCode),
            "Canada locale should include postal code pattern"
        );
    }

    #[test]
    fn all_locales_includes_email_and_ssn() {
        let patterns = build_patterns(Locale::all());
        assert!(patterns.iter().any(|p| p.pii_type == PiiType::Email));
        assert!(patterns.iter().any(|p| p.pii_type == PiiType::Ssn));
    }

    #[test]
    fn uk_includes_ni_number() {
        let patterns = build_patterns(&[Locale::Global, Locale::Uk]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::NiNumber),
            "UK locale should include NI number pattern"
        );
    }

    #[test]
    fn uk_includes_nhs_number() {
        let patterns = build_patterns(&[Locale::Global, Locale::Uk]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::NhsNumber),
            "UK locale should include NHS number pattern"
        );
    }

    #[test]
    fn uk_includes_drivers_license() {
        let patterns = build_patterns(&[Locale::Global, Locale::Uk]);
        assert!(
            patterns
                .iter()
                .any(|p| p.pii_type == PiiType::DriversLicense),
            "UK locale should include drivers licence pattern"
        );
    }

    #[test]
    fn fr_includes_insee_nir() {
        let patterns = build_patterns(&[Locale::Global, Locale::Fr]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::InseeNir),
            "France locale should include INSEE/NIR pattern"
        );
    }

    #[test]
    fn de_includes_national_id() {
        let patterns = build_patterns(&[Locale::Global, Locale::De]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::NationalId),
            "Germany locale should include Personalausweis pattern"
        );
    }

    #[test]
    fn de_includes_tax_id() {
        let patterns = build_patterns(&[Locale::Global, Locale::De]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::TaxId),
            "Germany locale should include Steuer-ID pattern"
        );
    }

    #[test]
    fn eu_includes_vat_number() {
        let patterns = build_patterns(&[Locale::Global, Locale::Eu]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::VatNumber),
            "EU locale should include VAT number pattern"
        );
    }

    #[test]
    fn eu_includes_swift_bic() {
        let patterns = build_patterns(&[Locale::Global, Locale::Eu]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::SwiftBic),
            "EU locale should include SWIFT/BIC pattern"
        );
    }

    #[test]
    fn all_locales_no_duplicates_with_eu() {
        // Adding Eu to all locales should not create duplicates
        let patterns = build_patterns(Locale::all());
        let mut seen = std::collections::HashSet::new();
        for p in &patterns {
            let key = (p.pii_type, p.regex.as_str().to_string());
            assert!(
                seen.insert(key),
                "duplicate pattern found: {:?}",
                p.pii_type
            );
        }
    }
}
