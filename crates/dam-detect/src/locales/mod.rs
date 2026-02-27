mod ae;
mod br;
mod ca;
mod de;
mod es;
mod eu;
mod fr;
mod global;
mod it;
mod mx;
mod sg;
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
            Locale::Sg => patterns.extend(sg::patterns()),
            Locale::Es => patterns.extend(es::patterns()),
            Locale::It => patterns.extend(it::patterns()),
            Locale::Br => patterns.extend(br::patterns()),
            Locale::Mx => patterns.extend(mx::patterns()),
            Locale::Ae => patterns.extend(ae::patterns()),
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
    fn sg_includes_nric() {
        let patterns = build_patterns(&[Locale::Global, Locale::Sg]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::Nric),
            "Singapore locale should include NRIC pattern"
        );
    }

    #[test]
    fn es_includes_nif() {
        let patterns = build_patterns(&[Locale::Global, Locale::Es]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::Nif),
            "Spain locale should include NIF pattern"
        );
    }

    #[test]
    fn es_includes_nie() {
        let patterns = build_patterns(&[Locale::Global, Locale::Es]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::Nie),
            "Spain locale should include NIE pattern"
        );
    }

    #[test]
    fn it_includes_codice_fiscale() {
        let patterns = build_patterns(&[Locale::Global, Locale::It]);
        assert!(
            patterns
                .iter()
                .any(|p| p.pii_type == PiiType::CodiceFiscale),
            "Italy locale should include Codice Fiscale pattern"
        );
    }

    #[test]
    fn br_includes_cpf() {
        let patterns = build_patterns(&[Locale::Global, Locale::Br]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::Cpf),
            "Brazil locale should include CPF pattern"
        );
    }

    #[test]
    fn mx_includes_curp() {
        let patterns = build_patterns(&[Locale::Global, Locale::Mx]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::Curp),
            "Mexico locale should include CURP pattern"
        );
    }

    #[test]
    fn ae_includes_emirates_id() {
        let patterns = build_patterns(&[Locale::Global, Locale::Ae]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::EmiratesId),
            "UAE locale should include Emirates ID pattern"
        );
    }

    #[test]
    fn us_includes_dea_number() {
        let patterns = build_patterns(&[Locale::Global, Locale::Us]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::DeaNumber),
            "US locale should include DEA number pattern"
        );
    }

    #[test]
    fn global_includes_vin() {
        let patterns = build_patterns(&[Locale::Global]);
        assert!(
            patterns.iter().any(|p| p.pii_type == PiiType::Vin),
            "Global locale should include VIN pattern"
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
