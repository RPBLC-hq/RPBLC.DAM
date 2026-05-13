use crate::SensitiveType;

pub fn canonical_sensitive_value(kind: SensitiveType, value: &str) -> String {
    match kind {
        SensitiveType::Email => canonical_email_value(value),
        SensitiveType::Domain => canonical_domain_value(value),
        SensitiveType::Phone | SensitiveType::Ssn | SensitiveType::CreditCard => value.to_string(),
    }
}

fn canonical_email_value(value: &str) -> String {
    let compact = value
        .chars()
        .filter(|character| !matches!(character, ' ' | '\t' | '\r' | '\n'))
        .collect::<String>();

    let Some((local, domain)) = compact.rsplit_once('@') else {
        return compact;
    };

    format!("{local}@{}", domain.to_ascii_lowercase())
}

fn canonical_domain_value(value: &str) -> String {
    value
        .chars()
        .filter(|character| !matches!(character, ' ' | '\t' | '\r' | '\n'))
        .collect::<String>()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_detector_supported_email_spacing() {
        assert_eq!(
            canonical_sensitive_value(SensitiveType::Email, "alice@ example .COM"),
            "alice@example.com"
        );
        assert_eq!(
            canonical_sensitive_value(SensitiveType::Email, "alice @example.com"),
            "alice@example.com"
        );
    }

    #[test]
    fn leaves_non_email_values_unchanged() {
        assert_eq!(
            canonical_sensitive_value(SensitiveType::Phone, "+1 555 555 5555"),
            "+1 555 555 5555"
        );
    }

    #[test]
    fn canonicalizes_domain_spacing_and_case() {
        assert_eq!(
            canonical_sensitive_value(SensitiveType::Domain, "Example .COM"),
            "example.com"
        );
    }
}
