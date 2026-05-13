pub use dam_core::{Detection, SensitiveType, Span};

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::BTreeSet;

static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"[A-Za-z0-9._%+\-]+[ \t\r\n]*@[ \t\r\n]*[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+|[ \t\r\n]+\.[ \t\r\n]*[A-Za-z0-9\-]+)+",
    )
    .unwrap()
});

static PHONE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\+[1-9]\d{6,14}|\b(?:\(\d{3}\)\s?|\d{3}[\-.])\d{3}[\-.]\d{4}\b").unwrap()
});

static SSN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());

static CREDIT_CARD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:\d{4}[\s\-]?){3}\d{4}\b").unwrap());

pub fn detect(input: &str) -> Vec<Detection> {
    detect_with_related_domains(input, &[])
}

pub fn detect_with_related_domains(input: &str, related_domains: &[String]) -> Vec<Detection> {
    let mut detections = Vec::new();

    detect_with_regex(input, &EMAIL_RE, SensitiveType::Email, &mut detections);
    detect_email_derived_domains(input, &mut detections, related_domains);
    detect_with_regex(input, &PHONE_RE, SensitiveType::Phone, &mut detections);
    detect_ssns(input, &mut detections);
    detect_credit_cards(input, &mut detections);

    dedup_overlaps(detections)
}

fn detect_with_regex(
    input: &str,
    regex: &Regex,
    kind: SensitiveType,
    detections: &mut Vec<Detection>,
) {
    detections.extend(regex.find_iter(input).map(|m| Detection {
        kind,
        span: Span {
            start: m.start(),
            end: m.end(),
        },
        value: m.as_str().to_string(),
    }));
}

fn detect_ssns(input: &str, detections: &mut Vec<Detection>) {
    detections.extend(SSN_RE.find_iter(input).filter_map(|m| {
        let digits: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
        if is_valid_ssn_area(&digits) {
            Some(Detection {
                kind: SensitiveType::Ssn,
                span: Span {
                    start: m.start(),
                    end: m.end(),
                },
                value: m.as_str().to_string(),
            })
        } else {
            None
        }
    }));
}

fn detect_credit_cards(input: &str, detections: &mut Vec<Detection>) {
    detections.extend(CREDIT_CARD_RE.find_iter(input).filter_map(|m| {
        let digits: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
        if luhn(&digits) {
            Some(Detection {
                kind: SensitiveType::CreditCard,
                span: Span {
                    start: m.start(),
                    end: m.end(),
                },
                value: m.as_str().to_string(),
            })
        } else {
            None
        }
    }));
}

fn detect_email_derived_domains(
    input: &str,
    detections: &mut Vec<Detection>,
    related_domains: &[String],
) {
    let mut domains = BTreeSet::new();
    for detection in detections
        .iter()
        .filter(|detection| detection.kind == SensitiveType::Email)
    {
        if let Some(domain) = domain_from_email_value(&detection.value) {
            domains.insert(domain);
        }
    }
    for domain in related_domains {
        if let Some(domain) = normalize_domain_value(domain) {
            domains.insert(domain);
        }
    }

    for domain in domains {
        let Some(regex) = domain_regex(&domain) else {
            continue;
        };
        detections.extend(regex.captures_iter(input).filter_map(|captures| {
            let domain_match = captures.get(1)?;
            Some(Detection {
                kind: SensitiveType::Domain,
                span: Span {
                    start: domain_match.start(),
                    end: domain_match.end(),
                },
                value: domain_match.as_str().to_string(),
            })
        }));
    }
}

fn domain_from_email_value(value: &str) -> Option<String> {
    let compact = value
        .chars()
        .filter(|character| !matches!(character, ' ' | '\t' | '\r' | '\n'))
        .collect::<String>();
    let (_, domain) = compact.rsplit_once('@')?;
    normalize_domain_value(domain)
}

fn normalize_domain_value(value: &str) -> Option<String> {
    let domain = value
        .chars()
        .filter(|character| !matches!(character, ' ' | '\t' | '\r' | '\n'))
        .collect::<String>()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if !is_valid_domain(&domain) {
        return None;
    }
    Some(domain)
}

fn is_valid_domain(domain: &str) -> bool {
    let labels = domain.split('.').collect::<Vec<_>>();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
        && labels
            .last()
            .is_some_and(|tld| tld.len() >= 2 && tld.chars().all(|ch| ch.is_ascii_alphabetic()))
}

fn domain_regex(domain: &str) -> Option<Regex> {
    let pattern = domain
        .split('.')
        .map(regex::escape)
        .collect::<Vec<_>>()
        .join(r"[ \t\r\n]*\.[ \t\r\n]*");
    Regex::new(&format!(
        r"(?i)(?:^|[^A-Za-z0-9@._-])({pattern})(?:$|[^A-Za-z0-9._-])"
    ))
    .ok()
}

fn dedup_overlaps(mut detections: Vec<Detection>) -> Vec<Detection> {
    detections.sort_by_key(|d| d.span.start);

    let mut kept: Vec<Detection> = Vec::with_capacity(detections.len());
    for detection in detections {
        if !kept
            .iter()
            .any(|existing| existing.span.overlaps(detection.span))
        {
            kept.push(detection);
        }
    }

    kept
}

fn is_valid_ssn_area(digits: &str) -> bool {
    if digits.len() != 9 {
        return false;
    }

    let area = &digits[0..3];
    let group = &digits[3..5];
    let serial = &digits[5..9];

    if area == "000" || area == "666" || group == "00" || serial == "0000" {
        return false;
    }

    area.parse::<u16>().is_ok_and(|n| n < 900)
}

fn luhn(digits: &str) -> bool {
    if digits.len() < 13 || digits.len() > 19 || digits.chars().all(|c| c == '0') {
        return false;
    }

    let mut sum = 0;
    let mut double = false;
    for ch in digits.chars().rev() {
        let Some(mut n) = ch.to_digit(10) else {
            return false;
        };
        if double {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        double = !double;
    }

    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_email() {
        let detections = detect("email alice@example.com");

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].kind, SensitiveType::Email);
        assert_eq!(detections[0].value, "alice@example.com");
    }

    #[test]
    fn detects_email_with_space_after_at() {
        let detections = detect("email alice@ example.com");

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].kind, SensitiveType::Email);
        assert_eq!(detections[0].value, "alice@ example.com");
    }

    #[test]
    fn detects_email_with_space_before_at() {
        let detections = detect("email alice @example.com");

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].kind, SensitiveType::Email);
        assert_eq!(detections[0].value, "alice @example.com");
    }

    #[test]
    fn detects_email_with_spaces_around_domain_dot() {
        let detections = detect("email alice@example . com");

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].kind, SensitiveType::Email);
        assert_eq!(detections[0].value, "alice@example . com");
    }

    #[test]
    fn detects_email_without_absorbing_following_sentence() {
        let detections = detect("email alice@example.com. What domain?");

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].kind, SensitiveType::Email);
        assert_eq!(detections[0].value, "alice@example.com");
    }

    #[test]
    fn detects_email_derived_domain_repeated_standalone() {
        let detections = detect("email alice@example.com domain example.com");

        assert_eq!(detections.len(), 2);
        assert_eq!(detections[0].kind, SensitiveType::Email);
        assert_eq!(detections[1].kind, SensitiveType::Domain);
        assert_eq!(detections[1].value, "example.com");
    }

    #[test]
    fn detects_email_derived_hyphenated_domain_repeated_standalone() {
        let detections = detect("email alice@corp-example.com domain corp-example.com");

        assert_eq!(detections.len(), 2);
        assert_eq!(detections[0].kind, SensitiveType::Email);
        assert_eq!(detections[1].kind, SensitiveType::Domain);
        assert_eq!(detections[1].value, "corp-example.com");
    }

    #[test]
    fn detects_email_derived_domain_with_spaced_dot() {
        let detections = detect("email alice@example.com domain example . com");

        assert_eq!(detections.len(), 2);
        assert_eq!(detections[1].kind, SensitiveType::Domain);
        assert_eq!(detections[1].value, "example . com");
    }

    #[test]
    fn detects_related_domain_without_email_in_input() {
        let detections = detect_with_related_domains(
            "provider answered example.com",
            &["example.com".to_string()],
        );

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].kind, SensitiveType::Domain);
        assert_eq!(detections[0].value, "example.com");
    }

    #[test]
    fn does_not_detect_domain_inside_email_only() {
        let detections = detect("email alice@example.com");

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].kind, SensitiveType::Email);
    }

    #[test]
    fn does_not_detect_email_domain_inside_subdomain() {
        let detections = detect("email alice@example.com route api.example.com");

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].kind, SensitiveType::Email);
    }

    #[test]
    fn detects_phone() {
        let detections = detect("call +14155551234");

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].kind, SensitiveType::Phone);
    }

    #[test]
    fn detects_valid_ssn() {
        let detections = detect("ssn 123-45-6789");

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].kind, SensitiveType::Ssn);
    }

    #[test]
    fn rejects_invalid_ssn_area() {
        assert!(detect("ssn 666-45-6789").is_empty());
    }

    #[test]
    fn detects_valid_credit_card() {
        let detections = detect("card 4111-1111-1111-1111");

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].kind, SensitiveType::CreditCard);
    }

    #[test]
    fn rejects_invalid_credit_card() {
        assert!(detect("card 4111-1111-1111-1112").is_empty());
    }

    #[test]
    fn returns_detections_in_text_order() {
        let detections = detect("ssn 123-45-6789 email alice@example.com");

        assert_eq!(detections.len(), 2);
        assert_eq!(detections[0].kind, SensitiveType::Ssn);
        assert_eq!(detections[1].kind, SensitiveType::Email);
    }
}
