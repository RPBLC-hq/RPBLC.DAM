//! Comprehensive QA tests for European locale detection (EU, UK, FR, DE).
//!
//! These tests exercise the detection pipeline with adversarial, mixed, and
//! edge-case inputs that go beyond unit tests — acting as a full QA pass.

#[cfg(test)]
mod tests {
    use crate::locales;
    use crate::stage_regex::{self, Detection};
    use dam_core::{Locale, PiiType};

    fn all_eu_patterns() -> Vec<stage_regex::Pattern> {
        locales::build_patterns(&[
            Locale::Global,
            Locale::Eu,
            Locale::Uk,
            Locale::Fr,
            Locale::De,
            Locale::Us,
            Locale::Ca,
        ])
    }

    fn detect(text: &str) -> Vec<Detection> {
        let (_, detections) = stage_regex::detect(text, &all_eu_patterns());
        detections
    }

    fn has(detections: &[Detection], pii_type: PiiType) -> bool {
        detections.iter().any(|d| d.pii_type == pii_type)
    }

    fn has_value(detections: &[Detection], pii_type: PiiType, value: &str) -> bool {
        detections
            .iter()
            .any(|d| d.pii_type == pii_type && d.value == value)
    }

    fn count(detections: &[Detection], pii_type: PiiType) -> usize {
        detections.iter().filter(|d| d.pii_type == pii_type).count()
    }

    // ========================================================================
    // 1. MULTI-PII STRINGS — many types in one blob
    // ========================================================================

    #[test]
    fn kitchen_sink_uk_text() {
        let text = "Dear AB123456C, your NHS number is 943 476 5919 and your driving licence is MORGA657054SM9IJ. Please email john@example.com.";
        let d = detect(text);
        assert!(has(&d, PiiType::NiNumber), "NI number not found");
        assert!(has(&d, PiiType::NhsNumber), "NHS number not found");
        assert!(has(&d, PiiType::DriversLicense), "DVLA not found");
        assert!(has(&d, PiiType::Email), "email not found");
    }

    #[test]
    fn kitchen_sink_eu_text() {
        let text = "Company VAT: DE123456789, bank SWIFT DEUTDEFF, IBAN DE89370400440532013000, contact alice@corp.de";
        let d = detect(text);
        assert!(has(&d, PiiType::VatNumber), "VAT not found");
        assert!(has(&d, PiiType::SwiftBic), "SWIFT not found");
        assert!(has(&d, PiiType::Iban), "IBAN not found");
        assert!(has(&d, PiiType::Email), "email not found");
    }

    #[test]
    fn kitchen_sink_fr_de_text() {
        let text = "NIR: 185057800608491, Steuer-ID: 65929970489, Ausweis: L01X00T471";
        let d = detect(text);
        assert!(has(&d, PiiType::InseeNir), "NIR not found");
        assert!(has(&d, PiiType::TaxId), "Steuer-ID not found");
        assert!(has(&d, PiiType::NationalId), "Personalausweis not found");
    }

    // ========================================================================
    // 2. PII IN STRUCTURED DATA — JSON, CSV, key=value
    // ========================================================================

    #[test]
    fn pii_in_json_like_string() {
        let text = r#"{"ni_number": "AB123456C", "nhs": "9434765919", "vat": "DE123456789"}"#;
        let d = detect(text);
        assert!(has(&d, PiiType::NiNumber), "NI in JSON not found");
        assert!(has(&d, PiiType::NhsNumber), "NHS in JSON not found");
        assert!(has(&d, PiiType::VatNumber), "VAT in JSON not found");
    }

    #[test]
    fn pii_in_csv_row() {
        let text = "AB123456C,9434765919,DE123456789,DEUTDEFF,john@test.com";
        let d = detect(text);
        assert!(has(&d, PiiType::NiNumber), "NI in CSV not found");
        assert!(has(&d, PiiType::NhsNumber), "NHS in CSV not found");
        assert!(has(&d, PiiType::VatNumber), "VAT in CSV not found");
        assert!(has(&d, PiiType::SwiftBic), "SWIFT in CSV not found");
        assert!(has(&d, PiiType::Email), "email in CSV not found");
    }

    #[test]
    fn pii_in_key_value_pairs() {
        let text = "ni=AB123456C&nhs=9434765919&email=test@example.com";
        let d = detect(text);
        assert!(has(&d, PiiType::NiNumber), "NI in query string not found");
        assert!(has(&d, PiiType::Email), "email in query string not found");
    }

    // ========================================================================
    // 3. UNICODE EVASION — zero-width chars, fullwidth, homoglyphs
    // ========================================================================

    #[test]
    fn ni_number_with_zero_width_chars() {
        let text = "NI: AB\u{200B}12\u{200C}34\u{200D}56C";
        let d = detect(text);
        assert!(
            has(&d, PiiType::NiNumber),
            "NI with zero-width chars should still be detected"
        );
    }

    #[test]
    fn nhs_with_zero_width_chars() {
        let text = "NHS: 943\u{200B}476\u{200C}5919";
        let d = detect(text);
        assert!(
            has(&d, PiiType::NhsNumber),
            "NHS with zero-width chars should still be detected"
        );
    }

    #[test]
    fn vat_with_zero_width_chars() {
        let text = "VAT: DE\u{200B}123\u{200C}456\u{200D}789";
        let d = detect(text);
        assert!(
            has(&d, PiiType::VatNumber),
            "VAT with zero-width chars should still be detected"
        );
    }

    #[test]
    fn fullwidth_digits_in_nhs() {
        // Fullwidth digits U+FF10-FF19 should normalize to ASCII via NFKC
        let text =
            "NHS: \u{FF19}\u{FF14}\u{FF13}\u{FF14}\u{FF17}\u{FF16}\u{FF15}\u{FF19}\u{FF11}\u{FF19}";
        let d = detect(text);
        assert!(
            has(&d, PiiType::NhsNumber),
            "NHS with fullwidth digits should be detected after NFKC normalization"
        );
    }

    #[test]
    fn fullwidth_letters_in_swift() {
        // Fullwidth DEUTDEFF
        let text = "SWIFT: \u{FF24}\u{FF25}\u{FF35}\u{FF34}\u{FF24}\u{FF25}\u{FF26}\u{FF26}";
        let d = detect(text);
        assert!(
            has(&d, PiiType::SwiftBic),
            "SWIFT with fullwidth letters should be detected after NFKC"
        );
    }

    #[test]
    fn soft_hyphen_in_ni_number() {
        let text = "NI: AB\u{00AD}123456C";
        let d = detect(text);
        assert!(
            has(&d, PiiType::NiNumber),
            "NI with soft hyphen should be detected"
        );
    }

    #[test]
    fn zero_width_no_break_space_in_vat() {
        let text = "VAT: DE\u{FEFF}123456789";
        let d = detect(text);
        assert!(
            has(&d, PiiType::VatNumber),
            "VAT with ZWNBSP should be detected"
        );
    }

    // ========================================================================
    // 4. URL-ENCODED PII
    // ========================================================================

    #[test]
    fn url_encoded_email() {
        let text = "email: john%40example.com";
        let d = detect(text);
        assert!(
            has(&d, PiiType::Email),
            "URL-encoded email should be detected"
        );
    }

    // ========================================================================
    // 5. FALSE POSITIVE RESISTANCE
    // ========================================================================

    #[test]
    fn common_english_words_not_swift() {
        let words = [
            "ABSTRACT", "COMPLETE", "DOCUMENT", "EVALUATE", "FUNCTION", "GENERATE", "HOMEWORK",
            "INCREASE", "KEYBOARD", "LANGUAGE",
        ];
        for word in &words {
            let d = detect(word);
            assert!(
                !has(&d, PiiType::SwiftBic),
                "'{word}' should NOT be detected as SWIFT code"
            );
        }
    }

    #[test]
    fn random_ten_digit_not_nhs() {
        let text = "Transaction 1234567890 completed";
        let d = detect(text);
        assert!(
            !has(&d, PiiType::NhsNumber),
            "1234567890 should not pass NHS MOD 11 check"
        );
    }

    #[test]
    fn phone_numbers_not_false_nhs() {
        // UK landline number — 10+ digits, should not be NHS
        let text = "Call 0207 123 4567 for appointments";
        let d = detect(text);
        let nhs_dets: Vec<_> = d
            .iter()
            .filter(|det| det.pii_type == PiiType::NhsNumber)
            .collect();
        // Any NHS detection here would be a false positive
        // Verify by checking MOD 11 on the detected value
        for det in &nhs_dets {
            let digits: String = det.value.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() == 10 {
                let nums: Vec<u32> = digits.chars().map(|c| c.to_digit(10).unwrap()).collect();
                let sum: u32 = nums.iter().zip((2..=10).rev()).map(|(d, w)| d * w).sum();
                let rem = sum % 11;
                let check = if rem == 0 { 0 } else { 11 - rem };
                assert_eq!(
                    check, nums[9],
                    "False NHS detection: {digits} doesn't pass MOD 11"
                );
            }
        }
    }

    #[test]
    fn german_postal_codes_not_steuer_id() {
        let text = "Address: Musterstrasse 1, 10115 Berlin";
        let d = detect(text);
        assert!(
            !has(&d, PiiType::TaxId),
            "5-digit postal code should not trigger Steuer-ID"
        );
    }

    #[test]
    fn year_not_detected_as_pii() {
        let text = "Founded in 2024, the company grew rapidly.";
        let d = detect(text);
        assert!(!has(&d, PiiType::TaxId), "year should not be Steuer-ID");
    }

    #[test]
    fn reject_consecutive_same_digit_nhs() {
        let text = "Code: 0000000000";
        let d = detect(text);
        assert!(
            !has(&d, PiiType::NhsNumber),
            "0000000000 should not be detected as NHS"
        );
    }

    #[test]
    fn short_uppercase_words_not_swift() {
        // Common abbreviations that are 8 uppercase alphanumeric chars
        for word in &["BUILDING", "CREATING", "DRAFTING", "ENSURING"] {
            let d = detect(word);
            assert!(!has(&d, PiiType::SwiftBic), "'{word}' should NOT be SWIFT");
        }
    }

    #[test]
    fn eur_not_vat() {
        let text = "Total: EUR 12,345.67 excluding VAT";
        let d = detect(text);
        assert!(
            !has_value(&d, PiiType::VatNumber, "EUR"),
            "EUR alone should not be a VAT number"
        );
    }

    // ========================================================================
    // 6. BOUNDARY CONDITIONS
    // ========================================================================

    #[test]
    fn pii_at_start_of_string() {
        let d = detect("AB123456C is my NI number");
        assert!(has(&d, PiiType::NiNumber));
    }

    #[test]
    fn pii_at_end_of_string() {
        let d = detect("My NI number is AB123456C");
        assert!(has(&d, PiiType::NiNumber));
    }

    #[test]
    fn pii_is_entire_string() {
        assert!(has(&detect("AB123456C"), PiiType::NiNumber));
        assert!(has(&detect("DEUTDEFF"), PiiType::SwiftBic));
        assert!(has(&detect("DE123456789"), PiiType::VatNumber));
        assert!(has(&detect("9434765919"), PiiType::NhsNumber));
    }

    #[test]
    fn pii_surrounded_by_punctuation() {
        assert!(has(&detect("(AB123456C)"), PiiType::NiNumber));
        assert!(has(&detect("[DEUTDEFF]"), PiiType::SwiftBic));
        assert!(has(&detect("\"DE123456789\""), PiiType::VatNumber));
        assert!(has(&detect("<9434765919>"), PiiType::NhsNumber));
        assert!(has(&detect("{AB123456C}"), PiiType::NiNumber));
        assert!(has(&detect("'BNPAFRPP'"), PiiType::SwiftBic));
    }

    #[test]
    fn pii_after_newline() {
        let d = detect("Line 1\nAB123456C\nLine 3");
        assert!(has(&d, PiiType::NiNumber), "NI after newline not found");
    }

    #[test]
    fn pii_after_tab() {
        let d = detect("Field:\tAB123456C\tDone");
        assert!(has(&d, PiiType::NiNumber), "NI after tab not found");
    }

    #[test]
    fn pii_after_colon_no_space() {
        let d = detect("NI:AB123456C");
        assert!(
            has(&d, PiiType::NiNumber),
            "NI after colon (no space) not found"
        );
    }

    // ========================================================================
    // 7. DUPLICATE / REPEATED DETECTION
    // ========================================================================

    #[test]
    fn same_ni_twice() {
        let d = detect("First: AB123456C, Second: AB123456C");
        assert_eq!(count(&d, PiiType::NiNumber), 2);
    }

    #[test]
    fn different_vats_in_one_string() {
        let d = detect("German VAT: DE123456789, Austrian VAT: ATU12345678");
        assert!(count(&d, PiiType::VatNumber) >= 2);
    }

    #[test]
    fn three_ni_numbers_in_list() {
        let text = "1. AB123456C\n2. CE654321D\n3. HJ987654A";
        let d = detect(text);
        assert_eq!(count(&d, PiiType::NiNumber), 3);
    }

    // ========================================================================
    // 8. OVERLAPPING / AMBIGUOUS PATTERNS
    // ========================================================================

    #[test]
    fn valid_nhs_number_detected() {
        let d = detect("Number: 9434765919");
        assert!(has(&d, PiiType::NhsNumber));
    }

    #[test]
    fn de_vat_and_steuer_id_dont_overlap() {
        // DE123456789 is VAT (DE + 9 digits). The "123456789" part is 9 digits,
        // too short for Steuer-ID (needs 11 digits starting with non-zero).
        let d = detect("VAT: DE123456789");
        assert!(has(&d, PiiType::VatNumber));
        // 123456789 is only 9 digits — can't be Steuer-ID
        assert!(
            !has_value(&d, PiiType::TaxId, "123456789"),
            "9-digit substring shouldn't be Steuer-ID"
        );
    }

    // ========================================================================
    // 9. NEAR-MISS VALUES (should be rejected)
    // ========================================================================

    #[test]
    fn ni_with_invalid_suffix_e() {
        assert!(!has(&detect("NI: AB123456E"), PiiType::NiNumber));
    }

    #[test]
    fn nhs_off_by_one_check_digit() {
        // 9434765919 is valid; 9434765918 has wrong check digit
        assert!(!has(&detect("NHS: 9434765918"), PiiType::NhsNumber));
    }

    #[test]
    fn dvla_with_month_13() {
        assert!(!has(
            &detect("DL: SMITH713010JJ9AA"),
            PiiType::DriversLicense
        ));
    }

    #[test]
    fn dvla_with_month_50() {
        assert!(!has(
            &detect("DL: SMITH750010JJ9AA"),
            PiiType::DriversLicense
        ));
    }

    #[test]
    fn dvla_with_month_63() {
        // Female range is 51-62; 63 is invalid
        assert!(!has(
            &detect("DL: SMITH763010JJ9AA"),
            PiiType::DriversLicense
        ));
    }

    #[test]
    fn dvla_with_day_00() {
        assert!(!has(
            &detect("DL: SMITH701000JJ9AA"),
            PiiType::DriversLicense
        ));
    }

    #[test]
    fn dvla_with_day_32() {
        assert!(!has(
            &detect("DL: SMITH701320JJ9AA"),
            PiiType::DriversLicense
        ));
    }

    #[test]
    fn nir_with_sex_digit_3() {
        assert!(!has(&detect("NIR: 385057800608491"), PiiType::InseeNir));
    }

    #[test]
    fn nir_with_month_00() {
        // Month 00 is invalid
        assert!(!has(&detect("NIR: 100007800608491"), PiiType::InseeNir));
    }

    #[test]
    fn nir_with_month_13() {
        // Month 13 is out of range for standard (but 20+ is for overseas territories)
        // Our regex allows 0[1-9]|1[0-2]|[2-9]\d — month 13 → 13, matched by 1[0-2]? No, [0-2] means 0,1,2
        // 13 would be 1 then 3 — doesn't match 1[0-2]. Let's verify.
        let text = "NIR: 185137800608491";
        let d = detect(text);
        // 13 → first digit 1, second digit 3. Regex group: (?:0[1-9]|1[0-2]|[2-9]\d)
        // 1[0-2] matches 10,11,12 but not 13. However [2-9]\d would not match 13 either (1 < 2).
        // So 13 should NOT match the regex at all.
        assert!(
            !has(&d, PiiType::InseeNir),
            "NIR with month 13 should be rejected by regex"
        );
    }

    #[test]
    fn vat_with_gb_prefix() {
        assert!(!has(&detect("VAT: GB123456789"), PiiType::VatNumber));
    }

    #[test]
    fn swift_with_9_chars() {
        assert!(!has(&detect("Code: DEUTDEFF5"), PiiType::SwiftBic));
    }

    #[test]
    fn swift_with_10_chars() {
        assert!(!has(&detect("Code: DEUTDEFF50"), PiiType::SwiftBic));
    }

    #[test]
    fn steuer_id_starting_with_zero() {
        assert!(!has(&detect("ID: 01234567890"), PiiType::TaxId));
    }

    #[test]
    fn personalausweis_wrong_check_digit() {
        // L01X00T471 is valid; change last digit
        assert!(!has(&detect("ID: L01X00T472"), PiiType::NationalId));
    }

    // ========================================================================
    // 10. ADVERSARIAL / TRICKY INPUTS
    // ========================================================================

    #[test]
    fn empty_string() {
        assert!(detect("").is_empty());
    }

    #[test]
    fn only_whitespace() {
        assert!(detect("   \t\n\r\n   ").is_empty());
    }

    #[test]
    fn very_long_string_with_embedded_pii() {
        let padding = "x".repeat(10_000);
        let text = format!("{padding} AB123456C {padding} DE123456789 {padding}");
        let d = detect(&text);
        assert!(has(&d, PiiType::NiNumber), "NI in long string not found");
        assert!(has(&d, PiiType::VatNumber), "VAT in long string not found");
    }

    #[test]
    fn ni_number_glued_to_words_no_boundary() {
        // No word boundary before/after — should NOT match
        assert!(!has(&detect("codeAB123456Cmore"), PiiType::NiNumber));
    }

    #[test]
    fn swift_glued_to_letters_no_boundary() {
        assert!(!has(&detect("codeDEUTDEFFmore"), PiiType::SwiftBic));
    }

    #[test]
    fn unicode_dashes_in_nhs() {
        // EN DASH (U+2013) between groups
        let text = "NHS: 943\u{2013}476\u{2013}5919";
        let d = detect(text);
        assert!(
            has(&d, PiiType::NhsNumber),
            "NHS with en-dash separators should be detected after normalization"
        );
    }

    #[test]
    fn em_dash_in_nhs() {
        let text = "NHS: 943\u{2014}476\u{2014}5919";
        let d = detect(text);
        assert!(
            has(&d, PiiType::NhsNumber),
            "NHS with em-dash separators should be detected"
        );
    }

    #[test]
    fn minus_sign_in_nhs() {
        // U+2212 MINUS SIGN
        let text = "NHS: 943\u{2212}476\u{2212}5919";
        let d = detect(text);
        assert!(
            has(&d, PiiType::NhsNumber),
            "NHS with minus sign (U+2212) should be detected"
        );
    }

    #[test]
    fn multiple_locales_same_sentence() {
        let text =
            "UK NI: AB123456C, FR NIR: 185057800608491, DE ID: L01X00T471, EU VAT: DE123456789";
        let d = detect(text);
        assert!(has(&d, PiiType::NiNumber), "NI not found");
        assert!(has(&d, PiiType::InseeNir), "NIR not found");
        assert!(has(&d, PiiType::NationalId), "DE ID not found");
        assert!(has(&d, PiiType::VatNumber), "VAT not found");
    }

    #[test]
    fn pii_in_markdown_table() {
        let text = "| Name | NI | NHS |\n|------|-----|-----|\n| John | AB123456C | 9434765919 |";
        let d = detect(text);
        assert!(has(&d, PiiType::NiNumber));
        assert!(has(&d, PiiType::NhsNumber));
    }

    #[test]
    fn pii_in_xml_tags() {
        let text = "<ni>AB123456C</ni><vat>DE123456789</vat>";
        let d = detect(text);
        assert!(has(&d, PiiType::NiNumber));
        assert!(has(&d, PiiType::VatNumber));
    }

    #[test]
    fn pii_in_sql_query() {
        let text = "INSERT INTO users (ni, email) VALUES ('AB123456C', 'test@example.com')";
        let d = detect(text);
        assert!(has(&d, PiiType::NiNumber), "NI in SQL not found");
        assert!(has(&d, PiiType::Email), "email in SQL not found");
    }

    // ========================================================================
    // 11. LOCALE ISOLATION
    // ========================================================================

    #[test]
    fn uk_patterns_only_when_uk_locale_active() {
        let no_uk = locales::build_patterns(&[Locale::Global, Locale::Eu, Locale::Fr, Locale::De]);
        let (_, d) = stage_regex::detect("NI: AB123456C, NHS: 9434765919", &no_uk);
        assert!(!has(&d, PiiType::NiNumber));
        assert!(!has(&d, PiiType::NhsNumber));
        assert!(!has(&d, PiiType::DriversLicense));
    }

    #[test]
    fn fr_patterns_only_when_fr_locale_active() {
        let no_fr = locales::build_patterns(&[Locale::Global, Locale::Eu, Locale::Uk, Locale::De]);
        let (_, d) = stage_regex::detect("NIR: 185057800608491", &no_fr);
        assert!(!has(&d, PiiType::InseeNir));
    }

    #[test]
    fn de_patterns_only_when_de_locale_active() {
        let no_de = locales::build_patterns(&[Locale::Global, Locale::Eu, Locale::Uk, Locale::Fr]);
        let (_, d) = stage_regex::detect("ID: L01X00T471, Tax: 65929970489", &no_de);
        assert!(!has(&d, PiiType::NationalId));
        assert!(!has(&d, PiiType::TaxId));
    }

    #[test]
    fn eu_patterns_only_when_eu_locale_active() {
        let no_eu = locales::build_patterns(&[Locale::Global, Locale::Uk, Locale::Fr, Locale::De]);
        let (_, d) = stage_regex::detect("VAT: DE123456789, SWIFT: DEUTDEFF", &no_eu);
        assert!(!has(&d, PiiType::VatNumber));
        assert!(!has(&d, PiiType::SwiftBic));
    }

    // ========================================================================
    // 12. VALIDATORS UNDER STRESS
    // ========================================================================

    #[test]
    fn all_eu_vat_country_prefixes() {
        let valid_vats = [
            "ATU12345678",
            "BE0123456789",
            "DE123456789",
            "FR12345678901",
            "NL123456789B01",
            "ESX12345678",
            "IT12345678901",
            "PL1234567890",
        ];
        for vat in &valid_vats {
            let d = detect(&format!("VAT: {vat}"));
            assert!(
                has(&d, PiiType::VatNumber),
                "Valid VAT '{vat}' should be detected"
            );
        }
    }

    #[test]
    fn swift_major_banks() {
        let swifts = [
            "DEUTDEFF", // Deutsche Bank
            "BNPAFRPP", // BNP Paribas
            "COBADEFF", // Commerzbank
            "CHASUS33", // JPMorgan Chase
            "BARCGB22", // Barclays
            "NWBKGB2L", // NatWest
            "HSBCGB2L", // HSBC UK
            "SCBLGB2L", // Standard Chartered
        ];
        for swift in &swifts {
            let d = detect(swift);
            assert!(
                has(&d, PiiType::SwiftBic),
                "Known SWIFT code '{swift}' should be detected"
            );
        }
    }

    #[test]
    fn nhs_numbers_with_various_separators() {
        let formats = ["9434765919", "943 476 5919", "943-476-5919"];
        for fmt in &formats {
            let d = detect(fmt);
            assert!(
                has(&d, PiiType::NhsNumber),
                "NHS in format '{fmt}' should be detected"
            );
        }
    }

    #[test]
    fn dvla_with_9_padding() {
        // Surnames shorter than 5 chars get 9-padded: "FOX" → "FOX99"
        let d = detect("DL: FOX99657054SM9IJ");
        assert!(has(&d, PiiType::DriversLicense));
    }

    #[test]
    fn nir_corsica_departments() {
        // 2A department: replace 2A→19 for mod calculation
        let base_2a: u64 = 1_850_119_006_084;
        let key_2a = 97 - (base_2a % 97);
        let nir_2a = format!("185012A006084{key_2a:02}");
        let d = detect(&nir_2a);
        assert!(
            has(&d, PiiType::InseeNir),
            "NIR with Corsica 2A department ({nir_2a}) should be detected"
        );

        // 2B department: replace 2B→18 for mod calculation
        let base_2b: u64 = 1_850_118_006_084;
        let key_2b = 97 - (base_2b % 97);
        let nir_2b = format!("185012B006084{key_2b:02}");
        let d = detect(&nir_2b);
        assert!(
            has(&d, PiiType::InseeNir),
            "NIR with Corsica 2B department ({nir_2b}) should be detected"
        );
    }

    // ========================================================================
    // 13. REGRESSION: existing global patterns still work
    // ========================================================================

    #[test]
    fn iban_still_works_with_eu_locale() {
        let patterns = locales::build_patterns(&[Locale::Global, Locale::Eu]);
        let (_, d) = stage_regex::detect("IBAN: DE89370400440532013000", &patterns);
        assert!(has(&d, PiiType::Iban));
    }

    #[test]
    fn email_still_works_with_all_locales() {
        assert!(has(&detect("contact: alice@example.com"), PiiType::Email));
    }

    #[test]
    fn credit_card_still_works() {
        assert!(has(&detect("Card: 4111111111111111"), PiiType::CreditCard));
    }

    #[test]
    fn ssn_still_works() {
        assert!(has(&detect("SSN: 123-45-6789"), PiiType::Ssn));
    }

    #[test]
    fn ipv4_still_works() {
        assert!(has(&detect("Server: 8.8.8.8"), PiiType::IpAddress));
    }

    #[test]
    fn dob_still_works() {
        // DOB regex uses DD/MM/YYYY or MM-DD-YYYY format, not ISO 8601
        assert!(has(&detect("Born: 01/15/1990"), PiiType::DateOfBirth));
        assert!(has(&detect("Born: 15-01-1990"), PiiType::DateOfBirth));
    }

    #[test]
    fn ca_sin_still_works() {
        // SIN starting with 0 is rejected by validator; use one starting with 1-7
        assert!(has(&detect("SIN: 130 692 544"), PiiType::Sin));
    }

    // ========================================================================
    // 14. REAL-WORLD SCENARIOS
    // ========================================================================

    #[test]
    fn customer_support_email_body() {
        let text = "\
Hi Support,\n\
My National Insurance number is CE654321D and\n\
my NHS number is 943 476 5919.\n\
My email is jane.smith@example.com.\n\
Thanks, Jane";
        let d = detect(text);
        assert!(has(&d, PiiType::NiNumber));
        assert!(has(&d, PiiType::NhsNumber));
        assert!(has(&d, PiiType::Email));
    }

    #[test]
    fn invoice_with_eu_data() {
        let text = "\
INVOICE #2024-001\n\
Company: Acme GmbH\n\
VAT ID: DE123456789\n\
Bank: Commerzbank\n\
SWIFT/BIC: COBADEFF\n\
IBAN: DE89370400440532013000\n\
Amount: EUR 1,234.56";
        let d = detect(text);
        assert!(has(&d, PiiType::VatNumber));
        assert!(has(&d, PiiType::SwiftBic));
        assert!(has(&d, PiiType::Iban));
    }

    #[test]
    fn french_social_security_form() {
        let text = "\
Formulaire de securite sociale\n\
Numero NIR: 185057800608491\n\
Email: jean.dupont@example.fr";
        let d = detect(text);
        assert!(has(&d, PiiType::InseeNir));
        assert!(has(&d, PiiType::Email));
    }

    #[test]
    fn german_tax_document() {
        let text = "\
Steuerbescheid 2023\n\
Steuerliche Identifikationsnummer: 65929970489\n\
Personalausweisnummer: L01X00T471";
        let d = detect(text);
        assert!(has(&d, PiiType::TaxId));
        assert!(has(&d, PiiType::NationalId));
    }

    #[test]
    fn api_log_with_mixed_pii() {
        let text = r#"2024-01-15T10:30:00Z INFO request from john@corp.com: {"ni":"AB123456C","vat":"FR12345678901","swift":"BNPAFRPP"}"#;
        let d = detect(text);
        assert!(has(&d, PiiType::Email));
        assert!(has(&d, PiiType::NiNumber));
        assert!(has(&d, PiiType::VatNumber));
        assert!(has(&d, PiiType::SwiftBic));
    }

    #[test]
    fn multiline_chat_transcript() {
        let text = "\
[10:01] Agent: Could you provide your NI number?\n\
[10:02] User: Sure, it's AB123456C\n\
[10:03] Agent: And your NHS number?\n\
[10:04] User: 943 476 5919\n\
[10:05] Agent: I also need your email\n\
[10:06] User: jane@example.co.uk";
        let d = detect(text);
        assert!(has(&d, PiiType::NiNumber));
        assert!(has(&d, PiiType::NhsNumber));
        assert!(has(&d, PiiType::Email));
    }

    #[test]
    fn gdpr_data_export() {
        let text = r#"{"subject":{"email":"user@example.de","ni_number":"AB123456C","nhs":"9434765919","vat":"DE123456789","iban":"DE89370400440532013000","nir":"185057800608491","steuer_id":"65929970489"}}"#;
        let d = detect(text);
        assert!(has(&d, PiiType::Email), "email in GDPR export");
        assert!(has(&d, PiiType::NiNumber), "NI in GDPR export");
        assert!(has(&d, PiiType::NhsNumber), "NHS in GDPR export");
        assert!(has(&d, PiiType::VatNumber), "VAT in GDPR export");
        assert!(has(&d, PiiType::Iban), "IBAN in GDPR export");
        assert!(has(&d, PiiType::InseeNir), "NIR in GDPR export");
        assert!(has(&d, PiiType::TaxId), "Steuer-ID in GDPR export");
    }

    // ========================================================================
    // 15. CONFIDENCE LEVELS
    // ========================================================================

    #[test]
    fn ni_number_has_high_confidence() {
        let d = detect("AB123456C");
        let ni = d.iter().find(|d| d.pii_type == PiiType::NiNumber).unwrap();
        assert!(
            ni.confidence >= 0.85,
            "NI should have high confidence, got {}",
            ni.confidence
        );
    }

    #[test]
    fn swift_has_reasonable_confidence() {
        let d = detect("DEUTDEFF");
        let swift = d.iter().find(|d| d.pii_type == PiiType::SwiftBic).unwrap();
        assert!(
            swift.confidence >= 0.75,
            "SWIFT should have reasonable confidence, got {}",
            swift.confidence
        );
    }

    // ========================================================================
    // 16. DETECTION OFFSETS
    // ========================================================================

    #[test]
    fn detection_offsets_are_correct() {
        let text = "prefix AB123456C suffix";
        let (normalized, d) = stage_regex::detect(text, &all_eu_patterns());
        let ni = d.iter().find(|d| d.pii_type == PiiType::NiNumber).unwrap();
        assert_eq!(&normalized[ni.start..ni.end], "AB123456C");
    }

    #[test]
    fn detection_offsets_with_unicode_normalization() {
        // After NFKC normalization, offsets refer to the normalized text
        let text = "prefix \u{200B}AB123456C suffix";
        let (normalized, d) = stage_regex::detect(text, &all_eu_patterns());
        let ni = d.iter().find(|d| d.pii_type == PiiType::NiNumber).unwrap();
        assert_eq!(
            &normalized[ni.start..ni.end],
            "AB123456C",
            "Offsets should index into the normalized text correctly"
        );
    }
}
