use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run_resolve(args: &[&str], input: &str, current_dir: &Path) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dam-resolve"))
        .args(args)
        .current_dir(current_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dam-resolve");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");

    child.wait_with_output().expect("wait for dam-resolve")
}

fn utf8(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("utf-8")
}

fn seed_vault(path: &Path, reference: &dam_core::Reference, value: &str) {
    let vault = dam_vault::Vault::open(path).expect("open vault");
    vault.put(&reference.key(), value).expect("put vault value");
}

#[test]
fn resolves_known_references_from_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let reference = dam_core::Reference::generate(dam_core::SensitiveType::Email);
    seed_vault(&db_path, &reference, "alice@example.com");

    let input = format!("email {}", reference.display());
    let output = run_resolve(&["--db", db_path.to_str().unwrap()], &input, dir.path());

    assert!(output.status.success());
    assert_eq!(utf8(&output.stdout), "email alice@example.com");
    assert!(output.stderr.is_empty());
}

#[test]
fn missing_references_are_left_unchanged_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let missing = dam_core::Reference::generate(dam_core::SensitiveType::Ssn);
    let input = format!("ssn {}", missing.display());

    let output = run_resolve(
        &["--db", db_path.to_str().unwrap(), "--report"],
        &input,
        dir.path(),
    );

    assert!(output.status.success());
    assert_eq!(utf8(&output.stdout), input);
    let stderr = utf8(&output.stderr);
    assert!(stderr.contains("references: 1"));
    assert!(stderr.contains("resolved: 0"));
    assert!(stderr.contains("missing: 1"));
}

#[test]
fn json_report_goes_to_stderr_without_resolved_raw_values() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let reference = dam_core::Reference::generate(dam_core::SensitiveType::Email);
    seed_vault(&db_path, &reference, "alice@example.com");

    let input = format!("email {}", reference.display());
    let output = run_resolve(
        &["--db", db_path.to_str().unwrap(), "--json-report"],
        &input,
        dir.path(),
    );

    assert!(output.status.success());
    assert_eq!(utf8(&output.stdout), "email alice@example.com");

    let stderr = utf8(&output.stderr);
    let report: serde_json::Value = serde_json::from_str(&stderr).unwrap();
    assert_eq!(report["status"], "completed");
    assert_eq!(report["summary"]["references"], 1);
    assert_eq!(report["summary"]["resolved"], 1);
    assert_eq!(report["resolved"][0]["kind"], "email");
    assert_eq!(report["resolved"][0]["reference"]["key"], reference.key());
    assert!(!stderr.contains("alice@example.com"));
}

#[test]
fn strict_mode_fails_without_partial_output_when_unresolved() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let known = dam_core::Reference::generate(dam_core::SensitiveType::Email);
    let missing = dam_core::Reference::generate(dam_core::SensitiveType::Ssn);
    seed_vault(&db_path, &known, "alice@example.com");
    let input = format!("known {} missing {}", known.display(), missing.display());

    let output = run_resolve(
        &["--db", db_path.to_str().unwrap(), "--strict"],
        &input,
        dir.path(),
    );

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = utf8(&output.stderr);
    assert!(stderr.contains("resolved: 1"));
    assert!(stderr.contains("missing: 1"));
    assert!(!stderr.contains("alice@example.com"));
}

#[test]
fn strict_mode_json_report_fails_without_partial_output() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let missing = dam_core::Reference::generate(dam_core::SensitiveType::Ssn);
    let input = format!("missing {}", missing.display());

    let output = run_resolve(
        &[
            "--db",
            db_path.to_str().unwrap(),
            "--strict",
            "--json-report",
        ],
        &input,
        dir.path(),
    );

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let stderr = utf8(&output.stderr);
    let report: serde_json::Value = serde_json::from_str(&stderr).unwrap();
    assert_eq!(report["status"], "failed_strict");
    assert_eq!(report["strict"], true);
    assert_eq!(report["summary"]["missing"], 1);
}

#[test]
fn malformed_and_redact_only_placeholders_are_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let input = "safe [email] malformed [email:not-valid] unknown [name:7B2HkqFn9xR4mWpD3nYvKt]";

    let output = run_resolve(
        &["--db", db_path.to_str().unwrap(), "--report"],
        input,
        dir.path(),
    );

    assert!(output.status.success());
    assert_eq!(utf8(&output.stdout), input);
    assert!(utf8(&output.stderr).contains("references: 0"));
}

#[test]
fn resolves_file_input() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let input_path = dir.path().join("input.txt");
    let reference = dam_core::Reference::generate(dam_core::SensitiveType::Phone);
    seed_vault(&db_path, &reference, "+14155551234");
    fs::write(&input_path, format!("phone {}", reference.display())).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dam-resolve"))
        .args([
            "--db",
            db_path.to_str().unwrap(),
            input_path.to_str().unwrap(),
        ])
        .current_dir(dir.path())
        .output()
        .expect("run dam-resolve");

    assert!(output.status.success());
    assert_eq!(utf8(&output.stdout), "phone +14155551234");
}

#[test]
fn writes_non_sensitive_log_events_when_log_path_is_configured() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let log_path = dir.path().join("log.db");
    let known = dam_core::Reference::generate(dam_core::SensitiveType::Email);
    let missing = dam_core::Reference::generate(dam_core::SensitiveType::Ssn);
    seed_vault(&db_path, &known, "alice@example.com");
    let input = format!("known {} missing {}", known.display(), missing.display());

    let output = run_resolve(
        &[
            "--db",
            db_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
        ],
        &input,
        dir.path(),
    );

    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
    assert_eq!(logs.len(), 3);
    assert!(logs.iter().any(|entry| entry.event_type == "vault_read"));
    assert!(logs.iter().any(|entry| entry.event_type == "resolve"));
    assert!(
        logs.iter()
            .any(|entry| entry.action == Some("missing".to_string()))
    );

    let joined = logs
        .iter()
        .map(|entry| {
            format!(
                "{} {} {:?} {:?} {:?} {}",
                entry.operation_id,
                entry.event_type,
                entry.kind,
                entry.reference,
                entry.action,
                entry.message
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!joined.contains("alice@example.com"));
}
