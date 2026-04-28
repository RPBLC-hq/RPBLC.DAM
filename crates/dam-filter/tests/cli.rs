use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run_filter(args: &[&str], input: &str, current_dir: &Path) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dam-filter"))
        .args(args)
        .current_dir(current_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dam-filter");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");

    child.wait_with_output().expect("wait for dam-filter")
}

fn utf8(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("utf-8")
}

fn write_config(dir: &Path, body: &str) -> String {
    let path = dir.join("dam.toml");
    fs::write(&path, body).expect("write config");
    path.to_str().unwrap().to_string()
}

#[test]
fn redacts_stdin_to_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let output = run_filter(
        &["--db", db_path.to_str().unwrap()],
        "email alice@example.com ssn 123-45-6789",
        dir.path(),
    );

    assert!(output.status.success());
    let stdout = utf8(&output.stdout);
    assert!(stdout.starts_with("email [email:"));
    assert!(stdout.contains("] ssn [ssn:"));
    assert!(!stdout.contains("alice@example.com"));
    assert!(!stdout.contains("123-45-6789"));
    assert!(output.stderr.is_empty());

    let vault = dam_vault::Vault::open(db_path).unwrap();
    let entries = vault.list().unwrap();
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .any(|entry| entry.value == "alice@example.com")
    );
    assert!(entries.iter().any(|entry| entry.value == "123-45-6789"));
}

#[test]
fn duplicate_values_reuse_one_reference_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let output = run_filter(
        &["--db", db_path.to_str().unwrap(), "--report"],
        "email alice@example.com again alice@example.com",
        dir.path(),
    );

    assert!(output.status.success(), "{}", utf8(&output.stderr));
    let stdout = utf8(&output.stdout);
    let references = dam_core::find_references(&stdout);
    assert_eq!(references.len(), 2);
    assert_eq!(references[0].reference, references[1].reference);
    assert_eq!(
        dam_vault::Vault::open(&db_path).unwrap().count().unwrap(),
        1
    );

    let stderr = utf8(&output.stderr);
    assert!(stderr.contains("detections: 2"));
    assert!(stderr.contains("stored: 1"));
}

#[test]
fn duplicate_value_reuse_can_be_disabled_by_config() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let config_path = write_config(
        dir.path(),
        r#"
        [policy]
        deduplicate_replacements = false
        "#,
    );
    let output = run_filter(
        &[
            "--config",
            &config_path,
            "--db",
            db_path.to_str().unwrap(),
            "--report",
        ],
        "email alice@example.com again alice@example.com",
        dir.path(),
    );

    assert!(output.status.success(), "{}", utf8(&output.stderr));
    let stdout = utf8(&output.stdout);
    let references = dam_core::find_references(&stdout);
    assert_eq!(references.len(), 2);
    assert_ne!(references[0].reference, references[1].reference);
    assert_eq!(
        dam_vault::Vault::open(&db_path).unwrap().count().unwrap(),
        2
    );

    let stderr = utf8(&output.stderr);
    assert!(stderr.contains("detections: 2"));
    assert!(stderr.contains("stored: 2"));
}

#[test]
fn active_consent_allows_value_without_vault_write() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let consent_path = dir.path().join("consent.db");
    dam_consent::ConsentStore::open(&consent_path)
        .unwrap()
        .grant(&dam_consent::GrantConsent {
            kind: dam_core::SensitiveType::Email,
            value: "alice@example.com".to_string(),
            vault_key: None,
            ttl_seconds: 60,
            created_by: "test".to_string(),
            reason: None,
        })
        .unwrap();
    let config_path = write_config(
        dir.path(),
        &format!(
            r#"
        [consent]
        path = "{}"
        "#,
            consent_path.display()
        ),
    );

    let output = run_filter(
        &[
            "--config",
            &config_path,
            "--db",
            db_path.to_str().unwrap(),
            "--report",
        ],
        "email alice@example.com",
        dir.path(),
    );

    assert!(output.status.success(), "{}", utf8(&output.stderr));
    assert_eq!(utf8(&output.stdout), "email alice@example.com");
    assert_eq!(
        dam_vault::Vault::open(&db_path).unwrap().count().unwrap(),
        0
    );
    let stderr = utf8(&output.stderr);
    assert!(stderr.contains("allowed: 1"));
}

#[test]
fn report_goes_to_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let output = run_filter(
        &["--db", db_path.to_str().unwrap(), "--report"],
        "email alice@example.com",
        dir.path(),
    );

    assert!(output.status.success());
    let stdout = utf8(&output.stdout);
    assert!(stdout.starts_with("email [email:"));

    let stderr = utf8(&output.stderr);
    assert!(stderr.contains("operation_id: "));
    assert!(stderr.contains("detections: 1"));
    assert!(stderr.contains("stored: 1"));
    assert!(stderr.contains("policy_redactions: 0"));
    assert!(stderr.contains("allowed: 0"));
    assert!(stderr.contains("blocked: 0"));
    assert!(stderr.contains("fallback_redactions: 0"));
    assert!(stderr.contains("email 6..23 alic..."));
}

#[test]
fn json_report_goes_to_stderr_without_raw_values() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let output = run_filter(
        &["--db", db_path.to_str().unwrap(), "--json-report"],
        "email alice@example.com",
        dir.path(),
    );

    assert!(output.status.success());
    let stdout = utf8(&output.stdout);
    assert!(stdout.starts_with("email [email:"));

    let stderr = utf8(&output.stderr);
    let report: serde_json::Value = serde_json::from_str(&stderr).unwrap();
    assert_eq!(report["status"], "completed");
    assert_eq!(report["summary"]["detections"], 1);
    assert_eq!(report["summary"]["tokenized"], 1);
    assert_eq!(report["detections"][0]["kind"], "email");
    assert_eq!(report["decisions"][0]["action"], "tokenize");
    assert_eq!(report["replacements"][0]["mode"], "tokenized");
    assert!(!stderr.contains("alice@example.com"));
    assert!(!stderr.contains("alic..."));
}

#[test]
fn writes_non_sensitive_log_events_when_log_path_is_configured() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let log_path = dir.path().join("log.db");
    let output = run_filter(
        &[
            "--db",
            db_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
        ],
        "email alice@example.com ssn 123-45-6789",
        dir.path(),
    );

    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
    assert_eq!(logs.len(), 8);
    assert!(logs.iter().any(|entry| entry.event_type == "detection"));
    assert!(
        logs.iter()
            .any(|entry| entry.event_type == "policy_decision")
    );
    assert!(logs.iter().any(|entry| entry.event_type == "vault_write"));
    assert!(logs.iter().any(|entry| entry.event_type == "redaction"));

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
    assert!(!joined.contains("123-45-6789"));
}

#[test]
fn policy_redact_replaces_without_vault_write() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let log_path = dir.path().join("log.db");
    let config_path = write_config(
        dir.path(),
        r#"
        [policy]
        default_action = "redact"
        "#,
    );
    let output = run_filter(
        &[
            "--config",
            &config_path,
            "--db",
            db_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            "--report",
        ],
        "email alice@example.com",
        dir.path(),
    );

    assert!(output.status.success());
    assert_eq!(utf8(&output.stdout), "email [email]");

    let stderr = utf8(&output.stderr);
    assert!(stderr.contains("stored: 0"));
    assert!(stderr.contains("policy_redactions: 1"));

    let vault = dam_vault::Vault::open(db_path).unwrap();
    assert_eq!(vault.count().unwrap(), 0);

    let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
    assert_eq!(logs.len(), 3);
    assert!(logs.iter().any(|entry| {
        entry.event_type == "policy_decision" && entry.action == Some("redact".to_string())
    }));
    assert!(!logs.iter().any(|entry| entry.event_type == "vault_write"));
}

#[test]
fn policy_allow_leaves_value_without_vault_write() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let log_path = dir.path().join("log.db");
    let config_path = write_config(
        dir.path(),
        r#"
        [policy]
        default_action = "allow"
        "#,
    );
    let output = run_filter(
        &[
            "--config",
            &config_path,
            "--db",
            db_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            "--report",
        ],
        "email alice@example.com",
        dir.path(),
    );

    assert!(output.status.success());
    assert_eq!(utf8(&output.stdout), "email alice@example.com");

    let stderr = utf8(&output.stderr);
    assert!(stderr.contains("stored: 0"));
    assert!(stderr.contains("allowed: 1"));

    let vault = dam_vault::Vault::open(db_path).unwrap();
    assert_eq!(vault.count().unwrap(), 0);

    let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
    assert_eq!(logs.len(), 2);
    assert!(logs.iter().any(|entry| {
        entry.event_type == "policy_decision" && entry.action == Some("allow".to_string())
    }));
}

#[test]
fn policy_block_exits_before_vault_write() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let log_path = dir.path().join("log.db");
    let config_path = write_config(
        dir.path(),
        r#"
        [policy]
        default_action = "block"
        "#,
    );
    let output = run_filter(
        &[
            "--config",
            &config_path,
            "--db",
            db_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
        ],
        "email alice@example.com",
        dir.path(),
    );

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = utf8(&output.stderr);
    assert!(stderr.contains("blocked: 1"));
    assert!(stderr.contains("policy_block email 6..23"));

    let vault = dam_vault::Vault::open(db_path).unwrap();
    assert_eq!(vault.count().unwrap(), 0);

    let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
    assert_eq!(logs.len(), 2);
    assert!(logs.iter().any(|entry| {
        entry.event_type == "policy_decision" && entry.action == Some("block".to_string())
    }));
}

#[test]
fn policy_block_json_report_is_machine_readable() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let config_path = write_config(
        dir.path(),
        r#"
        [policy]
        default_action = "block"
        "#,
    );
    let output = run_filter(
        &[
            "--config",
            &config_path,
            "--db",
            db_path.to_str().unwrap(),
            "--json-report",
        ],
        "email alice@example.com",
        dir.path(),
    );

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let stderr = utf8(&output.stderr);
    let report: serde_json::Value = serde_json::from_str(&stderr).unwrap();
    assert_eq!(report["status"], "blocked");
    assert_eq!(report["summary"]["blocked"], 1);
    assert_eq!(report["blocked"][0]["kind"], "email");
    assert!(!stderr.contains("alice@example.com"));

    let vault = dam_vault::Vault::open(db_path).unwrap();
    assert_eq!(vault.count().unwrap(), 0);
}
