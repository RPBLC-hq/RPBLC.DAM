use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use std::{
    io::Write,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

static BINARIES_BUILT: OnceLock<()> = OnceLock::new();

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("dam-e2e manifest should live under DAM/crates/dam-e2e")
        .to_path_buf()
}

fn ensure_binaries() {
    BINARIES_BUILT.get_or_init(|| {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let status = Command::new(cargo)
            .args([
                "build",
                "-q",
                "-p",
                "dam",
                "-p",
                "dam-filter",
                "-p",
                "dam-resolve",
                "-p",
                "dam-proxy",
                "-p",
                "dam-web",
            ])
            .current_dir(workspace_root())
            .status()
            .expect("build DAM binaries");

        assert!(status.success(), "DAM binary build failed");
    });
}

fn binary(name: &str) -> PathBuf {
    workspace_root()
        .join("target")
        .join("debug")
        .join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

fn run_binary_with_input(name: &str, args: &[&str], input: &str, current_dir: &Path) -> Output {
    ensure_binaries();

    let mut child = Command::new(binary(name))
        .args(args)
        .current_dir(current_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {name}: {error}"));

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");

    child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("wait for {name}: {error}"))
}

fn utf8(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("utf-8")
}

fn unused_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr")
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn spawn(name: &str, args: &[&str], current_dir: &Path) -> Self {
        ensure_binaries();

        let child = Command::new(binary(name))
            .args(args)
            .current_dir(current_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|error| panic!("spawn {name}: {error}"));

        Self { child }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct DamDaemonGuard {
    state_dir: PathBuf,
    current_dir: PathBuf,
}

impl DamDaemonGuard {
    fn new(state_dir: PathBuf, current_dir: PathBuf) -> Self {
        Self {
            state_dir,
            current_dir,
        }
    }

    fn disconnect(&self) -> Output {
        ensure_binaries();

        Command::new(binary("dam"))
            .arg("disconnect")
            .current_dir(&self.current_dir)
            .env("DAM_STATE_DIR", &self.state_dir)
            .output()
            .expect("run dam disconnect")
    }
}

impl Drop for DamDaemonGuard {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}

async fn wait_for_ok(url: &str) {
    let client = reqwest::Client::new();
    for _ in 0..60 {
        if let Ok(response) = client.get(url).send().await
            && response.status().is_success()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!("server did not become ready: {url}");
}

fn assert_logs_do_not_contain(log_path: &Path, forbidden: &[&str]) {
    let logs = dam_log::LogStore::open(log_path)
        .expect("open log db")
        .list()
        .expect("list logs");
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

    for value in forbidden {
        assert!(!joined.contains(value), "log leaked value: {value}");
    }
}

#[cfg(unix)]
#[test]
fn dam_codex_launcher_fails_closed_until_transport_is_protected() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault.db");

    ensure_binaries();
    let output = Command::new(binary("dam"))
        .args(["codex", "--db", vault_path.to_str().unwrap(), "--no-log"])
        .current_dir(dir.path())
        .output()
        .expect("run dam codex launcher");

    assert!(!output.status.success(), "dam codex should fail closed");
    let stderr = utf8(&output.stderr);
    assert!(stderr.contains("backend-api/codex/responses"), "{stderr}");
    assert!(stderr.contains("would not protect the prompt"), "{stderr}");
}

#[cfg(unix)]
#[test]
fn dam_codex_api_launcher_sets_dam_model_provider() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let bin_dir = dir.path().join("bin");
    std::fs::create_dir(&bin_dir).unwrap();
    let fake_codex = bin_dir.join("codex");
    std::fs::write(
        &fake_codex,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$DAM_FAKE_CODEX_ARGS\"\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&fake_codex).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&fake_codex, permissions).unwrap();

    let addr = unused_addr();
    let args_path = dir.path().join("codex-args.txt");
    let vault_path = dir.path().join("vault.db");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    ensure_binaries();
    let output = Command::new(binary("dam"))
        .args([
            "codex",
            "--api",
            "--listen",
            &addr.to_string(),
            "--upstream",
            "http://127.0.0.1:9",
            "--db",
            vault_path.to_str().unwrap(),
            "--no-log",
            "--",
            "-m",
            "gpt-5.5",
        ])
        .current_dir(dir.path())
        .env("PATH", path)
        .env("OPENAI_API_KEY", "sk-test")
        .env("DAM_FAKE_CODEX_ARGS", &args_path)
        .output()
        .expect("run dam codex launcher");

    assert!(output.status.success(), "{}", utf8(&output.stderr));
    let codex_args = std::fs::read_to_string(args_path).unwrap();
    assert!(codex_args.contains("model_provider=\"dam_openai\"\n"));
    assert!(codex_args.contains(&format!(
        "model_providers.dam_openai.base_url=\"http://{addr}/v1\"\n"
    )));
    assert!(codex_args.contains("model_providers.dam_openai.env_key=\"OPENAI_API_KEY\"\n"));
    assert!(codex_args.contains("model_providers.dam_openai.supports_websockets=false\n"));
    assert!(codex_args.contains("-m\n"));
    assert!(codex_args.contains("gpt-5.5\n"));
}

#[cfg(unix)]
#[test]
fn dam_claude_launcher_passes_anthropic_base_url_to_claude() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let bin_dir = dir.path().join("bin");
    std::fs::create_dir(&bin_dir).unwrap();
    let fake_claude = bin_dir.join("claude");
    std::fs::write(
        &fake_claude,
        "#!/bin/sh\nprintf '%s\\n' \"$ANTHROPIC_BASE_URL\" > \"$DAM_FAKE_CLAUDE_ENV\"\nprintf '%s\\n' \"$@\" > \"$DAM_FAKE_CLAUDE_ARGS\"\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&fake_claude).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&fake_claude, permissions).unwrap();

    let addr = unused_addr();
    let args_path = dir.path().join("claude-args.txt");
    let env_path = dir.path().join("claude-env.txt");
    let vault_path = dir.path().join("vault.db");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    ensure_binaries();
    let output = Command::new(binary("dam"))
        .args([
            "claude",
            "--listen",
            &addr.to_string(),
            "--upstream",
            "http://127.0.0.1:9",
            "--db",
            vault_path.to_str().unwrap(),
            "--no-log",
            "--",
            "--model",
            "sonnet",
        ])
        .current_dir(dir.path())
        .env("PATH", path)
        .env("DAM_FAKE_CLAUDE_ARGS", &args_path)
        .env("DAM_FAKE_CLAUDE_ENV", &env_path)
        .output()
        .expect("run dam claude launcher");

    assert!(output.status.success(), "{}", utf8(&output.stderr));
    let claude_env = std::fs::read_to_string(env_path).unwrap();
    assert_eq!(claude_env.trim(), format!("http://{addr}"));
    let claude_args = std::fs::read_to_string(args_path).unwrap();
    assert!(claude_args.contains("--model\n"));
    assert!(claude_args.contains("sonnet\n"));
}

#[test]
fn dam_connect_status_disconnect_tracks_profile_target() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let vault_path = dir.path().join("vault.db");
    let log_path = dir.path().join("log.db");
    let consent_path = dir.path().join("consent.db");
    let daemon = DamDaemonGuard::new(state_dir.clone(), dir.path().to_path_buf());

    ensure_binaries();
    let connect_output = Command::new(binary("dam"))
        .args([
            "connect",
            "--profile",
            "xai-compatible",
            "--listen",
            "127.0.0.1:0",
            "--db",
            vault_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            "--consent-db",
            consent_path.to_str().unwrap(),
        ])
        .current_dir(dir.path())
        .env("DAM_STATE_DIR", &state_dir)
        .output()
        .expect("run dam connect");

    assert!(
        connect_output.status.success(),
        "{}",
        utf8(&connect_output.stderr)
    );
    let connect_stdout = utf8(&connect_output.stdout);
    assert!(connect_stdout.contains("DAM connected at http://127.0.0.1:"));
    assert!(connect_stdout.contains("target: xai"));
    assert!(connect_stdout.contains("upstream: https://api.x.ai"));

    let status_output = Command::new(binary("dam"))
        .arg("status")
        .current_dir(dir.path())
        .env("DAM_STATE_DIR", &state_dir)
        .output()
        .expect("run dam status");

    assert!(
        status_output.status.success(),
        "{}",
        utf8(&status_output.stderr)
    );
    let status_stdout = utf8(&status_output.stdout);
    assert!(status_stdout.contains("state: connected"));
    assert!(status_stdout.contains("target: xai"));
    assert!(status_stdout.contains("provider: openai-compatible"));
    assert!(status_stdout.contains("upstream: https://api.x.ai"));
    assert!(status_stdout.contains("protection: protected"));

    let json_status_output = Command::new(binary("dam"))
        .args(["status", "--json"])
        .current_dir(dir.path())
        .env("DAM_STATE_DIR", &state_dir)
        .output()
        .expect("run dam status --json");

    assert!(
        json_status_output.status.success(),
        "{}",
        utf8(&json_status_output.stderr)
    );
    let status_json: serde_json::Value =
        serde_json::from_slice(&json_status_output.stdout).expect("status json");
    assert_eq!(status_json["state"], "connected");
    assert_eq!(status_json["daemon"]["target_name"], "xai");
    assert_eq!(
        status_json["daemon"]["target_provider"],
        "openai-compatible"
    );
    assert_eq!(status_json["daemon"]["upstream"], "https://api.x.ai");

    let disconnect_output = daemon.disconnect();
    assert!(
        disconnect_output.status.success(),
        "{}",
        utf8(&disconnect_output.stderr)
    );
    assert!(utf8(&disconnect_output.stdout).contains("DAM disconnected"));

    let disconnected_status = Command::new(binary("dam"))
        .arg("status")
        .current_dir(dir.path())
        .env("DAM_STATE_DIR", &state_dir)
        .output()
        .expect("run dam status after disconnect");

    assert!(!disconnected_status.status.success());
    assert!(utf8(&disconnected_status.stdout).contains("state: disconnected"));
}

#[test]
fn dam_connect_profile_apply_writes_claude_settings_and_starts_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let home_dir = dir.path().join("home");
    let settings_path = home_dir.join(".claude").join("settings.json");
    let vault_path = dir.path().join("vault.db");
    let log_path = dir.path().join("log.db");
    let consent_path = dir.path().join("consent.db");
    let addr = unused_addr();
    let daemon = DamDaemonGuard::new(state_dir.clone(), dir.path().to_path_buf());

    ensure_binaries();
    let profile_set = Command::new(binary("dam"))
        .args(["profile", "set", "claude-code"])
        .current_dir(dir.path())
        .env("DAM_STATE_DIR", &state_dir)
        .env("HOME", &home_dir)
        .output()
        .expect("run dam profile set");

    assert!(
        profile_set.status.success(),
        "{}",
        utf8(&profile_set.stderr)
    );
    assert!(utf8(&profile_set.stdout).contains("active_profile: claude-code"));

    let connect_output = Command::new(binary("dam"))
        .args([
            "connect",
            "--apply",
            "--listen",
            &addr.to_string(),
            "--db",
            vault_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            "--consent-db",
            consent_path.to_str().unwrap(),
        ])
        .current_dir(dir.path())
        .env("DAM_STATE_DIR", &state_dir)
        .env("HOME", &home_dir)
        .output()
        .expect("run dam connect --apply");

    assert!(
        connect_output.status.success(),
        "{}",
        utf8(&connect_output.stderr)
    );
    let stdout = utf8(&connect_output.stdout);
    assert!(stdout.contains("profile: claude-code"));
    assert!(stdout.contains("integration profile applied"));
    assert!(stdout.contains("rollback: dam integrations rollback claude-code"));
    assert!(stdout.contains(&format!("DAM connected at http://{addr}")));

    let settings: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings_path).unwrap()).unwrap();
    assert_eq!(
        settings["env"]["ANTHROPIC_BASE_URL"],
        format!("http://{addr}")
    );

    let status = Command::new(binary("dam"))
        .arg("status")
        .current_dir(dir.path())
        .env("DAM_STATE_DIR", &state_dir)
        .env("HOME", &home_dir)
        .output()
        .expect("run dam status");

    assert!(status.status.success(), "{}", utf8(&status.stderr));
    let status_stdout = utf8(&status.stdout);
    assert!(status_stdout.contains("state: connected"));
    assert!(status_stdout.contains("active_profile: claude-code"));

    let rollback = Command::new(binary("dam"))
        .args(["integrations", "rollback", "claude-code"])
        .current_dir(dir.path())
        .env("DAM_STATE_DIR", &state_dir)
        .env("HOME", &home_dir)
        .output()
        .expect("run dam integrations rollback");

    assert!(rollback.status.success(), "{}", utf8(&rollback.stderr));
    assert!(!settings_path.exists());

    let disconnect = daemon.disconnect();
    assert!(disconnect.status.success(), "{}", utf8(&disconnect.stderr));
}

#[test]
fn dam_integrations_apply_codex_api_and_rollback_from_binary() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let config_path = dir.path().join("codex.toml");
    let original_config = "approval_policy = \"never\"\n";
    std::fs::write(&config_path, original_config).unwrap();

    ensure_binaries();
    let dry_run = Command::new(binary("dam"))
        .args([
            "integrations",
            "apply",
            "codex-api",
            "--dry-run",
            "--target-path",
            config_path.to_str().unwrap(),
            "--proxy-url",
            "http://127.0.0.1:9000",
        ])
        .current_dir(dir.path())
        .env("DAM_STATE_DIR", &state_dir)
        .output()
        .expect("run dam integrations apply dry-run");

    assert!(dry_run.status.success(), "{}", utf8(&dry_run.stderr));
    assert!(utf8(&dry_run.stdout).contains("dry run complete; no files changed"));
    assert_eq!(
        std::fs::read_to_string(&config_path).unwrap(),
        original_config
    );

    let apply = Command::new(binary("dam"))
        .args([
            "integrations",
            "apply",
            "codex-api",
            "--write",
            "--target-path",
            config_path.to_str().unwrap(),
            "--proxy-url",
            "http://127.0.0.1:9000",
        ])
        .current_dir(dir.path())
        .env("DAM_STATE_DIR", &state_dir)
        .output()
        .expect("run dam integrations apply");

    assert!(apply.status.success(), "{}", utf8(&apply.stderr));
    assert!(utf8(&apply.stdout).contains("integration profile applied"));

    let config = std::fs::read_to_string(&config_path).unwrap();
    assert!(config.contains("approval_policy = \"never\""));
    assert!(config.contains("model_provider = \"dam_openai\""));
    assert!(config.contains("[model_providers.dam_openai]"));
    assert!(config.contains("base_url = \"http://127.0.0.1:9000/v1\""));
    assert!(config.contains("supports_websockets = false"));

    let rollback = Command::new(binary("dam"))
        .args(["integrations", "rollback", "codex-api"])
        .current_dir(dir.path())
        .env("DAM_STATE_DIR", &state_dir)
        .output()
        .expect("run dam integrations rollback");

    assert!(rollback.status.success(), "{}", utf8(&rollback.stderr));
    assert!(utf8(&rollback.stdout).contains("integration profile rolled back"));
    assert_eq!(
        std::fs::read_to_string(&config_path).unwrap(),
        original_config
    );
}

#[test]
fn dam_integrations_apply_claude_code_settings_and_rollback_from_binary() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let settings_path = dir.path().join("settings.json");
    let original_settings = r#"{"env":{"FOO":"bar"}}"#;
    std::fs::write(&settings_path, original_settings).unwrap();

    ensure_binaries();
    let apply = Command::new(binary("dam"))
        .args([
            "integrations",
            "apply",
            "claude-code",
            "--write",
            "--target-path",
            settings_path.to_str().unwrap(),
            "--proxy-url",
            "http://127.0.0.1:9000",
        ])
        .current_dir(dir.path())
        .env("DAM_STATE_DIR", &state_dir)
        .output()
        .expect("run dam integrations apply");

    assert!(apply.status.success(), "{}", utf8(&apply.stderr));
    assert!(utf8(&apply.stdout).contains("integration profile applied"));

    let settings: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings_path).unwrap()).unwrap();
    assert_eq!(settings["env"]["FOO"], "bar");
    assert_eq!(
        settings["env"]["ANTHROPIC_BASE_URL"],
        "http://127.0.0.1:9000"
    );

    let rollback = Command::new(binary("dam"))
        .args(["integrations", "rollback", "claude-code"])
        .current_dir(dir.path())
        .env("DAM_STATE_DIR", &state_dir)
        .output()
        .expect("run dam integrations rollback");

    assert!(rollback.status.success(), "{}", utf8(&rollback.stderr));
    assert!(utf8(&rollback.stdout).contains("integration profile rolled back"));
    assert_eq!(
        std::fs::read_to_string(&settings_path).unwrap(),
        original_settings
    );
}

#[test]
fn filter_then_resolve_roundtrip_survives_reordered_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault.db");
    let log_path = dir.path().join("log.db");
    let raw = "first alice@example.com second bob@example.net";

    let filter_output = run_binary_with_input(
        "dam-filter",
        &[
            "--db",
            vault_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
        ],
        raw,
        dir.path(),
    );
    assert!(
        filter_output.status.success(),
        "{}",
        utf8(&filter_output.stderr)
    );

    let redacted = utf8(&filter_output.stdout);
    assert!(!redacted.contains("alice@example.com"));
    assert!(!redacted.contains("bob@example.net"));

    let references = dam_core::find_references(&redacted);
    assert_eq!(references.len(), 2);
    assert_eq!(
        dam_vault::Vault::open(&vault_path)
            .unwrap()
            .count()
            .unwrap(),
        2
    );

    let reordered = format!(
        "second {} first {}",
        references[1].reference.display(),
        references[0].reference.display()
    );
    let resolve_output = run_binary_with_input(
        "dam-resolve",
        &[
            "--db",
            vault_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            "--report",
        ],
        &reordered,
        dir.path(),
    );
    assert!(
        resolve_output.status.success(),
        "{}",
        utf8(&resolve_output.stderr)
    );
    assert_eq!(
        utf8(&resolve_output.stdout),
        "second bob@example.net first alice@example.com"
    );

    let report = utf8(&resolve_output.stderr);
    assert!(report.contains("references: 2"));
    assert!(report.contains("resolved: 2"));
    assert_logs_do_not_contain(&log_path, &["alice@example.com", "bob@example.net"]);
}

#[tokio::test]
async fn web_reads_vault_and_logs_populated_by_filter() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault.db");
    let log_path = dir.path().join("log.db");
    let addr = unused_addr();

    let filter_output = run_binary_with_input(
        "dam-filter",
        &[
            "--db",
            vault_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
        ],
        "email alice@example.com ssn 123-45-6789",
        dir.path(),
    );
    assert!(
        filter_output.status.success(),
        "{}",
        utf8(&filter_output.stderr)
    );

    let _web = ChildGuard::spawn(
        "dam-web",
        &[
            "--db",
            vault_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            "--addr",
            &addr.to_string(),
        ],
        dir.path(),
    );

    let base = format!("http://{addr}");
    wait_for_ok(&format!("{base}/health")).await;

    let vault_html = reqwest::get(&base).await.unwrap().text().await.unwrap();
    assert!(vault_html.contains("DAM Vault"));
    assert!(vault_html.contains("alice@example.com"));
    assert!(vault_html.contains("123-45-6789"));

    let log_html = reqwest::get(format!("{base}/logs"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(log_html.contains("DAM Logs"));
    assert!(log_html.contains("vault_write"));
    assert!(log_html.contains("redaction"));
    assert!(!log_html.contains("alice@example.com"));
    assert!(!log_html.contains("123-45-6789"));

    let diagnostics_html = reqwest::get(format!("{base}/diagnostics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(diagnostics_html.contains("DAM Diagnostics"));
    assert!(diagnostics_html.contains("Config Check"));
    assert!(diagnostics_html.contains("Proxy Status"));
    assert!(diagnostics_html.contains("proxy is disabled"));
}

#[tokio::test]
async fn proxy_redacts_outbound_and_resolves_inbound_response() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault.db");
    let log_path = dir.path().join("log.db");
    let upstream_seen = Arc::new(Mutex::new(None::<String>));
    let upstream_url = spawn_fake_upstream(upstream_seen.clone()).await;
    let proxy_addr = unused_addr();

    let _proxy = ChildGuard::spawn(
        "dam-proxy",
        &[
            "--listen",
            &proxy_addr.to_string(),
            "--upstream",
            &upstream_url,
            "--no-api-key-env",
            "--db",
            vault_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            "--resolve-inbound",
        ],
        dir.path(),
    );

    let proxy_base = format!("http://{proxy_addr}");
    wait_for_ok(&format!("{proxy_base}/health")).await;

    let raw_body = r#"{"messages":[{"content":"email carol@example.com"}]}"#;
    let response_body = reqwest::Client::new()
        .post(format!("{proxy_base}/v1/chat/completions"))
        .body(raw_body)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(response_body, raw_body);

    let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
    assert!(!upstream_body.contains("carol@example.com"));
    assert!(upstream_body.contains("[email:"));
    let vault_entries = dam_vault::Vault::open(&vault_path).unwrap().list().unwrap();
    assert_eq!(vault_entries.len(), 1);
    assert!(
        upstream_body.contains(&vault_entries[0].key),
        "upstream token did not match vault key: upstream={upstream_body}, key={}",
        vault_entries[0].key
    );

    let resolve_output = run_binary_with_input(
        "dam-resolve",
        &["--db", vault_path.to_str().unwrap(), "--report"],
        &upstream_body,
        dir.path(),
    );
    assert!(
        resolve_output.status.success(),
        "{}",
        utf8(&resolve_output.stderr)
    );
    assert_eq!(
        utf8(&resolve_output.stdout),
        raw_body,
        "{}",
        utf8(&resolve_output.stderr)
    );

    let logs = dam_log::LogStore::open(&log_path).unwrap().list().unwrap();
    assert!(logs.iter().any(|entry| entry.event_type == "proxy_forward"));
    assert!(logs.iter().any(|entry| entry.event_type == "vault_write"));
    assert!(logs.iter().any(|entry| entry.event_type == "vault_read"));
    assert!(logs.iter().any(|entry| entry.event_type == "resolve"));
    assert_logs_do_not_contain(&log_path, &["carol@example.com"]);
}

#[tokio::test]
async fn proxy_can_leave_inbound_references_unresolved() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault.db");
    let log_path = dir.path().join("log.db");
    let upstream_seen = Arc::new(Mutex::new(None::<String>));
    let upstream_url = spawn_fake_upstream(upstream_seen.clone()).await;
    let proxy_addr = unused_addr();

    let _proxy = ChildGuard::spawn(
        "dam-proxy",
        &[
            "--listen",
            &proxy_addr.to_string(),
            "--upstream",
            &upstream_url,
            "--no-resolve-inbound",
            "--no-api-key-env",
            "--db",
            vault_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
        ],
        dir.path(),
    );

    let proxy_base = format!("http://{proxy_addr}");
    wait_for_ok(&format!("{proxy_base}/health")).await;

    let response_body = reqwest::Client::new()
        .post(format!("{proxy_base}/v1/chat/completions"))
        .body(r#"{"messages":[{"content":"email dave@example.com"}]}"#)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(!response_body.contains("dave@example.com"));
    assert!(response_body.contains("[email:"));

    let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
    assert_eq!(response_body, upstream_body);

    let logs = dam_log::LogStore::open(&log_path).unwrap().list().unwrap();
    assert!(logs.iter().any(|entry| entry.event_type == "proxy_forward"));
    assert!(logs.iter().any(|entry| entry.event_type == "vault_write"));
    assert!(!logs.iter().any(|entry| entry.event_type == "vault_read"));
    assert!(!logs.iter().any(|entry| entry.event_type == "resolve"));
    assert_logs_do_not_contain(&log_path, &["dave@example.com"]);
}

async fn spawn_fake_upstream(seen_body: Arc<Mutex<Option<String>>>) -> String {
    async fn echo(State(seen_body): State<Arc<Mutex<Option<String>>>>, body: Bytes) -> Response {
        let body_text = String::from_utf8(body.to_vec()).expect("upstream body should be utf-8");
        *seen_body.lock().unwrap() = Some(body_text.clone());
        (StatusCode::OK, body_text).into_response()
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake upstream");
    let addr = listener.local_addr().expect("fake upstream addr");
    let app = Router::new().fallback(post(echo)).with_state(seen_body);

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("fake upstream server");
    });

    format!("http://{addr}")
}
