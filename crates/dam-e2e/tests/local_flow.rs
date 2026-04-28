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
