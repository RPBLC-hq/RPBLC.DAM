use serde_json::{Value, json};
use std::env;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;

const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default)]
struct CliArgs {
    config: dam_config::ConfigOverrides,
}

fn main() {
    let cli = match parse_args(env::args().skip(1)) {
        Ok(cli) => cli,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };

    let config = match dam_config::load(&cli.config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("failed to load config: {error}");
            std::process::exit(2);
        }
    };

    let stdin = io::stdin();
    let stdout = io::stdout();
    if let Err(error) = run_stdio(&config, stdin.lock(), stdout.lock()) {
        eprintln!("stdio error: {error}");
        std::process::exit(1);
    }
}

fn run_stdio<R: Read, W: Write>(
    config: &dam_config::DamConfig,
    input: R,
    mut output: W,
) -> io::Result<()> {
    let mut reader = BufReader::new(input);
    while let Some(message) = read_message(&mut reader)? {
        if let Some(response) = handle_message(config, &message) {
            write_response(&mut output, &response)?;
        }
    }
    Ok(())
}

fn handle_message(config: &dam_config::DamConfig, message: &Value) -> Option<Value> {
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str)?;
    match method {
        "initialize" => Some(success(
            id,
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "dam-mcp", "version": env!("CARGO_PKG_VERSION") }
            }),
        )),
        "notifications/initialized" => None,
        "tools/list" => Some(success(id, json!({ "tools": tools(config) }))),
        "tools/call" => Some(handle_tool_call(config, id, message)),
        _ => Some(error(id, -32601, "method not found")),
    }
}

fn tools(config: &dam_config::DamConfig) -> Vec<Value> {
    let mut tools = vec![json!({
        "name": "dam_consent_list",
        "description": "List DAM passthrough consents.",
        "inputSchema": { "type": "object", "properties": {} }
    })];

    if config.consent.mcp_write_enabled {
        tools.push(json!({
            "name": "dam_consent_grant",
            "description": "Grant passthrough consent for a DAM vault key.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vault_key": { "type": "string" },
                    "ttl_seconds": { "type": "integer" },
                    "reason": { "type": "string" }
                },
                "required": ["vault_key"]
            }
        }));
        tools.push(json!({
            "name": "dam_consent_revoke",
            "description": "Revoke a DAM passthrough consent by consent id.",
            "inputSchema": {
                "type": "object",
                "properties": { "consent_id": { "type": "string" } },
                "required": ["consent_id"]
            }
        }));
    }

    tools
}

fn handle_tool_call(config: &dam_config::DamConfig, id: Option<Value>, message: &Value) -> Value {
    let Some(params) = message.get("params") else {
        return error(id, -32602, "missing params");
    };
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return error(id, -32602, "missing tool name");
    };
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    match call_tool(config, name, &arguments) {
        Ok(result) => success(
            id,
            json!({ "content": [{ "type": "text", "text": result }] }),
        ),
        Err(message) => success(
            id,
            json!({
                "isError": true,
                "content": [{ "type": "text", "text": message }]
            }),
        ),
    }
}

fn call_tool(
    config: &dam_config::DamConfig,
    name: &str,
    arguments: &Value,
) -> Result<String, String> {
    let store = open_consent_store(config)?;
    match name {
        "dam_consent_list" => {
            let entries = store.list().map_err(|error| error.to_string())?;
            Ok(serde_json::to_string(&json!({ "consents": entries_to_json(&entries) })).unwrap())
        }
        "dam_consent_grant" if config.consent.mcp_write_enabled => {
            let vault_key = arguments
                .get("vault_key")
                .and_then(Value::as_str)
                .ok_or_else(|| "vault_key is required".to_string())?;
            let ttl_seconds = arguments
                .get("ttl_seconds")
                .and_then(Value::as_u64)
                .unwrap_or(config.consent.default_ttl_seconds);
            let reason = arguments
                .get("reason")
                .and_then(Value::as_str)
                .map(str::to_string);
            let vault = open_vault(config)?;
            let entry = store
                .grant_for_reference(vault_key, &vault, ttl_seconds, "dam-mcp", reason)
                .map_err(|error| error.to_string())?;
            Ok(serde_json::to_string(&entry_to_json(&entry)).unwrap())
        }
        "dam_consent_revoke" if config.consent.mcp_write_enabled => {
            let consent_id = arguments
                .get("consent_id")
                .and_then(Value::as_str)
                .ok_or_else(|| "consent_id is required".to_string())?;
            let revoked = store
                .revoke(consent_id)
                .map_err(|error| error.to_string())?;
            Ok(serde_json::to_string(&json!({ "revoked": revoked })).unwrap())
        }
        "dam_consent_request" => Err("dam_consent_request is parked until dam-notify".to_string()),
        _ => Err("unknown or disabled tool".to_string()),
    }
}

fn open_consent_store(config: &dam_config::DamConfig) -> Result<dam_consent::ConsentStore, String> {
    if !config.consent.enabled {
        return Err("consent is disabled".to_string());
    }
    match config.consent.backend {
        dam_config::ConsentBackend::Sqlite => {
            dam_consent::ConsentStore::open(&config.consent.sqlite_path)
                .map_err(|error| error.to_string())
        }
    }
}

fn open_vault(config: &dam_config::DamConfig) -> Result<dam_vault::Vault, String> {
    match config.vault.backend {
        dam_config::VaultBackend::Sqlite => {
            dam_vault::Vault::open(&config.vault.sqlite_path).map_err(|error| error.to_string())
        }
        dam_config::VaultBackend::Remote => {
            Err("remote vault backend is not implemented".to_string())
        }
    }
}

fn entries_to_json(entries: &[dam_consent::ConsentEntry]) -> Vec<Value> {
    entries.iter().map(entry_to_json).collect()
}

fn entry_to_json(entry: &dam_consent::ConsentEntry) -> Value {
    json!({
        "id": entry.id,
        "kind": entry.kind.tag(),
        "vault_key": entry.vault_key,
        "scope": entry.scope,
        "created_at": entry.created_at,
        "expires_at": entry.expires_at,
        "revoked_at": entry.revoked_at,
        "created_by": entry.created_by,
        "reason": entry.reason,
    })
}

fn success(id: Option<Value>, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error(id: Option<Value>, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
}

fn read_message<R: BufRead>(reader: &mut R) -> io::Result<Option<Value>> {
    let Some(content_length) = read_content_length(reader)? else {
        return Ok(None);
    };
    if content_length > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("MCP message exceeds {MAX_MESSAGE_BYTES} byte limit"),
        ));
    }
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body)?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn read_content_length<R: BufRead>(reader: &mut R) -> io::Result<Option<usize>> {
    let mut content_length = None;
    loop {
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            return if content_length.is_some() {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF in message headers",
                ))
            } else {
                Ok(None)
            };
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(value) = line.strip_prefix("Content-Length:") {
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            );
        }
    }

    content_length
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length header"))
        .map(Some)
}

fn write_response<W: Write>(output: &mut W, response: &Value) -> io::Result<()> {
    let payload = response.to_string();
    write!(
        output,
        "Content-Length: {}\r\n\r\n{}",
        payload.len(),
        payload
    )?;
    output.flush()
}

#[cfg(test)]
fn parse_messages(input: &str) -> Vec<Value> {
    if input.trim_start().starts_with('{') {
        return serde_json::from_str(input)
            .map(|value| vec![value])
            .unwrap_or_default();
    }

    let mut messages = Vec::new();
    let mut rest = input;
    while let Some(header_end) = rest.find("\r\n\r\n") {
        let header = &rest[..header_end];
        let content_length = header.lines().find_map(|line| {
            line.strip_prefix("Content-Length:")
                .and_then(|value| value.trim().parse::<usize>().ok())
        });
        let Some(content_length) = content_length else {
            break;
        };
        let body_start = header_end + 4;
        if rest.len() < body_start + content_length {
            break;
        }
        let body = &rest[body_start..body_start + content_length];
        if let Ok(message) = serde_json::from_str(body) {
            messages.push(message);
        }
        rest = &rest[body_start + content_length..];
    }

    messages
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<CliArgs, String> {
    let args = args.into_iter().collect::<Vec<_>>();
    let mut cli = CliArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--config requires a path".to_string())?;
                cli.config.config_path = Some(PathBuf::from(value));
            }
            "--db" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--db requires a path".to_string())?;
                cli.config.vault_sqlite_path = Some(PathBuf::from(value));
            }
            "--consent-db" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--consent-db requires a path".to_string())?;
                cli.config.consent_sqlite_path = Some(PathBuf::from(value));
            }
            "-h" | "--help" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }
    Ok(cli)
}

fn usage() -> &'static str {
    "Usage: dam-mcp [--config dam.toml] [--db vault.db] [--consent-db consent.db]"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_tools() {
        let config = dam_config::DamConfig::default();
        let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
        let response = handle_message(&config, &request).unwrap();

        assert!(response.to_string().contains("dam_consent_grant"));
        assert!(response.to_string().contains("dam_consent_revoke"));
    }

    #[test]
    fn parses_content_length_messages() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let input = format!("Content-Length: {}\r\n\r\n{}", body.len(), body);

        let messages = parse_messages(&input);

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["method"], "tools/list");
    }

    #[test]
    fn stdio_handles_framed_messages_in_sequence() {
        let config = dam_config::DamConfig::default();
        let initialize = r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
        let tools = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        let input = format!(
            "Content-Length: {}\r\n\r\n{}Content-Length: {}\r\n\r\n{}",
            initialize.len(),
            initialize,
            tools.len(),
            tools
        );
        let mut output = Vec::new();

        run_stdio(&config, input.as_bytes(), &mut output).unwrap();

        let output = String::from_utf8(output).unwrap();
        let responses = parse_messages(&output);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[0]["result"]["serverInfo"]["name"], "dam-mcp");
        assert_eq!(responses[1]["id"], 2);
        assert!(responses[1].to_string().contains("dam_consent_list"));
    }

    #[test]
    fn stdio_rejects_oversized_message_frames() {
        let config = dam_config::DamConfig::default();
        let input = format!("Content-Length: {}\r\n\r\n{{}}", MAX_MESSAGE_BYTES + 1);
        let mut output = Vec::new();

        let error = run_stdio(&config, input.as_bytes(), &mut output).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(output.is_empty());
    }
}
