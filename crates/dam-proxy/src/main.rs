use std::{env, path::PathBuf, str::FromStr};

#[derive(Debug, Clone, Default)]
struct CliArgs {
    config: dam_config::ConfigOverrides,
}

#[tokio::main]
async fn main() {
    let cli = match parse_args(env::args().skip(1)) {
        Ok(cli) => cli,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("{}", usage());
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

    if let Err(error) = dam_proxy::run(config).await {
        eprintln!("dam-proxy failed: {error}");
        std::process::exit(1);
    }
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<CliArgs, String> {
    let args = args.into_iter().collect::<Vec<_>>();
    let mut cli = CliArgs::default();
    cli.config.proxy_enabled = Some(true);

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--config" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--config requires a path".to_string())?;
                cli.config.config_path = Some(PathBuf::from(value));
            }
            "--listen" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--listen requires an address".to_string())?;
                cli.config.proxy_listen = Some(value.clone());
            }
            "--upstream" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--upstream requires a URL".to_string())?;
                cli.config.proxy_target_upstream = Some(value.clone());
            }
            "--target-name" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--target-name requires a value".to_string())?;
                cli.config.proxy_target_name = Some(value.clone());
            }
            "--provider" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--provider requires a value".to_string())?;
                cli.config.proxy_target_provider = Some(value.clone());
            }
            "--failure-mode" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--failure-mode requires a value".to_string())?;
                cli.config.proxy_target_failure_mode = Some(
                    dam_config::ProxyFailureMode::from_str(value)
                        .map_err(|error| format!("invalid --failure-mode value: {error}"))?,
                );
            }
            "--resolve-inbound" => {
                cli.config.proxy_resolve_inbound = Some(true);
            }
            "--no-resolve-inbound" => {
                cli.config.proxy_resolve_inbound = Some(false);
            }
            "--api-key-env" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--api-key-env requires an env var name".to_string())?;
                cli.config.proxy_target_api_key_env = Some(value.clone());
            }
            "--no-api-key-env" => {
                cli.config.proxy_target_api_key_env = Some(String::new());
            }
            "--db" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--db requires a path".to_string())?;
                cli.config.vault_sqlite_path = Some(PathBuf::from(value));
            }
            "--log" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--log requires a path".to_string())?;
                cli.config.log_sqlite_path = Some(PathBuf::from(value));
            }
            "--no-log" => {
                cli.config.log_enabled = Some(false);
            }
            "-h" | "--help" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
        i += 1;
    }

    Ok(cli)
}

fn usage() -> &'static str {
    "Usage: dam-proxy [--config dam.toml] [--listen 127.0.0.1:7828] --upstream URL [--target-name NAME] [--provider openai-compatible] [--failure-mode bypass_on_error|redact_only|block_on_error] [--resolve-inbound|--no-resolve-inbound] [--api-key-env NAME|--no-api-key-env] [--db vault.db] [--log log.db|--no-log]"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_enables_proxy_and_accepts_upstream() {
        let cli = parse_args([
            "--listen".to_string(),
            "127.0.0.1:9000".to_string(),
            "--upstream".to_string(),
            "http://127.0.0.1:9999".to_string(),
            "--no-resolve-inbound".to_string(),
            "--no-api-key-env".to_string(),
        ])
        .unwrap();

        assert_eq!(cli.config.proxy_enabled, Some(true));
        assert_eq!(cli.config.proxy_listen, Some("127.0.0.1:9000".to_string()));
        assert_eq!(
            cli.config.proxy_target_upstream,
            Some("http://127.0.0.1:9999".to_string())
        );
        assert_eq!(cli.config.proxy_resolve_inbound, Some(false));
        assert_eq!(cli.config.proxy_target_api_key_env, Some(String::new()));
    }

    #[test]
    fn parse_args_rejects_unknown_args() {
        assert!(parse_args(["--wat".to_string()]).is_err());
    }
}
