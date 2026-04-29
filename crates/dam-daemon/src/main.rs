use std::env;

#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    };

    std::process::exit(code);
}

async fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if matches!(args.first().map(String::as_str), Some("-h" | "--help")) {
        println!("{}", usage());
        return Ok(());
    }
    if args.first().map(String::as_str) != Some("run") {
        return Err(usage().to_string());
    }
    if matches!(args.get(1).map(String::as_str), Some("-h" | "--help")) {
        println!("{}", usage_run());
        return Ok(());
    }

    let options = dam_daemon::parse_proxy_options(args.into_iter().skip(1))?;
    let config = dam_daemon::proxy_config(&options)?;
    dam_daemon::serve(config, options.config_path)
        .await
        .map_err(|error| format!("dam-daemon failed: {error}"))
}

fn usage() -> &'static str {
    "Usage: dam-daemon run [OPTIONS]\n\nRun `dam-daemon run --help` for options."
}

fn usage_run() -> &'static str {
    "Usage: dam-daemon run [--openai|--anthropic] [--config dam.toml] [--listen 127.0.0.1:7828] [--target-name NAME] [--provider openai-compatible|anthropic] [--upstream URL] [--db vault.db] [--log log.db|--no-log] [--consent-db consent.db] [--resolve-inbound|--no-resolve-inbound]"
}
