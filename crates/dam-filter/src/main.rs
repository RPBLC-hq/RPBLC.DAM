use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use dam_policy::PolicyEngine;

#[derive(Debug, Clone, Default)]
struct CliArgs {
    config: dam_config::ConfigOverrides,
    file: Option<PathBuf>,
    report: bool,
    json_report: bool,
}

fn main() {
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

    let input = match read_input(&cli) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("failed to read input: {error}");
            std::process::exit(1);
        }
    };

    let db_path = match vault_db_path(&config) {
        Ok(path) => path,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };

    let vault = match dam_vault::Vault::open(db_path) {
        Ok(vault) => vault,
        Err(error) => {
            eprintln!("failed to open vault db {}: {error}", db_path.display());
            std::process::exit(1);
        }
    };

    let consent_store = match open_consent_store(&config) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("failed to open consent db: {error}");
            std::process::exit(1);
        }
    };

    let log_path = match log_db_path(&config) {
        Ok(log_path) => log_path,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };

    let detections = dam_detect::detect(&input);
    let policy = dam_policy::StaticPolicy::from(config.policy.clone());
    let base_decisions = policy.decide_all(&detections);
    let (decisions, consent_matches) =
        match dam_consent::apply_consents_to_decisions(&base_decisions, consent_store.as_ref()) {
            Ok(result) => result,
            Err(error) => {
                eprintln!("failed to apply consents: {error}");
                std::process::exit(1);
            }
        };
    let operation_id = dam_core::generate_operation_id();

    if decisions
        .iter()
        .any(|decision| decision.action == dam_core::PolicyAction::Block)
    {
        let plan = blocked_plan_from_decisions(&decisions);
        record_log_events(log_path, &operation_id, &decisions, &plan, &consent_matches);
        if cli.json_report {
            print_json_report(&operation_id, &decisions, &plan);
        } else {
            print_blocked_report(&operation_id, &plan);
        }
        std::process::exit(1);
    }

    let plan = dam_core::build_replacement_plan_from_decisions_with_options(
        &decisions,
        &vault,
        dam_core::ReplacementPlanOptions {
            deduplicate_replacements: config.policy.deduplicate_replacements,
        },
    );
    record_log_events(log_path, &operation_id, &decisions, &plan, &consent_matches);
    let output = dam_redact::redact(&input, &plan.replacements);

    print!("{output}");

    if cli.json_report {
        print_json_report(&operation_id, &decisions, &plan);
    } else if cli.report {
        print_text_report(&operation_id, &detections, &decisions, &plan);
    }
}

fn blocked_plan_from_decisions(
    decisions: &[dam_core::PolicyDecision],
) -> dam_core::ReplacementPlan {
    dam_core::ReplacementPlan {
        blocked: decisions
            .iter()
            .filter(|decision| decision.action == dam_core::PolicyAction::Block)
            .map(|decision| dam_core::BlockedDetection {
                kind: decision.detection.kind,
                span: decision.detection.span,
            })
            .collect(),
        ..dam_core::ReplacementPlan::default()
    }
}

fn policy_action_count(
    decisions: &[dam_core::PolicyDecision],
    action: dam_core::PolicyAction,
) -> usize {
    decisions
        .iter()
        .filter(|decision| decision.action == action)
        .count()
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<CliArgs, String> {
    let args = args.into_iter().collect::<Vec<_>>();
    let mut cli = CliArgs::default();
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--report" => cli.report = true,
            "--json-report" => cli.json_report = true,
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
            _ if arg.starts_with('-') => return Err(format!("unknown argument: {arg}")),
            _ => {
                if cli.file.is_some() {
                    return Err("only one input file is supported".to_string());
                }
                cli.file = Some(PathBuf::from(arg));
            }
        }
        i += 1;
    }

    Ok(cli)
}

fn vault_db_path(config: &dam_config::DamConfig) -> Result<&Path, String> {
    match config.vault.backend {
        dam_config::VaultBackend::Sqlite => Ok(&config.vault.sqlite_path),
        dam_config::VaultBackend::Remote => Err(
            "remote vault backend is configured but not implemented in dam-filter yet".to_string(),
        ),
    }
}

fn log_db_path(config: &dam_config::DamConfig) -> Result<Option<&Path>, String> {
    if !config.log.enabled || config.log.backend == dam_config::LogBackend::None {
        return Ok(None);
    }

    match config.log.backend {
        dam_config::LogBackend::Sqlite => Ok(Some(&config.log.sqlite_path)),
        dam_config::LogBackend::Remote => Err(
            "remote log backend is configured but not implemented in dam-filter yet".to_string(),
        ),
        dam_config::LogBackend::None => Ok(None),
    }
}

fn open_consent_store(
    config: &dam_config::DamConfig,
) -> Result<Option<dam_consent::ConsentStore>, dam_consent::ConsentError> {
    if !config.consent.enabled {
        return Ok(None);
    }

    match config.consent.backend {
        dam_config::ConsentBackend::Sqlite => {
            dam_consent::ConsentStore::open(&config.consent.sqlite_path).map(Some)
        }
    }
}

fn record_log_events(
    log_path: Option<&Path>,
    operation_id: &str,
    decisions: &[dam_core::PolicyDecision],
    plan: &dam_core::ReplacementPlan,
    consent_matches: &[dam_consent::ConsentMatch],
) {
    let Some(log_path) = log_path else {
        return;
    };

    let store = match dam_log::LogStore::open(log_path) {
        Ok(store) => store,
        Err(error) => {
            eprintln!(
                "log_warning failed to open log db {}: {error}",
                log_path.display()
            );
            return;
        }
    };

    for event in dam_core::build_filter_log_events_from_decisions(operation_id, decisions, plan) {
        if let Err(error) = dam_core::EventSink::record(&store, &event) {
            eprintln!("log_warning failed to write log event: {error}");
            return;
        }
    }

    for consent_match in consent_matches {
        let event = dam_core::LogEvent::new(
            operation_id,
            dam_core::LogLevel::Info,
            dam_core::LogEventType::Consent,
            "active consent allowed detected value",
        )
        .with_kind(consent_match.kind)
        .with_action(format!("allow:{}", consent_match.consent_id));
        if let Err(error) = dam_core::EventSink::record(&store, &event) {
            eprintln!("log_warning failed to write log event: {error}");
            return;
        }
    }
}

fn read_input(cli: &CliArgs) -> io::Result<String> {
    match &cli.file {
        Some(path) => fs::read_to_string(path),
        None => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input)?;
            Ok(input)
        }
    }
}

fn print_blocked_report(operation_id: &str, plan: &dam_core::ReplacementPlan) {
    eprintln!("operation_id: {operation_id}");
    eprintln!("blocked: {}", plan.blocked_count());
    for blocked in &plan.blocked {
        eprintln!(
            "policy_block {} {}..{}",
            blocked.kind.tag(),
            blocked.span.start,
            blocked.span.end
        );
    }
}

fn print_text_report(
    operation_id: &str,
    detections: &[dam_core::Detection],
    decisions: &[dam_core::PolicyDecision],
    plan: &dam_core::ReplacementPlan,
) {
    eprintln!("operation_id: {operation_id}");
    eprintln!("detections: {}", detections.len());
    eprintln!("stored: {}", plan.vault_write_count());
    eprintln!("policy_redactions: {}", plan.redacted_count());
    eprintln!(
        "allowed: {}",
        policy_action_count(decisions, dam_core::PolicyAction::Allow)
    );
    eprintln!("blocked: {}", plan.blocked_count());
    eprintln!("fallback_redactions: {}", plan.fallback_count());
    for detection in detections {
        eprintln!(
            "{} {}..{} {}",
            detection.kind.tag(),
            detection.span.start,
            detection.span.end,
            preview(&detection.value)
        );
    }
    for failure in &plan.vault_failures {
        eprintln!(
            "vault_error {} {} {}",
            failure.kind.tag(),
            failure.value_preview,
            dam_api::VAULT_WRITE_FAILURE_REPORT_ERROR
        );
    }
}

fn print_json_report(
    operation_id: &str,
    decisions: &[dam_core::PolicyDecision],
    plan: &dam_core::ReplacementPlan,
) {
    let report = dam_api::filter_report_from_decisions(operation_id, decisions, plan);
    match serde_json::to_string_pretty(&report) {
        Ok(json) => eprintln!("{json}"),
        Err(error) => eprintln!("report_warning failed to serialize json report: {error}"),
    }
}

fn preview(value: &str) -> String {
    let mut preview = value.chars().take(4).collect::<String>();
    if value.chars().count() > 4 {
        preview.push_str("...");
    }
    preview
}

fn usage() -> &'static str {
    "Usage: dam-filter [--config dam.toml] [--db vault.db] [--log log.db] [--no-log] [--report] [--json-report] [FILE]"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_defaults_to_stdin() {
        let cli = parse_args(Vec::new()).unwrap();

        assert_eq!(cli.config, dam_config::ConfigOverrides::default());
        assert!(cli.file.is_none());
        assert!(!cli.report);
        assert!(!cli.json_report);
    }

    #[test]
    fn parse_args_accepts_config_db_log_report_and_file() {
        let cli = parse_args([
            "--config".to_string(),
            "/tmp/dam.toml".to_string(),
            "--db".to_string(),
            "/tmp/vault.db".to_string(),
            "--log".to_string(),
            "/tmp/log.db".to_string(),
            "--report".to_string(),
            "--json-report".to_string(),
            "input.txt".to_string(),
        ])
        .unwrap();

        assert_eq!(cli.config.config_path, Some(PathBuf::from("/tmp/dam.toml")));
        assert_eq!(
            cli.config.vault_sqlite_path,
            Some(PathBuf::from("/tmp/vault.db"))
        );
        assert_eq!(
            cli.config.log_sqlite_path,
            Some(PathBuf::from("/tmp/log.db"))
        );
        assert_eq!(cli.file, Some(PathBuf::from("input.txt")));
        assert!(cli.report);
        assert!(cli.json_report);
    }

    #[test]
    fn parse_args_accepts_no_log_override() {
        let cli = parse_args(["--no-log".to_string()]).unwrap();

        assert_eq!(cli.config.log_enabled, Some(false));
    }

    #[test]
    fn preview_short_values_are_unchanged() {
        assert_eq!(preview("abc"), "abc");
    }

    #[test]
    fn preview_long_values_are_truncated() {
        assert_eq!(preview("abcdef"), "abcd...");
    }
}
