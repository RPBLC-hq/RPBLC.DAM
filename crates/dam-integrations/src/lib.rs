use serde::{Deserialize, Serialize};

pub const DEFAULT_PROXY_URL: &str = "http://127.0.0.1:7828";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationProfile {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub provider: String,
    pub connect_args: Vec<String>,
    pub settings: Vec<IntegrationSetting>,
    pub commands: Vec<IntegrationCommand>,
    pub notes: Vec<String>,
    pub automation: AutomationLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationSetting {
    pub key: String,
    pub value: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationCommand {
    pub label: String,
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationLevel {
    Manual,
    ConnectPreset,
}

pub fn profiles(proxy_url: &str) -> Vec<IntegrationProfile> {
    vec![
        openai_compatible(proxy_url),
        anthropic(proxy_url),
        claude_code(proxy_url),
        codex_api(proxy_url),
        xai_compatible(proxy_url),
    ]
}

pub fn profile(id: &str, proxy_url: &str) -> Option<IntegrationProfile> {
    profiles(proxy_url)
        .into_iter()
        .find(|profile| profile.id == id)
}

pub fn profile_ids() -> Vec<&'static str> {
    vec![
        "openai-compatible",
        "anthropic",
        "claude-code",
        "codex-api",
        "xai-compatible",
    ]
}

pub fn openai_base_url(proxy_url: &str) -> String {
    format!("{}/v1", proxy_url.trim_end_matches('/'))
}

fn openai_compatible(proxy_url: &str) -> IntegrationProfile {
    IntegrationProfile {
        id: "openai-compatible".to_string(),
        name: "Generic OpenAI-compatible harness".to_string(),
        summary: "Point an OpenAI-compatible SDK or harness at the local DAM /v1 endpoint."
            .to_string(),
        provider: "openai-compatible".to_string(),
        connect_args: vec!["--openai".to_string()],
        settings: vec![IntegrationSetting {
            key: "OPENAI_BASE_URL".to_string(),
            value: openai_base_url(proxy_url),
            description: "OpenAI-compatible base URL for clients that honor OPENAI_BASE_URL"
                .to_string(),
        }],
        commands: vec![IntegrationCommand {
            label: "Start DAM for OpenAI-compatible traffic".to_string(),
            command: vec![
                "dam".to_string(),
                "connect".to_string(),
                "--openai".to_string(),
            ],
        }],
        notes: vec![
            "Keep provider credentials owned by the harness. DAM forwards caller auth headers."
                .to_string(),
            "Use this for SDKs and tools that let you set an OpenAI-compatible base URL."
                .to_string(),
        ],
        automation: AutomationLevel::ConnectPreset,
    }
}

fn anthropic(proxy_url: &str) -> IntegrationProfile {
    IntegrationProfile {
        id: "anthropic".to_string(),
        name: "Generic Anthropic-compatible harness".to_string(),
        summary: "Point an Anthropic-compatible harness at the local DAM endpoint.".to_string(),
        provider: "anthropic".to_string(),
        connect_args: vec!["--anthropic".to_string()],
        settings: vec![IntegrationSetting {
            key: "ANTHROPIC_BASE_URL".to_string(),
            value: proxy_url.trim_end_matches('/').to_string(),
            description: "Anthropic-compatible base URL for clients that honor ANTHROPIC_BASE_URL"
                .to_string(),
        }],
        commands: vec![IntegrationCommand {
            label: "Start DAM for Anthropic traffic".to_string(),
            command: vec![
                "dam".to_string(),
                "connect".to_string(),
                "--anthropic".to_string(),
            ],
        }],
        notes: vec![
            "Keep provider credentials owned by the harness. DAM forwards caller auth headers."
                .to_string(),
            "Use this for tools that speak Anthropic's HTTP API and expose a base URL setting."
                .to_string(),
        ],
        automation: AutomationLevel::ConnectPreset,
    }
}

fn claude_code(proxy_url: &str) -> IntegrationProfile {
    IntegrationProfile {
        id: "claude-code".to_string(),
        name: "Claude Code".to_string(),
        summary: "Run Claude Code through a background Anthropic-compatible DAM endpoint."
            .to_string(),
        provider: "anthropic".to_string(),
        connect_args: vec!["--anthropic".to_string()],
        settings: vec![IntegrationSetting {
            key: "ANTHROPIC_BASE_URL".to_string(),
            value: proxy_url.trim_end_matches('/').to_string(),
            description: "Claude Code base URL override".to_string(),
        }],
        commands: vec![
            IntegrationCommand {
                label: "Start DAM for Claude Code".to_string(),
                command: vec![
                    "dam".to_string(),
                    "connect".to_string(),
                    "--anthropic".to_string(),
                ],
            },
            IntegrationCommand {
                label: "Launch Claude Code against the connected daemon".to_string(),
                command: vec![
                    "env".to_string(),
                    format!("ANTHROPIC_BASE_URL={}", proxy_url.trim_end_matches('/')),
                    "claude".to_string(),
                ],
            },
        ],
        notes: vec![
            "`dam claude` remains the one-shot path when a background daemon is not needed."
                .to_string(),
            "Claude Code keeps provider authentication; DAM only receives and forwards the request headers.".to_string(),
        ],
        automation: AutomationLevel::ConnectPreset,
    }
}

fn codex_api(proxy_url: &str) -> IntegrationProfile {
    let base_url = openai_base_url(proxy_url);
    IntegrationProfile {
        id: "codex-api".to_string(),
        name: "Codex API-key mode".to_string(),
        summary: "Point Codex API-key mode at a background OpenAI-compatible DAM endpoint."
            .to_string(),
        provider: "openai-compatible".to_string(),
        connect_args: vec!["--openai".to_string()],
        settings: vec![
            IntegrationSetting {
                key: "model_provider".to_string(),
                value: "dam_openai".to_string(),
                description: "Temporary Codex provider id for DAM-routed API-key mode".to_string(),
            },
            IntegrationSetting {
                key: "model_providers.dam_openai.base_url".to_string(),
                value: base_url.clone(),
                description: "OpenAI Responses API base URL through DAM".to_string(),
            },
            IntegrationSetting {
                key: "model_providers.dam_openai.env_key".to_string(),
                value: "OPENAI_API_KEY".to_string(),
                description: "Codex still owns the provider API key".to_string(),
            },
            IntegrationSetting {
                key: "model_providers.dam_openai.supports_websockets".to_string(),
                value: "false".to_string(),
                description: "Disable Codex WebSockets until DAM has a WebSocket adapter"
                    .to_string(),
            },
        ],
        commands: vec![
            IntegrationCommand {
                label: "Start DAM for Codex API-key mode".to_string(),
                command: vec!["dam".to_string(), "connect".to_string(), "--openai".to_string()],
            },
            IntegrationCommand {
                label: "Launch Codex against the connected daemon".to_string(),
                command: codex_command(&base_url),
            },
        ],
        notes: vec![
            "`dam codex --api` remains the one-shot protected path.".to_string(),
            "Codex ChatGPT-login mode is still not protected by this profile because its model transport uses the ChatGPT backend path/WebSocket flow.".to_string(),
        ],
        automation: AutomationLevel::ConnectPreset,
    }
}

fn xai_compatible(proxy_url: &str) -> IntegrationProfile {
    IntegrationProfile {
        id: "xai-compatible".to_string(),
        name: "xAI OpenAI-compatible harness".to_string(),
        summary: "Start DAM with xAI as an OpenAI-compatible upstream target.".to_string(),
        provider: "openai-compatible".to_string(),
        connect_args: vec![
            "--target-name".to_string(),
            "xai".to_string(),
            "--provider".to_string(),
            "openai-compatible".to_string(),
            "--upstream".to_string(),
            "https://api.x.ai".to_string(),
        ],
        settings: vec![IntegrationSetting {
            key: "OPENAI_BASE_URL".to_string(),
            value: openai_base_url(proxy_url),
            description: "OpenAI-compatible base URL exposed by DAM for the harness".to_string(),
        }],
        commands: vec![IntegrationCommand {
            label: "Start DAM with xAI upstream".to_string(),
            command: vec![
                "dam".to_string(),
                "connect".to_string(),
                "--profile".to_string(),
                "xai-compatible".to_string(),
            ],
        }],
        notes: vec![
            "The harness still owns provider credentials. Configure its xAI API key through the harness's normal secret mechanism.".to_string(),
            "This profile only selects the upstream target and exposes a local OpenAI-compatible DAM endpoint.".to_string(),
        ],
        automation: AutomationLevel::ConnectPreset,
    }
}

fn codex_command(base_url: &str) -> Vec<String> {
    vec![
        "codex".to_string(),
        "-c".to_string(),
        "model_provider=\"dam_openai\"".to_string(),
        "-c".to_string(),
        "model_providers.dam_openai.name=\"OpenAI through DAM\"".to_string(),
        "-c".to_string(),
        format!("model_providers.dam_openai.base_url=\"{base_url}\""),
        "-c".to_string(),
        "model_providers.dam_openai.env_key=\"OPENAI_API_KEY\"".to_string(),
        "-c".to_string(),
        "model_providers.dam_openai.wire_api=\"responses\"".to_string(),
        "-c".to_string(),
        "model_providers.dam_openai.supports_websockets=false".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_stable_profile_ids() {
        assert_eq!(
            profile_ids(),
            [
                "openai-compatible",
                "anthropic",
                "claude-code",
                "codex-api",
                "xai-compatible"
            ]
        );
    }

    #[test]
    fn openai_profiles_use_v1_local_endpoint() {
        let profile = profile("openai-compatible", DEFAULT_PROXY_URL).unwrap();

        assert_eq!(profile.settings[0].key, "OPENAI_BASE_URL");
        assert_eq!(profile.settings[0].value, "http://127.0.0.1:7828/v1");
    }

    #[test]
    fn anthropic_profiles_use_root_local_endpoint() {
        let profile = profile("anthropic", "http://127.0.0.1:7828/").unwrap();

        assert_eq!(profile.settings[0].key, "ANTHROPIC_BASE_URL");
        assert_eq!(profile.settings[0].value, "http://127.0.0.1:7828");
    }

    #[test]
    fn xai_profile_supplies_connect_target_args() {
        let profile = profile("xai-compatible", DEFAULT_PROXY_URL).unwrap();

        assert_eq!(
            profile.connect_args,
            [
                "--target-name",
                "xai",
                "--provider",
                "openai-compatible",
                "--upstream",
                "https://api.x.ai"
            ]
        );
    }

    #[test]
    fn codex_profile_disables_websockets() {
        let profile = profile("codex-api", DEFAULT_PROXY_URL).unwrap();
        let command = &profile.commands[1].command;

        assert!(
            command.contains(&"model_providers.dam_openai.supports_websockets=false".to_string())
        );
    }
}
