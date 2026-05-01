use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

pub const OPENAI_COMPATIBLE_PROVIDER: &str = "openai-compatible";
pub const ANTHROPIC_PROVIDER: &str = "anthropic";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    #[default]
    ExplicitProxy,
    SystemProxy,
    Tun,
}

impl CaptureMode {
    pub fn tag(self) -> &'static str {
        match self {
            Self::ExplicitProxy => "explicit_proxy",
            Self::SystemProxy => "system_proxy",
            Self::Tun => "tun",
        }
    }
}

impl fmt::Display for CaptureMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.tag())
    }
}

impl FromStr for CaptureMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().replace('-', "_").as_str() {
            "explicit" | "explicit_proxy" | "app_layer" => Ok(Self::ExplicitProxy),
            "system" | "system_proxy" => Ok(Self::SystemProxy),
            "tun" | "vpn" => Ok(Self::Tun),
            _ => Err(format!(
                "unsupported network mode: {value}; expected explicit_proxy, system_proxy, or tun"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSupport {
    Implemented,
    Planned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsVisibility {
    NotRequired,
    HostOnly,
    RequiresInterception,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturePlan {
    pub mode: CaptureMode,
    pub support: CaptureSupport,
    pub requires_admin: bool,
    pub installs_system_routes: bool,
    pub tls_visibility: TlsVisibility,
    pub message: String,
}

impl CapturePlan {
    pub fn for_mode(mode: CaptureMode) -> Self {
        match mode {
            CaptureMode::ExplicitProxy => Self {
                mode,
                support: CaptureSupport::Implemented,
                requires_admin: false,
                installs_system_routes: false,
                tls_visibility: TlsVisibility::NotRequired,
                message: "selected AI clients must point at DAM's local app-layer endpoint"
                    .to_string(),
            },
            CaptureMode::SystemProxy => Self {
                mode,
                support: CaptureSupport::Planned,
                requires_admin: false,
                installs_system_routes: true,
                tls_visibility: TlsVisibility::HostOnly,
                message:
                    "system proxy routing is planned; HTTPS bodies still require a trust layer"
                        .to_string(),
            },
            CaptureMode::Tun => Self {
                mode,
                support: CaptureSupport::Planned,
                requires_admin: true,
                installs_system_routes: true,
                tls_visibility: TlsVisibility::HostOnly,
                message: "VPN/TUN routing is planned; HTTPS bodies still require a trust layer"
                    .to_string(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteCaptureReadiness {
    NotTransparentMode,
    NeedsSystemProxyInstall,
    NeedsTunInstall,
    Ready,
}

impl RouteCaptureReadiness {
    pub fn tag(self) -> &'static str {
        match self {
            Self::NotTransparentMode => "not_transparent_mode",
            Self::NeedsSystemProxyInstall => "needs_system_proxy_install",
            Self::NeedsTunInstall => "needs_tun_install",
            Self::Ready => "ready",
        }
    }
}

impl fmt::Display for RouteCaptureReadiness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.tag())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentRouteCaptureReadiness {
    pub route: AiRoute,
    pub protocol: TrafficProtocol,
    pub mode: CaptureMode,
    pub support: CaptureSupport,
    pub readiness: RouteCaptureReadiness,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficProtocol {
    Http,
    Https,
    WebSocket,
    Unknown,
}

impl TrafficProtocol {
    pub fn is_tls(self) -> bool {
        matches!(self, Self::Https | Self::WebSocket)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficObservation {
    pub host: String,
    pub port: Option<u16>,
    pub protocol: TrafficProtocol,
    pub path: Option<String>,
    pub process_name: Option<String>,
}

impl TrafficObservation {
    pub fn new(host: impl Into<String>, protocol: TrafficProtocol) -> Self {
        Self {
            host: host.into(),
            port: None,
            protocol,
            path: None,
            process_name: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiTrafficKind {
    OpenAiApi,
    AnthropicApi,
    XaiApi,
    ChatGptCodexBackend,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiRoute {
    pub kind: AiTrafficKind,
    #[serde(default)]
    pub host: String,
    pub provider: String,
    pub target_name: String,
    pub upstream: String,
}

impl AiRoute {
    pub fn new(
        kind: AiTrafficKind,
        host: impl AsRef<str>,
        provider: impl Into<String>,
        target_name: impl Into<String>,
        upstream: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            host: normalize_host(host.as_ref()),
            provider: provider.into(),
            target_name: target_name.into(),
            upstream: upstream.into(),
        }
    }

    pub fn custom(
        host: impl AsRef<str>,
        provider: impl Into<String>,
        target_name: impl Into<String>,
        upstream: impl Into<String>,
    ) -> Self {
        Self::new(AiTrafficKind::Custom, host, provider, target_name, upstream)
    }

    fn normalized(mut self) -> Self {
        self.host = normalize_host(&self.host);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum TransparentRouteDecision {
    NonAiTraffic {
        reason: String,
    },
    IdentifiedAi {
        route: AiRoute,
        tls_visibility: TlsVisibility,
        protectable_without_tls: bool,
    },
}

pub fn classify_ai_host(host: &str) -> Option<AiRoute> {
    classify_ai_host_with_routes(host, &known_ai_routes())
}

pub fn classify_ai_host_with_routes(host: &str, routes: &[AiRoute]) -> Option<AiRoute> {
    let normalized = normalize_host(host);
    routes
        .iter()
        .find(|route| route.host == normalized)
        .cloned()
}

pub fn known_ai_routes() -> Vec<AiRoute> {
    vec![
        AiRoute::new(
            AiTrafficKind::OpenAiApi,
            "api.openai.com",
            OPENAI_COMPATIBLE_PROVIDER,
            "openai",
            "https://api.openai.com",
        ),
        AiRoute::new(
            AiTrafficKind::AnthropicApi,
            "api.anthropic.com",
            ANTHROPIC_PROVIDER,
            "anthropic",
            "https://api.anthropic.com",
        ),
        AiRoute::new(
            AiTrafficKind::XaiApi,
            "api.x.ai",
            OPENAI_COMPATIBLE_PROVIDER,
            "xai",
            "https://api.x.ai",
        ),
        AiRoute::new(
            AiTrafficKind::ChatGptCodexBackend,
            "chatgpt.com",
            OPENAI_COMPATIBLE_PROVIDER,
            "chatgpt-codex",
            "https://chatgpt.com",
        ),
    ]
}

pub fn known_ai_hosts() -> Vec<&'static str> {
    vec![
        "api.openai.com",
        "api.anthropic.com",
        "api.x.ai",
        "chatgpt.com",
    ]
}

pub fn ai_routes_with_overlays(overlays: impl IntoIterator<Item = AiRoute>) -> Vec<AiRoute> {
    let mut routes = known_ai_routes();
    for overlay in overlays {
        let overlay = overlay.normalized();
        if overlay.host.is_empty() {
            continue;
        }
        if let Some(existing) = routes.iter_mut().find(|route| route.host == overlay.host) {
            *existing = overlay;
        } else {
            routes.push(overlay);
        }
    }
    routes
}

pub fn normalize_ai_host(host: &str) -> String {
    normalize_host(host)
}

pub fn decide_transparent_route(observation: &TrafficObservation) -> TransparentRouteDecision {
    decide_transparent_route_with_routes(observation, &known_ai_routes())
}

pub fn decide_transparent_route_with_routes(
    observation: &TrafficObservation,
    routes: &[AiRoute],
) -> TransparentRouteDecision {
    let Some(route) = classify_ai_host_with_routes(&observation.host, routes) else {
        return TransparentRouteDecision::NonAiTraffic {
            reason: "host is not a known AI provider endpoint".to_string(),
        };
    };

    if observation.protocol.is_tls() {
        TransparentRouteDecision::IdentifiedAi {
            route,
            tls_visibility: TlsVisibility::RequiresInterception,
            protectable_without_tls: false,
        }
    } else {
        TransparentRouteDecision::IdentifiedAi {
            route,
            tls_visibility: TlsVisibility::NotRequired,
            protectable_without_tls: true,
        }
    }
}

pub fn transparent_capture_readiness_for_known_ai_routes(
    mode: CaptureMode,
    system_proxy_active: bool,
    tun_active: bool,
) -> Vec<TransparentRouteCaptureReadiness> {
    transparent_capture_readiness_for_ai_routes(
        &known_ai_routes(),
        mode,
        system_proxy_active,
        tun_active,
    )
}

pub fn transparent_capture_readiness_for_ai_routes(
    routes: &[AiRoute],
    mode: CaptureMode,
    system_proxy_active: bool,
    tun_active: bool,
) -> Vec<TransparentRouteCaptureReadiness> {
    routes
        .iter()
        .cloned()
        .map(|route| {
            transparent_route_capture_readiness(
                route,
                TrafficProtocol::Https,
                mode,
                system_proxy_active,
                tun_active,
            )
        })
        .collect()
}

pub fn transparent_route_capture_readiness(
    route: AiRoute,
    protocol: TrafficProtocol,
    mode: CaptureMode,
    system_proxy_active: bool,
    tun_active: bool,
) -> TransparentRouteCaptureReadiness {
    let plan = CapturePlan::for_mode(mode);
    let (support, readiness, message) = match mode {
        CaptureMode::ExplicitProxy => (
            plan.support,
            RouteCaptureReadiness::NotTransparentMode,
            "explicit proxy mode only protects clients configured to use DAM".to_string(),
        ),
        CaptureMode::SystemProxy if system_proxy_active => (
            CaptureSupport::Implemented,
            RouteCaptureReadiness::Ready,
            format!("system proxy routing is active for {}", route.target_name),
        ),
        CaptureMode::SystemProxy => (
            plan.support,
            RouteCaptureReadiness::NeedsSystemProxyInstall,
            "system proxy routing is not installed".to_string(),
        ),
        CaptureMode::Tun if tun_active => (
            CaptureSupport::Implemented,
            RouteCaptureReadiness::Ready,
            format!("TUN routing is active for {}", route.target_name),
        ),
        CaptureMode::Tun => (
            plan.support,
            RouteCaptureReadiness::NeedsTunInstall,
            "TUN routing is not installed".to_string(),
        ),
    };

    TransparentRouteCaptureReadiness {
        route,
        protocol,
        mode,
        support,
        readiness,
        message,
    }
}

fn normalize_host(host: &str) -> String {
    let trimmed = host.trim().trim_end_matches('.');
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .or_else(|| trimmed.strip_prefix("wss://"))
        .or_else(|| trimmed.strip_prefix("ws://"))
        .unwrap_or(trimmed);
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    let host_only = host_port
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(host, _)| host))
        .unwrap_or_else(|| {
            host_port
                .split_once(':')
                .map(|(host, _)| host)
                .unwrap_or(host_port)
        });
    host_only.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_capture_modes_with_user_friendly_aliases() {
        assert_eq!(
            "explicit".parse::<CaptureMode>().unwrap(),
            CaptureMode::ExplicitProxy
        );
        assert_eq!(
            "system-proxy".parse::<CaptureMode>().unwrap(),
            CaptureMode::SystemProxy
        );
        assert_eq!("vpn".parse::<CaptureMode>().unwrap(), CaptureMode::Tun);
    }

    #[test]
    fn capture_plan_marks_only_explicit_proxy_as_implemented() {
        assert_eq!(
            CapturePlan::for_mode(CaptureMode::ExplicitProxy).support,
            CaptureSupport::Implemented
        );
        assert_eq!(
            CapturePlan::for_mode(CaptureMode::SystemProxy).support,
            CaptureSupport::Planned
        );
        assert!(CapturePlan::for_mode(CaptureMode::Tun).requires_admin);
    }

    #[test]
    fn classifies_known_ai_provider_hosts() {
        assert_eq!(
            classify_ai_host("https://api.openai.com/v1/responses")
                .unwrap()
                .target_name,
            "openai"
        );
        assert_eq!(
            classify_ai_host("api.anthropic.com:443").unwrap().provider,
            ANTHROPIC_PROVIDER.to_string()
        );
        assert_eq!(classify_ai_host("API.X.AI.").unwrap().target_name, "xai");
        assert_eq!(
            classify_ai_host("chatgpt.com").unwrap().kind,
            AiTrafficKind::ChatGptCodexBackend
        );
        assert!(classify_ai_host("example.com").is_none());
    }

    #[test]
    fn known_ai_routes_are_unique_and_non_empty() {
        let routes = known_ai_routes();

        assert_eq!(routes.len(), 4);
        assert_eq!(routes[0].host, "api.openai.com");
        assert_eq!(routes[0].target_name, "openai");
        assert_eq!(known_ai_hosts()[0], "api.openai.com");
    }

    #[test]
    fn custom_routes_extend_and_override_default_route_registry() {
        let routes = ai_routes_with_overlays([
            AiRoute::custom(
                "api.internal-ai.example:443",
                OPENAI_COMPATIBLE_PROVIDER,
                "internal-ai",
                "https://api.internal-ai.example",
            ),
            AiRoute::custom(
                "https://api.openai.com/v1",
                OPENAI_COMPATIBLE_PROVIDER,
                "openai-private-edge",
                "https://openai.internal.example",
            ),
        ]);

        assert_eq!(routes.len(), 5);
        assert_eq!(
            classify_ai_host_with_routes("api.internal-ai.example", &routes)
                .unwrap()
                .target_name,
            "internal-ai"
        );
        assert_eq!(
            classify_ai_host_with_routes("api.openai.com", &routes)
                .unwrap()
                .upstream,
            "https://openai.internal.example"
        );
    }

    #[test]
    fn transparent_https_ai_traffic_is_identified_but_not_protectable_without_tls() {
        let decision = decide_transparent_route(&TrafficObservation::new(
            "api.openai.com",
            TrafficProtocol::Https,
        ));

        assert_eq!(
            decision,
            TransparentRouteDecision::IdentifiedAi {
                route: classify_ai_host("api.openai.com").unwrap(),
                tls_visibility: TlsVisibility::RequiresInterception,
                protectable_without_tls: false,
            }
        );
    }

    #[test]
    fn transparent_http_ai_traffic_is_protectable_without_tls() {
        let decision = decide_transparent_route(&TrafficObservation::new(
            "api.anthropic.com",
            TrafficProtocol::Http,
        ));

        assert_eq!(
            decision,
            TransparentRouteDecision::IdentifiedAi {
                route: classify_ai_host("api.anthropic.com").unwrap(),
                tls_visibility: TlsVisibility::NotRequired,
                protectable_without_tls: true,
            }
        );
    }

    #[test]
    fn explicit_proxy_is_not_transparent_routing_ready() {
        let readiness = transparent_capture_readiness_for_known_ai_routes(
            CaptureMode::ExplicitProxy,
            false,
            false,
        );

        assert_eq!(readiness.len(), 4);
        assert!(
            readiness
                .iter()
                .all(|route| route.readiness == RouteCaptureReadiness::NotTransparentMode)
        );
    }

    #[test]
    fn system_proxy_and_tun_report_missing_route_installation() {
        let system_proxy = transparent_capture_readiness_for_known_ai_routes(
            CaptureMode::SystemProxy,
            false,
            false,
        );
        let tun = transparent_capture_readiness_for_known_ai_routes(CaptureMode::Tun, false, false);

        assert!(
            system_proxy
                .iter()
                .all(|route| route.readiness == RouteCaptureReadiness::NeedsSystemProxyInstall)
        );
        assert!(
            tun.iter()
                .all(|route| route.readiness == RouteCaptureReadiness::NeedsTunInstall)
        );
    }

    #[test]
    fn active_system_proxy_or_tun_marks_transparent_routing_ready() {
        let system_proxy = transparent_capture_readiness_for_known_ai_routes(
            CaptureMode::SystemProxy,
            true,
            false,
        );
        let tun = transparent_capture_readiness_for_known_ai_routes(CaptureMode::Tun, false, true);

        assert!(
            system_proxy
                .iter()
                .all(|route| route.readiness == RouteCaptureReadiness::Ready)
        );
        assert!(
            system_proxy
                .iter()
                .all(|route| route.support == CaptureSupport::Implemented)
        );
        assert!(
            tun.iter()
                .all(|route| route.readiness == RouteCaptureReadiness::Ready)
        );
        assert!(
            tun.iter()
                .all(|route| route.support == CaptureSupport::Implemented)
        );
    }

    #[test]
    fn transparent_readiness_accepts_custom_route_sets() {
        let routes = ai_routes_with_overlays([AiRoute::custom(
            "api.enterprise-ai.example",
            OPENAI_COMPATIBLE_PROVIDER,
            "enterprise-ai",
            "https://api.enterprise-ai.example",
        )]);

        let readiness = transparent_capture_readiness_for_ai_routes(
            &routes,
            CaptureMode::SystemProxy,
            true,
            false,
        );

        assert_eq!(readiness.len(), 5);
        assert!(
            readiness
                .iter()
                .any(|route| route.route.target_name == "enterprise-ai"
                    && route.readiness == RouteCaptureReadiness::Ready)
        );
    }
}
