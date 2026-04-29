use http::{HeaderMap, header};

pub const OPENAI_COMPATIBLE_PROVIDER: &str = "openai-compatible";
pub const ANTHROPIC_PROVIDER: &str = "anthropic";
pub const ANTHROPIC_API_KEY_HEADER: &str = "x-api-key";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    OpenAiCompatible,
    Anthropic,
}

impl ProviderKind {
    pub fn parse(value: &str) -> Result<Self, RouteError> {
        match value {
            OPENAI_COMPATIBLE_PROVIDER => Ok(Self::OpenAiCompatible),
            ANTHROPIC_PROVIDER => Ok(Self::Anthropic),
            other => Err(RouteError::UnsupportedProvider(other.to_string())),
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Self::OpenAiCompatible => OPENAI_COMPATIBLE_PROVIDER,
            Self::Anthropic => ANTHROPIC_PROVIDER,
        }
    }

    pub fn caller_auth_header_present(self, headers: &HeaderMap) -> bool {
        match self {
            Self::OpenAiCompatible => headers.contains_key(header::AUTHORIZATION),
            Self::Anthropic => {
                headers.contains_key(ANTHROPIC_API_KEY_HEADER)
                    || headers.contains_key(header::AUTHORIZATION)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteError {
    #[error("proxy target is missing")]
    MissingTarget,

    #[error("unsupported proxy provider: {0}")]
    UnsupportedProvider(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAuth {
    CallerPassthrough,
    TargetApiKey,
    ConfigRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    target: dam_config::ProxyTargetConfig,
    provider: ProviderKind,
    default_failure_mode: dam_config::ProxyFailureMode,
}

impl RoutePlan {
    pub fn from_proxy_config(config: &dam_config::ProxyConfig) -> Result<Self, RouteError> {
        let target = config
            .targets
            .first()
            .cloned()
            .ok_or(RouteError::MissingTarget)?;
        Self::new(target, config.default_failure_mode)
    }

    pub fn new(
        target: dam_config::ProxyTargetConfig,
        default_failure_mode: dam_config::ProxyFailureMode,
    ) -> Result<Self, RouteError> {
        let provider = ProviderKind::parse(&target.provider)?;
        Ok(Self {
            target,
            provider,
            default_failure_mode,
        })
    }

    pub fn target(&self) -> &dam_config::ProxyTargetConfig {
        &self.target
    }

    pub fn provider_kind(&self) -> ProviderKind {
        self.provider
    }

    pub fn failure_mode(&self) -> dam_config::ProxyFailureMode {
        self.target
            .effective_failure_mode(self.default_failure_mode)
    }

    pub fn decide<'a>(&'a self, headers: &HeaderMap) -> RouteDecision<'a> {
        let auth = if self.target.api_key.is_some() {
            RouteAuth::TargetApiKey
        } else if self.target.api_key_env.is_some()
            && !self.provider.caller_auth_header_present(headers)
        {
            RouteAuth::ConfigRequired
        } else {
            RouteAuth::CallerPassthrough
        };

        RouteDecision {
            target: &self.target,
            provider: self.provider,
            failure_mode: self.failure_mode(),
            auth,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteDecision<'a> {
    target: &'a dam_config::ProxyTargetConfig,
    provider: ProviderKind,
    failure_mode: dam_config::ProxyFailureMode,
    auth: RouteAuth,
}

impl<'a> RouteDecision<'a> {
    pub fn target(self) -> &'a dam_config::ProxyTargetConfig {
        self.target
    }

    pub fn provider_kind(self) -> ProviderKind {
        self.provider
    }

    pub fn failure_mode(self) -> dam_config::ProxyFailureMode {
        self.failure_mode
    }

    pub fn auth(self) -> RouteAuth {
        self.auth
    }

    pub fn config_required(self) -> bool {
        self.auth == RouteAuth::ConfigRequired
    }

    pub fn target_api_key(self) -> Option<&'a str> {
        match self.auth {
            RouteAuth::TargetApiKey => self.target.api_key.as_ref().map(|key| key.expose()),
            RouteAuth::CallerPassthrough | RouteAuth::ConfigRequired => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn target(provider: &str) -> dam_config::ProxyTargetConfig {
        dam_config::ProxyTargetConfig {
            name: "test".to_string(),
            provider: provider.to_string(),
            upstream: "https://upstream.example.test".to_string(),
            failure_mode: None,
            api_key_env: None,
            api_key: None,
        }
    }

    fn proxy_config(target: dam_config::ProxyTargetConfig) -> dam_config::ProxyConfig {
        let mut config = dam_config::ProxyConfig::default();
        config.targets.push(target);
        config
    }

    #[test]
    fn selects_first_target_and_effective_failure_mode() {
        let mut first = target(OPENAI_COMPATIBLE_PROVIDER);
        first.name = "first".to_string();
        first.failure_mode = Some(dam_config::ProxyFailureMode::BlockOnError);
        let mut second = target(ANTHROPIC_PROVIDER);
        second.name = "second".to_string();

        let mut config = proxy_config(first);
        config.targets.push(second);
        config.default_failure_mode = dam_config::ProxyFailureMode::BypassOnError;

        let route = RoutePlan::from_proxy_config(&config).unwrap();

        assert_eq!(route.target().name, "first");
        assert_eq!(route.provider_kind(), ProviderKind::OpenAiCompatible);
        assert_eq!(
            route.failure_mode(),
            dam_config::ProxyFailureMode::BlockOnError
        );
    }

    #[test]
    fn uses_default_failure_mode_when_target_does_not_override() {
        let mut config = proxy_config(target(OPENAI_COMPATIBLE_PROVIDER));
        config.default_failure_mode = dam_config::ProxyFailureMode::RedactOnly;

        let route = RoutePlan::from_proxy_config(&config).unwrap();

        assert_eq!(
            route.failure_mode(),
            dam_config::ProxyFailureMode::RedactOnly
        );
    }

    #[test]
    fn missing_target_is_reported() {
        let config = dam_config::ProxyConfig::default();

        assert_eq!(
            RoutePlan::from_proxy_config(&config).unwrap_err(),
            RouteError::MissingTarget
        );
    }

    #[test]
    fn unsupported_provider_is_reported() {
        let config = proxy_config(target("unknown"));

        assert_eq!(
            RoutePlan::from_proxy_config(&config).unwrap_err(),
            RouteError::UnsupportedProvider("unknown".to_string())
        );
    }

    #[test]
    fn openai_target_requires_config_when_env_key_is_missing_and_caller_auth_is_absent() {
        let mut target = target(OPENAI_COMPATIBLE_PROVIDER);
        target.api_key_env = Some("OPENAI_API_KEY".to_string());
        let route = RoutePlan::from_proxy_config(&proxy_config(target)).unwrap();

        let decision = route.decide(&HeaderMap::new());

        assert_eq!(decision.auth(), RouteAuth::ConfigRequired);
        assert!(decision.config_required());
        assert!(decision.target_api_key().is_none());
    }

    #[test]
    fn openai_target_accepts_caller_authorization_when_env_key_is_missing() {
        let mut target = target(OPENAI_COMPATIBLE_PROVIDER);
        target.api_key_env = Some("OPENAI_API_KEY".to_string());
        let route = RoutePlan::from_proxy_config(&proxy_config(target)).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer caller"),
        );

        let decision = route.decide(&headers);

        assert_eq!(decision.auth(), RouteAuth::CallerPassthrough);
        assert!(!decision.config_required());
    }

    #[test]
    fn target_api_key_wins_over_caller_auth() {
        let mut target = target(OPENAI_COMPATIBLE_PROVIDER);
        target.api_key_env = Some("OPENAI_API_KEY".to_string());
        target.api_key = Some(dam_config::SecretValue::new(
            "OPENAI_API_KEY",
            "target-secret",
        ));
        let route = RoutePlan::from_proxy_config(&proxy_config(target)).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer caller"),
        );

        let decision = route.decide(&headers);

        assert_eq!(decision.auth(), RouteAuth::TargetApiKey);
        assert_eq!(decision.target_api_key(), Some("target-secret"));
    }

    #[test]
    fn target_without_api_key_env_uses_pass_through_even_without_caller_auth() {
        let route = RoutePlan::from_proxy_config(&proxy_config(target(OPENAI_COMPATIBLE_PROVIDER)))
            .unwrap();

        let decision = route.decide(&HeaderMap::new());

        assert_eq!(decision.auth(), RouteAuth::CallerPassthrough);
        assert!(!decision.config_required());
    }

    #[test]
    fn anthropic_target_accepts_x_api_key_or_authorization_as_caller_auth() {
        let mut target = target(ANTHROPIC_PROVIDER);
        target.api_key_env = Some("ANTHROPIC_API_KEY".to_string());
        let route = RoutePlan::from_proxy_config(&proxy_config(target)).unwrap();

        let mut x_api_key_headers = HeaderMap::new();
        x_api_key_headers.insert(ANTHROPIC_API_KEY_HEADER, HeaderValue::from_static("caller"));
        assert_eq!(
            route.decide(&x_api_key_headers).auth(),
            RouteAuth::CallerPassthrough
        );

        let mut authorization_headers = HeaderMap::new();
        authorization_headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer a"));
        assert_eq!(
            route.decide(&authorization_headers).auth(),
            RouteAuth::CallerPassthrough
        );
    }
}
