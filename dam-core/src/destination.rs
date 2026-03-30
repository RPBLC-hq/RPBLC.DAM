use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LlmProvider {
    Anthropic,
    OpenAI,
    OpenRouter,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    Llm { provider: LlmProvider },
    Other { host: String },
}

impl Destination {
    /// Classify a URL's host as an LLM provider or other.
    pub fn from_url(url: &str) -> Self {
        let host = extract_host(url);
        Self::from_host(host)
    }

    /// Classify a bare hostname as an LLM provider or other.
    ///
    /// Uses exact or suffix matching (`.domain`) to prevent spoofing.
    /// For example, `evilanthropiccom.com` will NOT match `anthropic.com`.
    pub fn from_host(host: &str) -> Self {
        if host_matches(host, "anthropic.com") {
            Self::Llm {
                provider: LlmProvider::Anthropic,
            }
        } else if host_matches(host, "openai.com") || host_matches(host, "chatgpt.com") {
            Self::Llm {
                provider: LlmProvider::OpenAI,
            }
        } else if host_matches(host, "openrouter.ai") {
            Self::Llm {
                provider: LlmProvider::OpenRouter,
            }
        } else {
            Self::Other {
                host: host.to_string(),
            }
        }
    }

    pub fn is_llm(&self) -> bool {
        matches!(self, Self::Llm { .. })
    }

    pub fn host(&self) -> &str {
        match self {
            Self::Llm { provider } => match provider {
                LlmProvider::Anthropic => "api.anthropic.com",
                LlmProvider::OpenAI => "api.openai.com",
                LlmProvider::OpenRouter => "openrouter.ai",
                LlmProvider::Other(h) => h,
            },
            Self::Other { host } => host,
        }
    }
}

/// Check if `host` equals `domain` or ends with `.` + `domain`.
///
/// Prevents substring spoofing: `evilanthropiccom.com` does NOT match `anthropic.com`.
fn host_matches(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn extract_host(url: &str) -> &str {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    // Take everything before the first `/`, `:`, or `?`
    // (query params can leak into the host when there's no path separator)
    without_scheme
        .split(&['/', ':', '?'][..])
        .next()
        .unwrap_or(without_scheme)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_detected() {
        let d = Destination::from_url("https://api.anthropic.com/v1/messages");
        assert!(matches!(
            d,
            Destination::Llm {
                provider: LlmProvider::Anthropic
            }
        ));
        assert!(d.is_llm());
    }

    #[test]
    fn test_openai_detected() {
        let d = Destination::from_url("https://api.openai.com/v1/chat/completions");
        assert!(matches!(
            d,
            Destination::Llm {
                provider: LlmProvider::OpenAI
            }
        ));
    }

    #[test]
    fn test_openrouter_detected() {
        let d = Destination::from_url("https://openrouter.ai/api/v1/chat/completions");
        assert!(matches!(
            d,
            Destination::Llm {
                provider: LlmProvider::OpenRouter
            }
        ));
    }

    #[test]
    fn test_unknown_host() {
        let d = Destination::from_url("https://example.com/api");
        assert!(matches!(d, Destination::Other { .. }));
        assert!(!d.is_llm());
    }

    #[test]
    fn test_localhost_not_llm() {
        let d = Destination::from_url("http://localhost:8080/test");
        assert!(!d.is_llm());
    }

    #[test]
    fn test_url_with_path() {
        let d = Destination::from_url("https://api.anthropic.com/v1/messages?foo=bar");
        assert!(d.is_llm());
    }

    #[test]
    fn test_bare_host() {
        let d = Destination::from_url("api.openai.com");
        assert!(d.is_llm());
    }

    // Spoofing prevention tests
    #[test]
    fn test_spoofed_anthropic_not_matched() {
        let d = Destination::from_url("https://evilanthropiccom.com/v1/messages");
        assert!(!d.is_llm());
    }

    #[test]
    fn test_spoofed_openai_suffix_not_matched() {
        let d = Destination::from_url("https://openai.com.evil.example/v1/chat");
        assert!(!d.is_llm());
    }

    #[test]
    fn test_exact_domain_matches() {
        let d = Destination::from_host("anthropic.com");
        assert!(d.is_llm());
        let d = Destination::from_host("openai.com");
        assert!(d.is_llm());
        let d = Destination::from_host("openrouter.ai");
        assert!(d.is_llm());
    }

    #[test]
    fn test_subdomain_matches() {
        let d = Destination::from_host("api.anthropic.com");
        assert!(d.is_llm());
        let d = Destination::from_host("deep.sub.openai.com");
        assert!(d.is_llm());
    }

    #[test]
    fn test_host_matches_fn() {
        assert!(host_matches("api.anthropic.com", "anthropic.com"));
        assert!(host_matches("anthropic.com", "anthropic.com"));
        assert!(!host_matches("evilanthropiccom.com", "anthropic.com"));
        assert!(!host_matches("openai.com.evil.example", "openai.com"));
        assert!(!host_matches("notopenai.com", "openai.com"));
    }

    // Query param stripping in extract_host
    #[test]
    fn test_extract_host_strips_query_params() {
        assert_eq!(extract_host("https://example.com?foo=bar"), "example.com");
        assert_eq!(extract_host("example.com?query"), "example.com");
    }

    #[test]
    fn test_extract_host_with_port() {
        assert_eq!(extract_host("http://localhost:8080/test"), "localhost");
    }

    #[test]
    fn test_extract_host_bare() {
        assert_eq!(extract_host("api.openai.com"), "api.openai.com");
    }
}
