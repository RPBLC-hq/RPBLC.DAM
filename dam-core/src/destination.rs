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
    pub fn from_host(host: &str) -> Self {
        if host.contains("anthropic.com") {
            Self::Llm {
                provider: LlmProvider::Anthropic,
            }
        } else if host.contains("openai.com") || host.contains("chatgpt.com") {
            Self::Llm {
                provider: LlmProvider::OpenAI,
            }
        } else if host.contains("openrouter.ai") {
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

fn extract_host(url: &str) -> &str {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    // Take everything before the first `/` or `:`
    without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .split(':')
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
}
