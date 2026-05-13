use crate::ProxyError;

pub(crate) struct ProviderAdapters {
    openai: dam_provider_openai::OpenAiProvider,
    anthropic: dam_provider_anthropic::AnthropicProvider,
}

pub(crate) enum ProviderAdapter<'a> {
    OpenAi(&'a dam_provider_openai::OpenAiProvider),
    Anthropic(&'a dam_provider_anthropic::AnthropicProvider),
}

impl ProviderAdapters {
    pub(crate) fn new() -> Result<Self, ProxyError> {
        Ok(Self {
            openai: dam_provider_openai::OpenAiProvider::new()
                .map_err(|error| ProxyError::ProviderInit(error.to_string()))?,
            anthropic: dam_provider_anthropic::AnthropicProvider::new()
                .map_err(|error| ProxyError::ProviderInit(error.to_string()))?,
        })
    }

    pub(crate) fn get(&self, kind: dam_router::ProviderKind) -> ProviderAdapter<'_> {
        match kind {
            dam_router::ProviderKind::GenericHttp => ProviderAdapter::OpenAi(&self.openai),
            dam_router::ProviderKind::OpenAiCompatible => ProviderAdapter::OpenAi(&self.openai),
            dam_router::ProviderKind::Anthropic => ProviderAdapter::Anthropic(&self.anthropic),
        }
    }
}
