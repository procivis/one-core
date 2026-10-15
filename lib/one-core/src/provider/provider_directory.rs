use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::sync::Arc;

use thiserror::Error;

use crate::config::core_config::{ConfigFields, ConfigKey};
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::provider::Provider;

pub struct ProviderDirectory<C, CF, P>
where
    C: ConfigKey,
    CF: ConfigFields,
    P: Provider + ?Sized,
{
    providers: HashMap<C, Arc<P>>,
    configs: HashMap<C, CF>,
}

impl<C, CF, P> Clone for ProviderDirectory<C, CF, P>
where
    C: ConfigKey,
    CF: ConfigFields,
    P: Provider + ?Sized,
{
    fn clone(&self) -> Self {
        Self {
            providers: self.providers.clone(),
            configs: self.configs.clone(),
        }
    }
}

#[derive(Debug, Error)]
pub enum InitializationError {
    #[error("failed to deserialize params for config entry `{key}`: {source}")]
    InvalidParams {
        key: String,
        source: serde_json::Error,
    },
    #[error("Missing provider dependency: {0}")]
    MissingDependency(String),
    #[error("Invalid param value for `{key}`: {description}")]
    InvalidParamValue { key: String, description: String },
    #[error("unsupported configuration for config entry `{key}`: {detail}")]
    UnsupportedConfiguration { key: String, detail: String },
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for InitializationError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidParams { .. }
            | Self::UnsupportedConfiguration { .. }
            | Self::InvalidParamValue { .. } => ErrorCode::BR_0429,
            Self::MissingDependency(_) => ErrorCode::BR_0428,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum ProviderError {
    #[error("Missing provider `{config_key}` of type `{provider_type}`")]
    MissingProvider {
        config_key: String,
        provider_type: String,
    },

    #[error("Provider `{provider}` is disabled")]
    ProviderDisabled { provider: String },
}

impl ErrorCodeMixin for ProviderError {
    fn error_code(&self) -> ErrorCode {
        match self {
            ProviderError::MissingProvider { .. } => ErrorCode::BR_0430,
            ProviderError::ProviderDisabled { .. } => ErrorCode::BR_0431,
        }
    }
}

pub trait WithDisabledDecorator {
    /// returns a decorated version with disabled flag handling
    fn decorate(self: Arc<Self>) -> Arc<Self>;
}

impl<C, CF, P> ProviderDirectory<C, CF, P>
where
    C: ConfigKey,
    CF: ConfigFields,
    P: Provider + ?Sized + 'static,
{
    pub fn initialize<'a, K>(
        config_blocks: impl Iterator<Item = (&'a C, &'a mut CF)>,
        initializer: impl Fn(&K, &CF) -> Result<Arc<P>, InitializationError>,
    ) -> Result<Self, InitializationError>
    where
        K: ?Sized,
        C: 'a + Borrow<K>,
        CF: 'a + ConfigFields,
        P: WithDisabledDecorator,
    {
        let mut providers = HashMap::new();
        let mut configs = HashMap::new();

        for (config_id, field) in config_blocks {
            let mut provider = initializer(config_id.borrow(), field)?;
            if !field.enabled() {
                provider = P::decorate(provider);
            }

            configs.insert(config_id.clone(), field.clone());

            if let Some(capabilities) = provider.capabilities() {
                field.set_capabilities(capabilities);
            }

            providers.insert(config_id.clone(), provider);
        }

        Ok(Self { providers, configs })
    }

    /// insert a custom provider not mentioned in the config
    pub fn insert_non_config(&mut self, config_id: C, provider: Arc<P>) {
        self.providers.insert(config_id, provider);
    }

    /// Merge two directories of the same type together
    pub fn merge(&mut self, other: Self) {
        self.providers.extend(other.providers);
        self.configs.extend(other.configs);
    }

    pub fn provider<K>(&self, config_id: &K) -> Result<Arc<P>, NestedError>
    where
        K: Hash + Eq + ?Sized + Display,
        C: Borrow<K>,
    {
        self.providers.get(config_id).cloned().ok_or(
            ProviderError::MissingProvider {
                config_key: config_id.to_string(),
                provider_type: std::any::type_name::<P>().to_string(),
            }
            .into(),
        )
    }

    pub fn iter(&self) -> impl Iterator<Item = (&C, &Arc<P>)> {
        self.providers.iter()
    }

    pub fn config(&self, config_id: &C) -> Result<&CF, NestedError> {
        self.configs.get(config_id).ok_or(
            ProviderError::MissingProvider {
                config_key: config_id.to_string(),
                provider_type: std::any::type_name::<P>().to_string(),
            }
            .into(),
        )
    }

    pub fn iter_configs(&self) -> impl Iterator<Item = (&C, &CF)> {
        self.configs.iter()
    }
}
