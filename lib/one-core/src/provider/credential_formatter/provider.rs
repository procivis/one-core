use std::{collections::HashMap, sync::Arc};

use serde_json::json;

use crate::config::core_config::{CoreConfig, FormatType, JsonLdContextConfig};
use crate::config::ConfigError;
use crate::crypto::CryptoProvider;

use crate::provider::credential_formatter::jwt_formatter::JWTFormatter;
use crate::provider::credential_formatter::mdoc_formatter::MdocFormatter;
use crate::provider::credential_formatter::sdjwt_formatter::SDJWTFormatter;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::repository::json_ld_context_repository::JsonLdContextRepository;

use super::json_ld_bbsplus::JsonLdBbsplus;
use super::json_ld_classic::JsonLdClassic;
use super::CredentialFormatter;

#[cfg_attr(test, mockall::automock)]
pub trait CredentialFormatterProvider: Send + Sync {
    fn get_formatter(&self, formatter_id: &str) -> Option<Arc<dyn CredentialFormatter>>;
}

pub(crate) struct CredentialFormatterProviderImpl {
    formatters: HashMap<String, Arc<dyn CredentialFormatter>>,
}

impl CredentialFormatterProviderImpl {
    pub(crate) fn new(formatters: HashMap<String, Arc<dyn CredentialFormatter>>) -> Self {
        Self { formatters }
    }
}

impl CredentialFormatterProvider for CredentialFormatterProviderImpl {
    fn get_formatter(&self, format: &str) -> Option<Arc<dyn CredentialFormatter>> {
        self.formatters.get(format).cloned()
    }
}

pub(crate) fn credential_formatters_from_config(
    config: &mut CoreConfig,
    json_ld_context_config: JsonLdContextConfig,
    crypto: Arc<dyn CryptoProvider>,
    core_base_url: Option<String>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    json_ld_context_repository: Arc<dyn JsonLdContextRepository>,
) -> Result<HashMap<String, Arc<dyn CredentialFormatter>>, ConfigError> {
    let mut formatters: HashMap<String, Arc<dyn CredentialFormatter>> = HashMap::new();

    for (name, field) in config.format.iter() {
        let formatter = match &field.r#type {
            FormatType::Jwt => {
                let params = config.format.get(name)?;
                Arc::new(JWTFormatter::new(params)) as _
            }
            FormatType::Sdjwt => {
                let params = config.format.get(name)?;
                Arc::new(SDJWTFormatter::new(params, crypto.clone())) as _
            }
            FormatType::JsonLdClassic => {
                let params = config.format.get(name)?;
                Arc::new(JsonLdClassic::new(
                    params,
                    crypto.clone(),
                    core_base_url.clone(),
                    json_ld_context_config.to_owned(),
                    did_method_provider.clone(),
                    json_ld_context_repository.clone(),
                )) as _
            }
            FormatType::JsonLdBbsplus => {
                let params = config.format.get(name)?;
                Arc::new(JsonLdBbsplus::new(
                    params,
                    crypto.clone(),
                    core_base_url.clone(),
                    json_ld_context_config.to_owned(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    json_ld_context_repository.clone(),
                )) as _
            }
            FormatType::Mdoc => {
                let params = config.format.get(name)?;
                Arc::new(MdocFormatter::new(
                    params,
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    core_base_url.clone(),
                    config.clone().datatype,
                )) as _
            }
        };
        formatters.insert(name.to_owned(), formatter);
    }

    for (key, value) in config.format.iter_mut() {
        if let Some(entity) = formatters.get(key) {
            value.capabilities = Some(json!(entity.get_capabilities()));
        }
    }

    Ok(formatters)
}
