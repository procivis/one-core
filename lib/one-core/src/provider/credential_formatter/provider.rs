use std::{collections::HashMap, sync::Arc};

use crate::config::core_config::{FormatConfig, FormatType};
use crate::config::ConfigError;
use crate::crypto::CryptoProvider;
use crate::provider::credential_formatter::json_ld_formatter::JsonLdFormatter;
use crate::provider::credential_formatter::jwt_formatter::JWTFormatter;
use crate::provider::credential_formatter::mdoc_formatter::MdocFormatter;
use crate::provider::credential_formatter::sdjwt_formatter::SDJWTFormatter;

use super::CredentialFormatter;

#[cfg_attr(test, mockall::automock)]
pub(crate) trait CredentialFormatterProvider {
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
    config: &FormatConfig,
    crypto: Arc<dyn CryptoProvider + Send + Sync>,
) -> Result<HashMap<String, Arc<dyn CredentialFormatter>>, ConfigError> {
    let mut formatters = HashMap::new();

    for format_type in config.as_inner().keys() {
        let type_str = format_type.to_string();

        match format_type {
            FormatType::Jwt => {
                let capabilities = config.get_capabilities(&type_str)?;

                let params = config.get(format_type)?;
                let formatter = Arc::new(JWTFormatter::new(capabilities, params)) as _;
                formatters.insert(type_str, formatter);
            }
            FormatType::Sdjwt => {
                let capabilities = config.get_capabilities(&type_str)?;

                let params = config.get(format_type)?;
                let formatter =
                    Arc::new(SDJWTFormatter::new(capabilities, params, crypto.clone())) as _;
                formatters.insert(type_str, formatter);
            }
            FormatType::JsonLd => {
                let formatter = Arc::new(JsonLdFormatter::new()) as _;
                formatters.insert(type_str, formatter);
            }
            FormatType::Mdoc => {
                let formatter = Arc::new(MdocFormatter::new()) as _;
                formatters.insert(type_str, formatter);
            }
        }
    }

    Ok(formatters)
}
