//! Credential format provider.

use std::collections::HashMap;
use std::sync::Arc;

use one_crypto::CryptoProvider;
use serde_json::json;

use super::CredentialFormatter;
use super::json_ld_bbsplus::JsonLdBbsplus;
use super::json_ld_classic::JsonLdClassic;
use super::jwt_formatter::JWTFormatter;
use super::mdoc_formatter::MdocFormatter;
use super::physical_card::PhysicalCardFormatter;
use super::sdjwt_formatter::SDJWTFormatter;
use super::sdjwtvc_formatter::SDJWTVCFormatter;
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, FormatType, Params};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::provider::caching_loader::json_ld_context::JsonLdCachingLoader;
use crate::provider::caching_loader::vct::VctTypeMetadataFetcher;
use crate::provider::data_type::provider::DataTypeProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait CredentialFormatterProvider: Send + Sync {
    fn get_credential_formatter(&self, formatter_id: &str) -> Option<Arc<dyn CredentialFormatter>>;
}

struct CredentialFormatterProviderImpl {
    credential_formatters: HashMap<String, Arc<dyn CredentialFormatter>>,
}

impl CredentialFormatterProviderImpl {
    fn new(credential_formatters: HashMap<String, Arc<dyn CredentialFormatter>>) -> Self {
        Self {
            credential_formatters,
        }
    }
}

impl CredentialFormatterProvider for CredentialFormatterProviderImpl {
    fn get_credential_formatter(&self, format: &str) -> Option<Arc<dyn CredentialFormatter>> {
        self.credential_formatters.get(format).cloned()
    }
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn credential_formatter_provider_from_config(
    config: &mut CoreConfig,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    client: Arc<dyn HttpClient>,
    data_type_provider: Arc<dyn DataTypeProvider>,
    crypto: Arc<dyn CryptoProvider>,
    json_ld_cache: JsonLdCachingLoader,
    did_method_provider: Arc<dyn DidMethodProvider>,
    vct_type_metadata_cache: Arc<dyn VctTypeMetadataFetcher>,
    certificate_validator: Arc<dyn CertificateValidator>,
) -> Result<Arc<dyn CredentialFormatterProvider>, ConfigValidationError> {
    let mut credential_formatters: HashMap<String, Arc<dyn CredentialFormatter>> = HashMap::new();

    for (name, field) in config.format.iter() {
        let formatter = match field.r#type {
            FormatType::Jwt => {
                let params = config.format.get(name)?;
                Arc::new(JWTFormatter::new(
                    params,
                    key_algorithm_provider.clone(),
                    data_type_provider.clone(),
                )) as _
            }
            FormatType::PhysicalCard => Arc::new(PhysicalCardFormatter::new(
                crypto.clone(),
                json_ld_cache.clone(),
                client.clone(),
            )) as _,
            FormatType::SdJwt => {
                let params = config.format.get(name)?;
                Arc::new(SDJWTFormatter::new(
                    params,
                    crypto.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    data_type_provider.clone(),
                    client.clone(),
                )) as _
            }
            FormatType::SdJwtVc => {
                let params = config.format.get(name)?;
                Arc::new(SDJWTVCFormatter::new(
                    params,
                    crypto.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    vct_type_metadata_cache.clone(),
                    certificate_validator.clone(),
                    config.datatype.clone(),
                    client.clone(),
                    data_type_provider.clone(),
                )) as _
            }
            FormatType::JsonLdClassic => {
                let params = config.format.get(name)?;
                Arc::new(JsonLdClassic::new(
                    params,
                    crypto.clone(),
                    json_ld_cache.clone(),
                    data_type_provider.clone(),
                    key_algorithm_provider.clone(),
                    client.clone(),
                )) as _
            }
            FormatType::JsonLdBbsPlus => {
                let params = config.format.get(name)?;
                Arc::new(JsonLdBbsplus::new(
                    params,
                    crypto.clone(),
                    did_method_provider.clone(),
                    data_type_provider.clone(),
                    key_algorithm_provider.clone(),
                    json_ld_cache.clone(),
                    client.clone(),
                )) as _
            }
            FormatType::Mdoc => {
                let params = config.format.get(name)?;
                Arc::new(MdocFormatter::new(
                    params,
                    certificate_validator.clone(),
                    did_method_provider.clone(),
                    config.datatype.clone(),
                    data_type_provider.clone(),
                    key_algorithm_provider.clone(),
                )) as _
            }
        };
        credential_formatters.insert(name.to_owned(), formatter);
    }

    for (key, value) in config.format.iter_mut() {
        if let Some(entity) = credential_formatters.get(key) {
            value.capabilities = Some(json!(entity.get_capabilities()));
            if let Some(params) = &mut value.params {
                if let Some(public) = &mut params.public {
                    if public["embedLayoutProperties"].is_null() {
                        public["embedLayoutProperties"] = false.into();
                    }
                } else {
                    params.public = Some(json!({
                        "embedLayoutProperties": false
                    }));
                }
            } else {
                value.params = Some(Params {
                    private: None,
                    public: Some(json!({
                        "embedLayoutProperties": false
                    })),
                });
            };
        }
    }

    Ok(Arc::new(CredentialFormatterProviderImpl::new(
        credential_formatters,
    )))
}
