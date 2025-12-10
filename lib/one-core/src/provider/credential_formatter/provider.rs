//! Credential format provider.

use std::collections::HashMap;
use std::sync::Arc;

use one_crypto::CryptoProvider;
use serde_json::json;
use shared_types::CredentialFormat;

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
    fn get_credential_formatter(
        &self,
        credential_format: &CredentialFormat,
    ) -> Option<Arc<dyn CredentialFormatter>>;

    /// Retrieves the highest priority formatter by type, if any.
    /// Returns the config name and formatter.
    fn get_formatter_by_type(
        &self,
        format_type: FormatType,
    ) -> Option<(CredentialFormat, Arc<dyn CredentialFormatter>)>;
}

struct CredentialFormatterProviderImpl {
    credential_formatters: HashMap<CredentialFormat, Arc<dyn CredentialFormatter>>,
    /// Map of format type to name of highest priority formatter.
    type_to_name: HashMap<FormatType, CredentialFormat>,
}

impl CredentialFormatterProviderImpl {
    fn new(
        credential_formatters: HashMap<CredentialFormat, Arc<dyn CredentialFormatter>>,
        type_to_name: HashMap<FormatType, CredentialFormat>,
    ) -> Self {
        Self {
            credential_formatters,
            type_to_name,
        }
    }
}

impl CredentialFormatterProvider for CredentialFormatterProviderImpl {
    fn get_credential_formatter(
        &self,
        format: &CredentialFormat,
    ) -> Option<Arc<dyn CredentialFormatter>> {
        self.credential_formatters.get(format).cloned()
    }

    fn get_formatter_by_type(
        &self,
        format_type: FormatType,
    ) -> Option<(CredentialFormat, Arc<dyn CredentialFormatter>)> {
        let name = self.type_to_name.get(&format_type)?;
        let formatter = self.get_credential_formatter(name)?;
        Some((name.to_owned(), formatter))
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
    let mut credential_formatters: HashMap<CredentialFormat, Arc<dyn CredentialFormatter>> =
        HashMap::new();
    let mut type_to_name_prio: HashMap<FormatType, (CredentialFormat, u64)> = HashMap::new();

    for (name, field) in config.format.iter() {
        let priority = field.priority.unwrap_or_default();

        if absent_or_lower_priority(&type_to_name_prio, &field.r#type, priority) {
            type_to_name_prio.insert(field.r#type, (name.clone(), priority));
        }

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

    let type_to_name = type_to_name_prio
        .into_iter()
        .map(|(k, v)| (k, v.0))
        .collect();
    Ok(Arc::new(CredentialFormatterProviderImpl::new(
        credential_formatters,
        type_to_name,
    )))
}

fn absent_or_lower_priority(
    map: &HashMap<FormatType, (CredentialFormat, u64)>,
    key: &FormatType,
    priority: u64,
) -> bool {
    match map.get(key) {
        None => true,
        Some((_, existing_priority)) => *existing_priority < priority,
    }
}

#[cfg(test)]
mod test {
    use one_crypto::MockCryptoProvider;
    use similar_asserts::assert_eq;
    use time::Duration;

    use super::*;
    use crate::config::core_config::{ConfigEntryDisplay, Fields, IssuanceProtocolType};
    use crate::proto::certificate_validator::MockCertificateValidator;
    use crate::proto::http_client::MockHttpClient;
    use crate::provider::caching_loader::vct::MockVctTypeMetadataFetcher;
    use crate::provider::data_type::provider::MockDataTypeProvider;
    use crate::provider::did_method::provider::MockDidMethodProvider;
    use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
    use crate::provider::remote_entity_storage::{MockRemoteEntityStorage, RemoteEntityType};
    use crate::service::test_utilities::generic_config;

    #[test]
    fn get_formatter_by_type_returns_highest_priority() {
        let jsonld_cache_resolver = JsonLdCachingLoader::new(
            RemoteEntityType::JsonLdContext,
            Arc::new(MockRemoteEntityStorage::new()),
            100,
            Duration::seconds(2),
            Duration::seconds(2),
        );
        let mut generic_config = generic_config();
        generic_config.core.format.insert(
            "MY_SD_JWT_VC".into(),
            Fields {
                r#type: FormatType::SdJwtVc,
                display: ConfigEntryDisplay::TranslationId("translationId".to_string()),
                order: None,
                priority: Some(100),
                enabled: None,
                capabilities: None,
                params: Some(Params {
                    private: None,
                    public: Some(json!({
                        "leeway": 60,
                        "embedLayoutProperties": true,
                        "swiyuMode": false
                    })),
                }),
            },
        );
        generic_config.core.format.insert(
            "SD_JWT_VC_SWIYU".into(),
            Fields {
                r#type: FormatType::SdJwtVc,
                display: ConfigEntryDisplay::TranslationId("translationId".to_string()),
                order: None,
                priority: None,
                enabled: None,
                capabilities: None,
                params: Some(Params {
                    private: None,
                    public: Some(json!({
                        "leeway": 60,
                        "embedLayoutProperties": true,
                        "swiyuMode": true
                    })),
                }),
            },
        );

        let provider = credential_formatter_provider_from_config(
            &mut generic_config.core,
            Arc::new(MockKeyAlgorithmProvider::new()),
            Arc::new(MockHttpClient::new()),
            Arc::new(MockDataTypeProvider::new()),
            Arc::new(MockCryptoProvider::new()),
            jsonld_cache_resolver,
            Arc::new(MockDidMethodProvider::new()),
            Arc::new(MockVctTypeMetadataFetcher::new()),
            Arc::new(MockCertificateValidator::new()),
        )
        .unwrap();

        let (name, provider) = provider.get_formatter_by_type(FormatType::SdJwtVc).unwrap();
        assert_eq!(name.as_ref(), "MY_SD_JWT_VC");
        let capabilities = provider.get_capabilities();
        assert!(
            capabilities
                .issuance_exchange_protocols
                .contains(&IssuanceProtocolType::OpenId4VciDraft13) // not swiyu mode
        )
    }
}
