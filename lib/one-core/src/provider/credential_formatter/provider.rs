//! Credential format provider.

use std::sync::Arc;

use itertools::Itertools;
use serde_json::json;
use shared_types::CredentialFormat;

use super::CredentialFormatter;
use super::decorators::CapabilityChecked;
use super::json_ld_bbsplus::JsonLdBbsplus;
use super::json_ld_classic::JsonLdClassic;
use super::jwt_formatter::JWTFormatter;
use super::mdoc_formatter::MdocFormatter;
use super::sdjwt_formatter::SDJWTFormatter;
use super::sdjwtvc_formatter::SDJWTVCFormatter;
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, DatatypeConfig, Fields, FormatType, Params};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::provider::caching_loader::json_ld_context::JsonLdCachingLoader;
use crate::provider::caching_loader::vct::VctTypeMetadataFetcher;
use crate::provider::data_type::provider::DataTypeProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::provider_directory::{InitializationError, ProviderDirectory};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait CredentialFormatterProvider: Send + Sync {
    fn get_credential_formatter(
        &self,
        credential_format: &CredentialFormat,
    ) -> Result<Arc<dyn CredentialFormatter>, NestedError>;

    /// Retrieves the highest priority formatter by type, if any.
    /// Returns the config name and formatter.
    fn get_formatter_by_type(
        &self,
        format_type: FormatType,
    ) -> Option<(CredentialFormat, Arc<dyn CredentialFormatter>)>;
}

impl CredentialFormatterProvider
    for ProviderDirectory<CredentialFormat, Fields<FormatType>, dyn CredentialFormatter>
{
    fn get_credential_formatter(
        &self,
        format: &CredentialFormat,
    ) -> Result<Arc<dyn CredentialFormatter>, NestedError> {
        self.provider(format)
    }

    fn get_formatter_by_type(
        &self,
        format_type: FormatType,
    ) -> Option<(CredentialFormat, Arc<dyn CredentialFormatter>)> {
        let (format_id, _) = self
            .iter_configs()
            .filter(|(_, field)| field.enabled && field.r#type == format_type)
            .sorted_by_key(|(_, field)| field.priority.unwrap_or_default())
            .last()?;

        self.provider(format_id)
            .ok()
            .map(|provider| (format_id.to_owned(), provider))
    }
}

#[expect(clippy::too_many_arguments)]
fn initialize_provider(
    name: &CredentialFormat,
    fields: &Fields<FormatType>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    client: &Arc<dyn HttpClient>,
    data_type_provider: &Arc<dyn DataTypeProvider>,
    json_ld_cache: &JsonLdCachingLoader,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    vct_type_metadata_cache: &Arc<dyn VctTypeMetadataFetcher>,
    certificate_validator: &Arc<dyn CertificateValidator>,
    datatype_config: &DatatypeConfig,
    base_url: Option<Arc<str>>,
) -> Result<Arc<dyn CredentialFormatter>, InitializationError> {
    let provider: Arc<dyn CredentialFormatter> = match fields.r#type {
        FormatType::Jwt => Arc::new(JWTFormatter::new(
            name.clone(),
            fields.merge_fields(),
            key_algorithm_provider.clone(),
            did_method_provider.clone(),
            data_type_provider.clone(),
        )?),
        FormatType::SdJwt => Arc::new(SDJWTFormatter::new(
            base_url,
            name.clone(),
            fields.merge_fields(),
            did_method_provider.clone(),
            key_algorithm_provider.clone(),
            data_type_provider.clone(),
            client.clone(),
        )?),
        FormatType::SdJwtVc => Arc::new(SDJWTVCFormatter::new(
            base_url,
            name.clone(),
            fields.merge_fields(),
            did_method_provider.clone(),
            key_algorithm_provider.clone(),
            vct_type_metadata_cache.clone(),
            certificate_validator.clone(),
            datatype_config.clone(),
            client.clone(),
            data_type_provider.clone(),
        )?),
        FormatType::JsonLdClassic => Arc::new(JsonLdClassic::new(
            name.clone(),
            fields.merge_fields(),
            json_ld_cache.clone(),
            data_type_provider.clone(),
            key_algorithm_provider.clone(),
            did_method_provider.clone(),
            client.clone(),
        )?),
        FormatType::JsonLdBbsPlus => Arc::new(JsonLdBbsplus::new(
            name.clone(),
            fields.merge_fields(),
            did_method_provider.clone(),
            data_type_provider.clone(),
            key_algorithm_provider.clone(),
            json_ld_cache.clone(),
            client.clone(),
        )?),
        FormatType::Mdoc => Arc::new(MdocFormatter::new(
            base_url,
            name.clone(),
            fields.merge_fields(),
            certificate_validator.clone(),
            did_method_provider.clone(),
            data_type_provider.clone(),
            key_algorithm_provider.clone(),
            client.clone(),
        )?),
    };
    Ok(provider)
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn credential_formatter_provider_from_config(
    config: &mut CoreConfig,
    base_url: Option<Arc<str>>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    client: Arc<dyn HttpClient>,
    data_type_provider: Arc<dyn DataTypeProvider>,
    json_ld_cache: JsonLdCachingLoader,
    did_method_provider: Arc<dyn DidMethodProvider>,
    vct_type_metadata_cache: Arc<dyn VctTypeMetadataFetcher>,
    certificate_validator: Arc<dyn CertificateValidator>,
) -> Result<Arc<dyn CredentialFormatterProvider>, ConfigValidationError> {
    let datatype_config = &config.datatype;
    let directory = ProviderDirectory::initialize(
        config.format.iter_mut(),
        |name: &CredentialFormat, fields: &Fields<FormatType>| {
            let provider = initialize_provider(
                name,
                fields,
                &key_algorithm_provider,
                &client,
                &data_type_provider,
                &json_ld_cache,
                &did_method_provider,
                &vct_type_metadata_cache,
                &certificate_validator,
                datatype_config,
                base_url.clone(),
            )?;

            let provider: Arc<dyn CredentialFormatter> = Arc::new(CapabilityChecked(provider));

            Ok(provider)
        },
    )
    .error_while("initializing credential format providers")?;

    for (_, fields) in config.format.iter_mut() {
        if let Some(params) = &mut fields.params {
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
            fields.params = Some(Params {
                private: None,
                public: Some(json!({
                    "embedLayoutProperties": false
                })),
            });
        };
    }

    Ok(Arc::new(directory))
}

#[cfg(test)]
mod test {
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
                enabled: true,
                capabilities: None,
                params: Some(Params {
                    private: None,
                    public: Some(json!({
                        "leewaySeconds": 60,
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
                enabled: true,
                capabilities: None,
                params: Some(Params {
                    private: None,
                    public: Some(json!({
                        "leewaySeconds": 60,
                        "embedLayoutProperties": true,
                        "swiyuMode": true
                    })),
                }),
            },
        );

        let provider = credential_formatter_provider_from_config(
            &mut generic_config.core,
            Some("testUrl".into()),
            Arc::new(MockKeyAlgorithmProvider::new()),
            Arc::new(MockHttpClient::new()),
            Arc::new(MockDataTypeProvider::new()),
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
                .contains(&IssuanceProtocolType::OpenId4VciFinal1_0) // not swiyu mode
        )
    }
}
