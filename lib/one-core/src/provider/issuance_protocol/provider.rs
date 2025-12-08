use std::collections::HashMap;
use std::sync::Arc;

use itertools::Itertools;
use serde_json::json;
use url::Url;

use super::openid4vci_draft13::OpenID4VCI13;
use super::openid4vci_draft13::model::OpenID4VCIDraft13Params;
use super::openid4vci_draft13_swiyu::{OpenID4VCI13Swiyu, OpenID4VCISwiyuParams};
use super::openid4vci_final1_0::OpenID4VCIFinal1_0;
use super::openid4vci_final1_0::model::OpenID4VCIFinal1Params;
use super::{IssuanceProtocol, openid4vci_draft13};
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, IssuanceProtocolConfig, IssuanceProtocolType};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::credential_schema::importer::CredentialSchemaImporter;
use crate::proto::credential_schema::parser::CredentialSchemaImportParser;
use crate::proto::http_client::HttpClient;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::wallet_unit::HolderWalletUnitProto;
use crate::provider::blob_storage_provider::BlobStorageProvider;
use crate::provider::caching_loader::openid_metadata::OpenIDMetadataFetcher;
use crate::provider::caching_loader::vct::VctTypeMetadataFetcher;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_security_level::provider::KeySecurityLevelProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait IssuanceProtocolProvider: Send + Sync {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn IssuanceProtocol>>;
    async fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn IssuanceProtocol>)>;
}

struct IssuanceProtocolProviderImpl {
    protocols: HashMap<String, Arc<dyn IssuanceProtocol>>,
    config: IssuanceProtocolConfig,
}

#[async_trait::async_trait]
impl IssuanceProtocolProvider for IssuanceProtocolProviderImpl {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn IssuanceProtocol>> {
        self.protocols.get(protocol_id).cloned()
    }

    async fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn IssuanceProtocol>)> {
        let get_order = |id: &str| {
            self.config
                .get_fields(id)
                .ok()
                .and_then(|entry| entry.order)
                .unwrap_or(0)
        };
        let sorted_protocols = self
            .protocols
            .iter()
            .sorted_by(|(a, _), (b, _)| Ord::cmp(&get_order(a), &get_order(b)));

        for (id, protocol) in sorted_protocols {
            if protocol.holder_can_handle(url).await {
                return Some((id.to_owned(), protocol.to_owned()));
            }
        }

        None
    }
}

impl IssuanceProtocolProviderImpl {
    fn new(
        protocols: HashMap<String, Arc<dyn IssuanceProtocol>>,
        config: IssuanceProtocolConfig,
    ) -> Self {
        Self { protocols, config }
    }
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn issuance_protocol_provider_from_config(
    config: &mut CoreConfig,
    core_base_url: Option<String>,
    credential_repository: Arc<dyn CredentialRepository>,
    key_repository: Arc<dyn KeyRepository>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    vct_type_metadata_cache: Arc<dyn VctTypeMetadataFetcher>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_security_level_provider: Arc<dyn KeySecurityLevelProvider>,
    revocation_provider: Arc<dyn RevocationMethodProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    client: Arc<dyn HttpClient>,
    openid_metadata_cache: Arc<dyn OpenIDMetadataFetcher>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    credential_schema_importer: Arc<dyn CredentialSchemaImporter>,
    credential_schema_import_parser: Arc<dyn CredentialSchemaImportParser>,
    wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
) -> Result<Arc<dyn IssuanceProtocolProvider>, ConfigValidationError> {
    let mut providers: HashMap<String, Arc<dyn IssuanceProtocol>> = HashMap::new();

    let core_config = Arc::new(config.to_owned());

    for (name, fields) in config.issuance_protocol.iter_mut() {
        let protocol: Arc<dyn IssuanceProtocol> = match fields.r#type {
            IssuanceProtocolType::OpenId4VciFinal1_0 => {
                let params = fields
                    .deserialize::<OpenID4VCIFinal1Params>()
                    .map_err(|source| ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    })?;

                Arc::new(OpenID4VCIFinal1_0::new(
                    client.clone(),
                    openid_metadata_cache.clone(),
                    credential_repository.clone(),
                    key_repository.clone(),
                    identifier_creator.clone(),
                    validity_credential_repository.clone(),
                    formatter_provider.clone(),
                    revocation_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    key_security_level_provider.clone(),
                    blob_storage_provider.clone(),
                    core_base_url.clone(),
                    core_config.clone(),
                    params,
                    name.to_owned(),
                    wallet_unit_proto.clone(),
                ))
            }
            IssuanceProtocolType::OpenId4VciDraft13 => {
                let params = fields
                    .deserialize::<OpenID4VCIDraft13Params>()
                    .map_err(|source| ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    })?;

                let handle_invitation_operations = openid4vci_draft13::handle_invitation_operations::HandleInvitationOperationsImpl::new(
                    vct_type_metadata_cache.clone(),
                    client.clone(),
                    credential_schema_importer.clone(),
                    credential_schema_import_parser.clone(),
                    core_config.clone(),
                );

                Arc::new(OpenID4VCI13::new(
                    client.clone(),
                    openid_metadata_cache.clone(),
                    credential_repository.clone(),
                    key_repository.clone(),
                    validity_credential_repository.clone(),
                    formatter_provider.clone(),
                    revocation_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_security_level_provider.clone(),
                    key_provider.clone(),
                    certificate_validator.clone(),
                    identifier_creator.clone(),
                    blob_storage_provider.clone(),
                    core_base_url.clone(),
                    core_config.clone(),
                    params,
                    Arc::new(handle_invitation_operations),
                ))
            }
            IssuanceProtocolType::OpenId4VciDraft13Swiyu => {
                let params = fields
                    .deserialize::<OpenID4VCISwiyuParams>()
                    .map_err(|source| ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    })?;

                let handle_invitation_operations = openid4vci_draft13::handle_invitation_operations::HandleInvitationOperationsImpl::new(
                    vct_type_metadata_cache.clone(),
                    client.clone(),
                    credential_schema_importer.clone(),
                    credential_schema_import_parser.clone(),
                    core_config.clone(),
                );

                Arc::new(OpenID4VCI13Swiyu::new(
                    client.clone(),
                    openid_metadata_cache.clone(),
                    credential_repository.clone(),
                    key_repository.clone(),
                    validity_credential_repository.clone(),
                    formatter_provider.clone(),
                    revocation_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_security_level_provider.clone(),
                    key_provider.clone(),
                    certificate_validator.clone(),
                    identifier_creator.clone(),
                    blob_storage_provider.clone(),
                    core_base_url.clone(),
                    core_config.clone(),
                    params,
                    Arc::new(handle_invitation_operations),
                ))
            }
        };
        fields.capabilities = Some(json!(protocol.get_capabilities()));
        providers.insert(name.to_string(), protocol);
    }

    Ok(Arc::new(IssuanceProtocolProviderImpl::new(
        providers,
        config.issuance_protocol.to_owned(),
    )))
}
