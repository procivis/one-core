use std::sync::Arc;

use itertools::Itertools;
use url::Url;

use super::IssuanceProtocol;
use super::decorators::CapabilityChecked;
use super::openid4vci_final1_0::OpenID4VCIFinal1_0;
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, Fields, IssuanceProtocolType};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::credential_schema::importer::CredentialSchemaImporter;
use crate::proto::http_client::HttpClient;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::session_provider::SessionProvider;
use crate::proto::transaction_manager::TransactionManager;
use crate::proto::wallet_instance::HolderWalletUnitProto;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::caching_loader::openid_metadata::OpenIDMetadataFetcher;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_security_level::provider::KeySecurityLevelProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::provider_directory::{InitializationError, ProviderDirectory};
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::instance_repository::InstanceRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::wallet_attestation_repository::WalletAttestationRepository;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait IssuanceProtocolProvider: Send + Sync {
    fn get_protocol(&self, protocol_id: &str) -> Result<Arc<dyn IssuanceProtocol>, NestedError>;

    /// The protocol that handles `url`, if any.
    async fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn IssuanceProtocol>)>;
}

#[async_trait::async_trait]
impl IssuanceProtocolProvider
    for ProviderDirectory<String, Fields<IssuanceProtocolType>, dyn IssuanceProtocol>
{
    fn get_protocol(&self, protocol_id: &str) -> Result<Arc<dyn IssuanceProtocol>, NestedError> {
        self.provider(protocol_id)
    }

    async fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn IssuanceProtocol>)> {
        let get_order = |id: &String| {
            self.config(id)
                .ok()
                .and_then(|entry| entry.order)
                .unwrap_or(0)
        };
        let sorted_protocols = self
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

#[expect(clippy::too_many_arguments)]
fn initialize_provider(
    name: &str,
    fields: &Fields<IssuanceProtocolType>,
    core_config: &Arc<CoreConfig>,
    core_base_url: &Option<String>,
    credential_repository: &Arc<dyn CredentialRepository>,
    key_repository: &Arc<dyn KeyRepository>,
    formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    key_provider: &Arc<dyn KeyProvider>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_security_level_provider: &Arc<dyn KeySecurityLevelProvider>,
    revocation_provider: &Arc<dyn RevocationMethodProvider>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    certificate_validator: &Arc<dyn CertificateValidator>,
    identifier_creator: &Arc<dyn IdentifierCreator>,
    client: &Arc<dyn HttpClient>,
    openid_metadata_cache: &Arc<dyn OpenIDMetadataFetcher>,
    blob_storage_provider: &Arc<dyn BlobStorageProvider>,
    credential_schema_importer: &Arc<dyn CredentialSchemaImporter>,
    wallet_unit_proto: &Arc<dyn HolderWalletUnitProto>,
    holder_wallet_unit_repository: &Arc<dyn InstanceRepository>,
    history_repository: &Arc<dyn HistoryRepository>,
    session_provider: &Arc<dyn SessionProvider>,
    credential_schema_repository: &Arc<dyn CredentialSchemaRepository>,
    interaction_repository: &Arc<dyn InteractionRepository>,
    identifier_repository: &Arc<dyn IdentifierRepository>,
    did_repository: &Arc<dyn DidRepository>,
    wallet_attestation_repository: &Arc<dyn WalletAttestationRepository>,
    tx_manager: &Arc<dyn TransactionManager>,
) -> Result<Arc<dyn IssuanceProtocol>, InitializationError> {
    let provider: Arc<dyn IssuanceProtocol> = match fields.r#type {
        IssuanceProtocolType::OpenId4VciFinal1_0 => Arc::new(OpenID4VCIFinal1_0::new(
            client.clone(),
            openid_metadata_cache.clone(),
            credential_repository.clone(),
            key_repository.clone(),
            identifier_creator.clone(),
            credential_schema_importer.clone(),
            credential_schema_repository.clone(),
            formatter_provider.clone(),
            revocation_provider.clone(),
            did_method_provider.clone(),
            key_algorithm_provider.clone(),
            key_provider.clone(),
            key_security_level_provider.clone(),
            blob_storage_provider.clone(),
            core_base_url.clone(),
            core_config.clone(),
            fields.merge_fields(),
            name.to_owned(),
            wallet_unit_proto.clone(),
            holder_wallet_unit_repository.clone(),
            certificate_validator.clone(),
            history_repository.clone(),
            session_provider.clone(),
            interaction_repository.clone(),
            identifier_repository.clone(),
            did_repository.clone(),
            wallet_attestation_repository.clone(),
            tx_manager.clone(),
        )?),
    };
    Ok(provider)
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn issuance_protocol_provider_from_config(
    config: &mut CoreConfig,
    core_base_url: Option<String>,
    credential_repository: Arc<dyn CredentialRepository>,
    key_repository: Arc<dyn KeyRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
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
    wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
    holder_wallet_unit_repository: Arc<dyn InstanceRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    session_provider: Arc<dyn SessionProvider>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    did_repository: Arc<dyn DidRepository>,
    wallet_attestation_repository: Arc<dyn WalletAttestationRepository>,
    tx_manager: Arc<dyn TransactionManager>,
) -> Result<Arc<dyn IssuanceProtocolProvider>, ConfigValidationError> {
    let core_config = Arc::new(config.to_owned());

    let directory = ProviderDirectory::initialize(
        config.issuance_protocol.iter_mut(),
        |name: &String, fields: &Fields<IssuanceProtocolType>| {
            let provider = initialize_provider(
                name,
                fields,
                &core_config,
                &core_base_url,
                &credential_repository,
                &key_repository,
                &formatter_provider,
                &key_provider,
                &key_algorithm_provider,
                &key_security_level_provider,
                &revocation_provider,
                &did_method_provider,
                &certificate_validator,
                &identifier_creator,
                &client,
                &openid_metadata_cache,
                &blob_storage_provider,
                &credential_schema_importer,
                &wallet_unit_proto,
                &holder_wallet_unit_repository,
                &history_repository,
                &session_provider,
                &credential_schema_repository,
                &interaction_repository,
                &identifier_repository,
                &did_repository,
                &wallet_attestation_repository,
                &tx_manager,
            )?;

            let provider: Arc<dyn IssuanceProtocol> = Arc::new(CapabilityChecked(provider));

            Ok(provider)
        },
    )
    .error_while("initializing issuance protocol providers")?;

    Ok(Arc::new(directory))
}
