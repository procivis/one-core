pub mod dto;
pub mod service;

use std::sync::Arc;

use crate::config::core_config;
use crate::config::core_config::IssuanceProtocolType;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::transaction_manager::TransactionManager;
use crate::proto::wallet_instance::HolderWalletUnitProto;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::issuance_protocol::openid4vci_final1_0_swiyu::OID4VCI_FINAL1_0_SWIYU_VERSION;
use crate::provider::issuance_protocol::provider::IssuanceProtocolProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::service::oid4vci_final1_0::OID4VCIFinal1_0Service;
use crate::service::oid4vci_final1_0::resolver::CredentialIssuerMetadataFetcher;

#[derive(Clone)]
pub struct OID4VCIFinal1_0SwiyuService {
    inner: OID4VCIFinal1_0Service,
}

impl OID4VCIFinal1_0SwiyuService {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        core_base_url: Option<String>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        credential_repository: Arc<dyn CredentialRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        config: Arc<core_config::CoreConfig>,
        protocol_provider: Arc<dyn IssuanceProtocolProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        transaction_manager: Arc<dyn TransactionManager>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        holder_wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
        credential_issuer_metadata_cache: Arc<dyn CredentialIssuerMetadataFetcher>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        ecosystem_provider: Arc<dyn EcosystemDirectory>,
    ) -> Self {
        let protocol_base_url = core_base_url
            .as_ref()
            .map(|url| format!("{url}/ssi/openid4vci/{OID4VCI_FINAL1_0_SWIYU_VERSION}"));
        Self {
            inner: OID4VCIFinal1_0Service::new_with_custom_protocol(
                core_base_url,
                protocol_base_url,
                IssuanceProtocolType::OpenId4vciFinal1_0Swiyu,
                credential_schema_repository.clone(),
                credential_repository,
                interaction_repository,
                identifier_repository,
                config,
                protocol_provider,
                did_method_provider,
                key_algorithm_provider,
                key_provider,
                revocation_method_provider,
                certificate_validator,
                identifier_creator,
                transaction_manager,
                blob_storage_provider,
                holder_wallet_unit_proto,
                credential_issuer_metadata_cache,
                formatter_provider,
                ecosystem_provider,
            ),
        }
    }
}
