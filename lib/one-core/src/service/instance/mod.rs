use std::sync::Arc;

use crate::config::core_config::CoreConfig;
use crate::proto::csr_creator::CsrCreator;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::os_provider::OSInfoProvider;
use crate::proto::schema_import::SchemaImporter;
use crate::proto::session_provider::SessionProvider;
use crate::proto::trust_collection::TrustCollectionManager;
use crate::proto::verifier_provider_client::VerifierProviderClient;
use crate::proto::wallet_instance::HolderWalletUnitProto;
use crate::proto::wallet_provider_client::WalletProviderClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::instance_repository::InstanceRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::organisation_repository::OrganisationRepository;

pub mod dto;
pub mod error;
pub(crate) mod mapper;
pub mod service;
#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct InstanceService {
    key_repository: Arc<dyn KeyRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    instance_repository: Arc<dyn InstanceRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    wallet_provider_client: Arc<dyn WalletProviderClient>,
    verifier_provider_client: Arc<dyn VerifierProviderClient>,
    wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
    os_info_provider: Arc<dyn OSInfoProvider>,
    trust_collection_manager: Arc<dyn TrustCollectionManager>,
    base_url: Option<String>,
    config: Arc<CoreConfig>,
    session_provider: Arc<dyn SessionProvider>,
    schema_importer: Arc<dyn SchemaImporter>,
    csr_creator: Arc<dyn CsrCreator>,
    identifier_creator: Arc<dyn IdentifierCreator>,
}

impl InstanceService {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        organisation_repository: Arc<dyn OrganisationRepository>,
        instance_repository: Arc<dyn InstanceRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        key_repository: Arc<dyn KeyRepository>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        wallet_provider_client: Arc<dyn WalletProviderClient>,
        verifier_provider_client: Arc<dyn VerifierProviderClient>,
        wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
        os_info_provider: Arc<dyn OSInfoProvider>,
        trust_collection_manager: Arc<dyn TrustCollectionManager>,
        base_url: Option<String>,
        config: Arc<CoreConfig>,
        session_provider: Arc<dyn SessionProvider>,
        schema_importer: Arc<dyn SchemaImporter>,
        csr_creator: Arc<dyn CsrCreator>,
        identifier_creator: Arc<dyn IdentifierCreator>,
    ) -> Self {
        Self {
            wallet_provider_client,
            verifier_provider_client,
            wallet_unit_proto,
            key_provider,
            key_repository,
            key_algorithm_provider,
            os_info_provider,
            trust_collection_manager,
            organisation_repository,
            instance_repository,
            history_repository,
            base_url,
            config,
            session_provider,
            schema_importer,
            csr_creator,
            identifier_creator,
        }
    }
}
