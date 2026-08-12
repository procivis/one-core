mod service;

use std::sync::Arc;

use crate::config::core_config;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::openid4vp_proof_validator::OpenId4VpProofValidator;
use crate::proto::session_provider::SessionProvider;
use crate::proto::transaction_manager::TransactionManager;
use crate::proto::wrp_validator::WRPValidator;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::oid4vp_final1_0::OID4VPFinal1_0Service;

#[derive(Clone)]
pub struct OID4VPFinal1_0SwiyuService {
    inner: OID4VPFinal1_0Service,
    proof_repository: Arc<dyn ProofRepository>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
}

#[expect(clippy::too_many_arguments)]
impl OID4VPFinal1_0SwiyuService {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        key_repository: Arc<dyn KeyRepository>,
        key_provider: Arc<dyn KeyProvider>,
        config: Arc<core_config::CoreConfig>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        transaction_manager: Arc<dyn TransactionManager>,
        proof_validator: Arc<dyn OpenId4VpProofValidator>,
        wrp_validator: Arc<dyn WRPValidator>,
        history_repository: Arc<dyn HistoryRepository>,
        session_provider: Arc<dyn SessionProvider>,
        ecosystem_provider: Arc<dyn EcosystemDirectory>,
    ) -> Self {
        let inner = OID4VPFinal1_0Service::new(
            credential_repository,
            proof_repository.clone(),
            key_repository,
            key_provider.clone(),
            config,
            key_algorithm_provider.clone(),
            blob_storage_provider,
            identifier_creator,
            transaction_manager,
            proof_validator,
            wrp_validator,
            history_repository,
            session_provider,
            ecosystem_provider,
        );
        Self {
            inner,
            proof_repository,
            key_algorithm_provider,
            key_provider,
        }
    }
}
