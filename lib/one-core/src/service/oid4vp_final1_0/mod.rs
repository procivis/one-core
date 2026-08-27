use std::sync::Arc;

use crate::config::core_config;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::openid4vp_proof_validator::OpenId4VpProofValidator;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::proof_repository::ProofRepository;

pub mod error;
pub(crate) mod proof_request;
pub mod service;

#[derive(Clone)]
pub struct OID4VPFinal1_0Service {
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    key_repository: Arc<dyn KeyRepository>,
    key_provider: Arc<dyn KeyProvider>,
    config: Arc<core_config::CoreConfig>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    transaction_manager: Arc<dyn TransactionManager>,
    proof_validator: Arc<dyn OpenId4VpProofValidator>,
    ecosystem_provider: Arc<dyn EcosystemDirectory>,
}

#[expect(clippy::too_many_arguments)]
impl OID4VPFinal1_0Service {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        key_repository: Arc<dyn KeyRepository>,
        key_provider: Arc<dyn KeyProvider>,
        config: Arc<core_config::CoreConfig>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        transaction_manager: Arc<dyn TransactionManager>,
        proof_validator: Arc<dyn OpenId4VpProofValidator>,
        ecosystem_provider: Arc<dyn EcosystemDirectory>,
    ) -> Self {
        Self {
            credential_repository,
            proof_repository,
            interaction_repository,
            key_repository,
            key_provider,
            config,
            key_algorithm_provider,
            blob_storage_provider,
            identifier_creator,
            transaction_manager,
            proof_validator,
            ecosystem_provider,
        }
    }
}

#[cfg(test)]
mod test;
