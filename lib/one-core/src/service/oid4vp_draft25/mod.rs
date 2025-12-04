use std::sync::Arc;

use crate::config::core_config;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::openid4vp_proof_validator::OpenId4VpProofValidator;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::blob_storage_provider::BlobStorageProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;

pub mod mapper;
pub(crate) mod proof_request;
pub mod service;

#[derive(Clone)]
pub struct OID4VPDraft25Service {
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    key_repository: Arc<dyn KeyRepository>,
    key_provider: Arc<dyn KeyProvider>,
    config: Arc<core_config::CoreConfig>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    transaction_manager: Arc<dyn TransactionManager>,
    proof_validator: Arc<dyn OpenId4VpProofValidator>,
}

#[expect(clippy::too_many_arguments)]
impl OID4VPDraft25Service {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        key_repository: Arc<dyn KeyRepository>,
        key_provider: Arc<dyn KeyProvider>,
        config: Arc<core_config::CoreConfig>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        transaction_manager: Arc<dyn TransactionManager>,
        proof_validator: Arc<dyn OpenId4VpProofValidator>,
    ) -> Self {
        Self {
            credential_repository,
            proof_repository,
            key_repository,
            key_provider,
            config,
            key_algorithm_provider,
            validity_credential_repository,
            blob_storage_provider,
            identifier_creator,
            transaction_manager,
            proof_validator,
        }
    }
}

#[cfg(test)]
mod test;
