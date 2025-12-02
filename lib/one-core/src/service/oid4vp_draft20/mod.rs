use std::sync::Arc;

use crate::config::core_config;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::identifier::creator::IdentifierCreator;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::blob_storage_provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;

pub mod mapper;
pub(crate) mod proof_request;
pub mod service;

#[derive(Clone)]
pub struct OID4VPDraft20Service {
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    key_repository: Arc<dyn KeyRepository>,
    key_provider: Arc<dyn KeyProvider>,
    config: Arc<core_config::CoreConfig>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    transaction_manager: Arc<dyn TransactionManager>,
}

#[expect(clippy::too_many_arguments)]
impl OID4VPDraft20Service {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        key_repository: Arc<dyn KeyRepository>,
        key_provider: Arc<dyn KeyProvider>,
        config: Arc<core_config::CoreConfig>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        certificate_validator: Arc<dyn CertificateValidator>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        transaction_manager: Arc<dyn TransactionManager>,
    ) -> Self {
        Self {
            credential_repository,
            proof_repository,
            key_repository,
            key_provider,
            config,
            credential_formatter_provider,
            presentation_formatter_provider,
            did_method_provider,
            key_algorithm_provider,
            revocation_method_provider,
            validity_credential_repository,
            certificate_validator,
            blob_storage_provider,
            identifier_creator,
            transaction_manager,
        }
    }
}

#[cfg(test)]
mod test;
