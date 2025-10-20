use std::sync::Arc;

use crate::config::core_config;
use crate::proto::certificate_validator::CertificateValidator;
use crate::provider::blob_storage_provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;

pub mod mapper;
pub(crate) mod proof_request;
pub mod service;

#[derive(Clone)]
pub struct OID4VPFinal1_0Service {
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    key_repository: Arc<dyn KeyRepository>,
    key_provider: Arc<dyn KeyProvider>,
    config: Arc<core_config::CoreConfig>,
    did_repository: Arc<dyn DidRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
    certificate_repository: Arc<dyn CertificateRepository>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
}

#[allow(clippy::too_many_arguments)]
impl OID4VPFinal1_0Service {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        key_repository: Arc<dyn KeyRepository>,
        key_provider: Arc<dyn KeyProvider>,
        config: Arc<core_config::CoreConfig>,
        did_repository: Arc<dyn DidRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        certificate_validator: Arc<dyn CertificateValidator>,
        certificate_repository: Arc<dyn CertificateRepository>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
    ) -> Self {
        Self {
            credential_repository,
            proof_repository,
            key_repository,
            key_provider,
            config,
            did_repository,
            identifier_repository,
            credential_formatter_provider,
            presentation_formatter_provider,
            did_method_provider,
            key_algorithm_provider,
            revocation_method_provider,
            validity_credential_repository,
            certificate_validator,
            certificate_repository,
            blob_storage_provider,
        }
    }
}

#[cfg(test)]
mod test;
