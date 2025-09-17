use std::sync::Arc;

use super::certificate::validator::CertificateValidator;
use crate::config::core_config;
use crate::provider::blob_storage_provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::issuance_protocol::provider::IssuanceProtocolProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::verification_protocol::provider::VerificationProtocolProvider;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;

pub mod dto;
pub mod issuance;
pub mod service;
pub mod verification;

mod mapper;
mod validator;

#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct SSIHolderService {
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    did_repository: Arc<dyn DidRepository>,
    key_repository: Arc<dyn KeyRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    certificate_repository: Arc<dyn CertificateRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    issuance_protocol_provider: Arc<dyn IssuanceProtocolProvider>,
    verification_protocol_provider: Arc<dyn VerificationProtocolProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    config: Arc<core_config::CoreConfig>,
    client: Arc<dyn HttpClient>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
}

#[allow(clippy::too_many_arguments)]
impl SSIHolderService {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        did_repository: Arc<dyn DidRepository>,
        key_repository: Arc<dyn KeyRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        certificate_repository: Arc<dyn CertificateRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        issuance_protocol_provider: Arc<dyn IssuanceProtocolProvider>,
        verification_protocol_provider: Arc<dyn VerificationProtocolProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        config: Arc<core_config::CoreConfig>,
        client: Arc<dyn HttpClient>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
    ) -> Self {
        Self {
            credential_repository,
            proof_repository,
            organisation_repository,
            interaction_repository,
            credential_schema_repository,
            validity_credential_repository,
            did_repository,
            key_repository,
            identifier_repository,
            certificate_repository,
            history_repository,
            key_provider,
            key_algorithm_provider,
            formatter_provider,
            issuance_protocol_provider,
            verification_protocol_provider,
            did_method_provider,
            certificate_validator,
            config,
            client,
            blob_storage_provider,
        }
    }
}
