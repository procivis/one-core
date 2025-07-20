use std::sync::Arc;

use crate::config::core_config;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::verification_protocol::provider::VerificationProtocolProvider;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::claim_repository::ClaimRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::certificate::validator::CertificateValidator;
use crate::util::ble_resource::BleWaiter;

pub mod dto;
mod iso_mdl;
mod mapper;
mod proximity_callback;
mod scan_to_verify;
pub mod service;

#[derive(Clone)]
pub struct ProofService {
    proof_repository: Arc<dyn ProofRepository>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    did_repository: Arc<dyn DidRepository>,
    certificate_repository: Arc<dyn CertificateRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    claim_repository: Arc<dyn ClaimRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    key_repository: Arc<dyn KeyRepository>,
    credential_schema: Arc<dyn CredentialSchemaRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    protocol_provider: Arc<dyn VerificationProtocolProvider>,
    #[allow(dead_code)]
    did_method_provider: Arc<dyn DidMethodProvider>,
    ble: Option<BleWaiter>,
    config: Arc<core_config::CoreConfig>,
    base_url: Option<String>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
}

impl ProofService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        proof_repository: Arc<dyn ProofRepository>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        did_repository: Arc<dyn DidRepository>,
        certificate_repository: Arc<dyn CertificateRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        claim_repository: Arc<dyn ClaimRepository>,
        credential_repository: Arc<dyn CredentialRepository>,
        credential_schema: Arc<dyn CredentialSchemaRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        protocol_provider: Arc<dyn VerificationProtocolProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        ble: Option<BleWaiter>,
        config: Arc<core_config::CoreConfig>,
        base_url: Option<String>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        certificate_validator: Arc<dyn CertificateValidator>,
        key_repository: Arc<dyn KeyRepository>,
    ) -> Self {
        Self {
            proof_repository,
            key_algorithm_provider,
            key_provider,
            proof_schema_repository,
            did_repository,
            certificate_repository,
            identifier_repository,
            claim_repository,
            credential_repository,
            credential_schema,
            history_repository,
            interaction_repository,
            key_repository,
            credential_formatter_provider,
            presentation_formatter_provider,
            revocation_method_provider,
            protocol_provider,
            did_method_provider,
            ble,
            config,
            base_url,
            organisation_repository,
            validity_credential_repository,
            certificate_validator,
        }
    }
}

#[cfg(test)]
mod test;
mod validator;
