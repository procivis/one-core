use std::sync::Arc;

use crate::config::core_config;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::verification_protocol::provider::VerificationProtocolProvider;
use crate::repository::claim_repository::ClaimRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::util::ble_resource::BleWaiter;
pub mod dto;
mod iso_mdl;
mod mapper;
mod scan_to_verify;
pub mod service;

#[derive(Clone)]
pub struct ProofService {
    proof_repository: Arc<dyn ProofRepository>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    did_repository: Arc<dyn DidRepository>,
    claim_repository: Arc<dyn ClaimRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    credential_schema: Arc<dyn CredentialSchemaRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    protocol_provider: Arc<dyn VerificationProtocolProvider>,
    #[allow(dead_code)]
    did_method_provider: Arc<dyn DidMethodProvider>,
    ble: Option<BleWaiter>,
    config: Arc<core_config::CoreConfig>,
    base_url: Option<String>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
}

impl ProofService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        proof_repository: Arc<dyn ProofRepository>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        did_repository: Arc<dyn DidRepository>,
        claim_repository: Arc<dyn ClaimRepository>,
        credential_repository: Arc<dyn CredentialRepository>,
        credential_schema: Arc<dyn CredentialSchemaRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        protocol_provider: Arc<dyn VerificationProtocolProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        ble: Option<BleWaiter>,
        config: Arc<core_config::CoreConfig>,
        base_url: Option<String>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    ) -> Self {
        Self {
            proof_repository,
            key_algorithm_provider,
            key_provider,
            proof_schema_repository,
            did_repository,
            claim_repository,
            credential_repository,
            credential_schema,
            history_repository,
            interaction_repository,
            credential_formatter_provider,
            revocation_method_provider,
            protocol_provider,
            did_method_provider,
            ble,
            config,
            base_url,
            organisation_repository,
            validity_credential_repository,
        }
    }
}

#[cfg(test)]
mod test;
mod validator;
