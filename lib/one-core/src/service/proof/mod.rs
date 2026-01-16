use std::sync::Arc;

use crate::config::core_config;
use crate::proto::bluetooth_low_energy::ble_resource::BleWaiter;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::nfc::hce::NfcHce;
use crate::proto::openid4vp_proof_validator::OpenId4VpProofValidator;
use crate::proto::session_provider::SessionProvider;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::blob_storage_provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::verification_protocol::provider::VerificationProtocolProvider;
use crate::repository::claim_repository::ClaimRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;

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
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
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
    organisation_repository: Arc<dyn OrganisationRepository>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    nfc_hce_provider: Option<Arc<dyn NfcHce>>,
    session_provider: Arc<dyn SessionProvider>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    transaction_manager: Arc<dyn TransactionManager>,
    proof_validator: Arc<dyn OpenId4VpProofValidator>,
}

impl ProofService {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        proof_repository: Arc<dyn ProofRepository>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
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
        organisation_repository: Arc<dyn OrganisationRepository>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        certificate_validator: Arc<dyn CertificateValidator>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        nfc_hce_provider: Option<Arc<dyn NfcHce>>,
        session_provider: Arc<dyn SessionProvider>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        transaction_manager: Arc<dyn TransactionManager>,
        proof_validator: Arc<dyn OpenId4VpProofValidator>,
    ) -> Self {
        Self {
            proof_repository,
            key_algorithm_provider,
            proof_schema_repository,
            identifier_repository,
            claim_repository,
            credential_repository,
            credential_schema,
            history_repository,
            interaction_repository,
            credential_formatter_provider,
            presentation_formatter_provider,
            revocation_method_provider,
            protocol_provider,
            did_method_provider,
            ble,
            config,
            organisation_repository,
            validity_credential_repository,
            certificate_validator,
            blob_storage_provider,
            nfc_hce_provider,
            session_provider,
            identifier_creator,
            transaction_manager,
            proof_validator,
        }
    }
}

#[cfg(test)]
mod test;
mod validator;
