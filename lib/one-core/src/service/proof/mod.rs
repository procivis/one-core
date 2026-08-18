use std::sync::Arc;

use crate::config::core_config;
use crate::proto::bluetooth_low_energy::ble_resource::BleWaiter;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::nfc::hce::NfcHce;
use crate::proto::notification_scheduler::NotificationScheduler;
use crate::proto::openid4vp_proof_validator::OpenId4VpProofValidator;
use crate::proto::session_provider::SessionProvider;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::transaction_data::provider::TransactionDataProvider;
use crate::provider::verification_protocol::provider::VerificationProtocolProvider;
use crate::repository::claim_repository::ClaimRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;

pub mod dto;
pub mod error;
mod iso_mdl;
mod mapper;
mod proximity_callback;
pub mod service;

#[derive(Clone)]
pub struct ProofService {
    proof_repository: Arc<dyn ProofRepository>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    claim_repository: Arc<dyn ClaimRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    protocol_provider: Arc<dyn VerificationProtocolProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    ble: Option<BleWaiter>,
    config: Arc<core_config::CoreConfig>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    nfc_hce_provider: Option<Arc<dyn NfcHce>>,
    session_provider: Arc<dyn SessionProvider>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    transaction_manager: Arc<dyn TransactionManager>,
    proof_validator: Arc<dyn OpenId4VpProofValidator>,
    notification_scheduler: Arc<dyn NotificationScheduler>,
    transaction_data_provider: Arc<dyn TransactionDataProvider>,
    ecosystem_provider: Arc<dyn EcosystemDirectory>,
}

impl ProofService {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        proof_repository: Arc<dyn ProofRepository>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        claim_repository: Arc<dyn ClaimRepository>,
        credential_repository: Arc<dyn CredentialRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
        protocol_provider: Arc<dyn VerificationProtocolProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        ble: Option<BleWaiter>,
        config: Arc<core_config::CoreConfig>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        certificate_validator: Arc<dyn CertificateValidator>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        nfc_hce_provider: Option<Arc<dyn NfcHce>>,
        session_provider: Arc<dyn SessionProvider>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        transaction_manager: Arc<dyn TransactionManager>,
        proof_validator: Arc<dyn OpenId4VpProofValidator>,
        notification_scheduler: Arc<dyn NotificationScheduler>,
        transaction_data_provider: Arc<dyn TransactionDataProvider>,
        ecosystem_provider: Arc<dyn EcosystemDirectory>,
    ) -> Self {
        Self {
            proof_repository,
            key_provider,
            key_algorithm_provider,
            proof_schema_repository,
            identifier_repository,
            claim_repository,
            credential_repository,
            history_repository,
            interaction_repository,
            credential_formatter_provider,
            presentation_formatter_provider,
            protocol_provider,
            did_method_provider,
            ble,
            config,
            organisation_repository,
            certificate_validator,
            blob_storage_provider,
            nfc_hce_provider,
            session_provider,
            identifier_creator,
            transaction_manager,
            proof_validator,
            notification_scheduler,
            transaction_data_provider,
            ecosystem_provider,
        }
    }
}

#[cfg(test)]
mod test;
mod validator;
