use std::sync::Arc;

use crate::config::core_config;
use crate::provider::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use crate::provider::exchange_protocol::provider::ExchangeProtocolProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use one_providers::credential_formatter::provider::CredentialFormatterProvider;
use one_providers::revocation::provider::RevocationMethodProvider;

pub mod dto;
mod mapper;
mod scan_to_verify;
pub mod service;

#[derive(Clone)]
pub struct ProofService {
    proof_repository: Arc<dyn ProofRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    did_repository: Arc<dyn DidRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    credential_schema: Arc<dyn CredentialSchemaRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    protocol_provider: Arc<dyn ExchangeProtocolProvider>,
    ble_peripheral: Option<Arc<dyn BlePeripheral>>,
    config: Arc<core_config::CoreConfig>,
    base_url: Option<String>,
}

impl ProofService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        proof_repository: Arc<dyn ProofRepository>,
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        did_repository: Arc<dyn DidRepository>,
        credential_repository: Arc<dyn CredentialRepository>,
        credential_schema: Arc<dyn CredentialSchemaRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        protocol_provider: Arc<dyn ExchangeProtocolProvider>,
        ble_peripheral: Option<Arc<dyn BlePeripheral>>,
        config: Arc<core_config::CoreConfig>,
        base_url: Option<String>,
    ) -> Self {
        Self {
            proof_repository,
            proof_schema_repository,
            did_repository,
            credential_repository,
            credential_schema,
            history_repository,
            interaction_repository,
            credential_formatter_provider,
            revocation_method_provider,
            protocol_provider,
            ble_peripheral,
            config,
            base_url,
        }
    }
}

#[cfg(test)]
mod test;
mod validator;
