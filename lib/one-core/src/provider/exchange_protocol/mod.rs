use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use one_providers::key_storage::provider::KeyProvider;
use serde::{de, Serialize};
use thiserror::Error;
use url::Url;

use one_providers::key_algorithm::provider::KeyAlgorithmProvider;

use self::dto::{PresentationDefinitionResponseDTO, PresentedCredential, SubmitIssuerResponse};
use crate::config::core_config::{CoreConfig, ExchangeType};
use crate::config::ConfigValidationError;
use crate::model::credential::Credential;
use crate::model::did::Did;
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::exchange_protocol::openid4vc::OpenID4VC;
use crate::provider::exchange_protocol::procivis_temp::ProcivisTemp;
use crate::provider::exchange_protocol::scan_to_verify::ScanToVerify;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::DataRepository;
use crate::service::ssi_holder::dto::InvitationResponseDTO;

use super::bluetooth_low_energy::low_level::ble_central::BleCentral;
use super::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;

pub mod dto;
mod mapper;
pub mod openid4vc;
pub mod procivis_temp;
pub(crate) mod provider;
pub mod scan_to_verify;
#[cfg(test)]
mod test;

#[derive(Debug, Error)]
pub enum ExchangeProtocolError {
    #[error("Exchange protocol failure: `{0}`")]
    Failed(String),
    #[error("Exchange protocol disabled: `{0}`")]
    Disabled(String),
    #[error("Transport error: `{0}`")]
    Transport(anyhow::Error),
    #[error("JSON error: `{0}`")]
    JsonError(serde_json::Error),
    #[error("Operation not supported")]
    OperationNotSupported,
    #[error("Base url is unknown")]
    MissingBaseUrl,
    #[error("Invalid request: `{0}`")]
    InvalidRequest(String),
    #[error("Incorrect credential schema type")]
    IncorrectCredentialSchemaType,
    #[error("Incorrect credential schema type")]
    Other(anyhow::Error),
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait ExchangeProtocol: Send + Sync {
    // holder methods
    fn can_handle(&self, url: &Url) -> bool;

    async fn handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError>;

    async fn reject_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError>;

    async fn submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
    ) -> Result<(), ExchangeProtocolError>;

    async fn accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
    ) -> Result<SubmitIssuerResponse, ExchangeProtocolError>;

    async fn reject_credential(&self, credential: &Credential)
        -> Result<(), ExchangeProtocolError>;

    async fn get_presentation_definition(
        &self,
        proof: &Proof,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError>;

    // issuer methods
    /// Generates QR-code content to start the credential issuance flow
    async fn share_credential(
        &self,
        credential: &Credential,
    ) -> Result<String, ExchangeProtocolError>;

    // verifier methods
    /// Generates QR-code content to start the proof request flow
    async fn share_proof(&self, proof: &Proof) -> Result<String, ExchangeProtocolError>;
}

pub(super) fn get_base_url_from_interaction(
    interaction: Option<&Interaction>,
) -> Result<Url, ExchangeProtocolError> {
    interaction
        .ok_or(ExchangeProtocolError::Failed(
            "interaction is None".to_string(),
        ))?
        .host
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed(
            "interaction host is missing".to_string(),
        ))
        .cloned()
}

pub(super) fn serialize_interaction_data<DataDTO: ?Sized + Serialize>(
    dto: &DataDTO,
) -> Result<Vec<u8>, ExchangeProtocolError> {
    serde_json::to_vec(&dto).map_err(ExchangeProtocolError::JsonError)
}

pub fn deserialize_interaction_data<DataDTO: for<'a> de::Deserialize<'a>>(
    interaction: Option<&Interaction>,
) -> Result<DataDTO, ExchangeProtocolError> {
    let data = interaction
        .ok_or(ExchangeProtocolError::Failed(
            "interaction is None".to_string(),
        ))?
        .data
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed(
            "interaction data is missing".to_string(),
        ))?;
    serde_json::from_slice(data).map_err(ExchangeProtocolError::JsonError)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn exchange_protocol_providers_from_config(
    config: Arc<CoreConfig>,
    core_base_url: Option<String>,
    data_provider: Arc<dyn DataRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    ble_peripheral: Option<Arc<dyn BlePeripheral>>,
    ble_central: Option<Arc<dyn BleCentral>>,
) -> Result<HashMap<String, Arc<dyn ExchangeProtocol>>, ConfigValidationError> {
    let mut providers: HashMap<String, Arc<dyn ExchangeProtocol>> = HashMap::new();

    for (name, fields) in config.exchange.iter() {
        match fields.r#type {
            ExchangeType::ProcivisTemporary => {
                let protocol = Arc::new(ProcivisTemp::new(
                    core_base_url.clone(),
                    data_provider.get_credential_repository(),
                    data_provider.get_interaction_repository(),
                    data_provider.get_credential_schema_repository(),
                    data_provider.get_did_repository(),
                    formatter_provider.clone(),
                    key_provider.clone(),
                    config.clone(),
                ));

                providers.insert(name.to_string(), protocol);
            }
            ExchangeType::ScanToVerify => {
                let protocol = Arc::new(ScanToVerify::new());

                providers.insert(name.to_string(), protocol);
            }
            ExchangeType::OpenId4Vc => {
                let params = config.exchange.get(name)?;

                let protocol = Arc::new(OpenID4VC::new(
                    core_base_url.clone(),
                    data_provider.get_credential_repository(),
                    data_provider.get_credential_schema_repository(),
                    data_provider.get_did_repository(),
                    data_provider.get_proof_repository(),
                    data_provider.get_interaction_repository(),
                    formatter_provider.clone(),
                    revocation_method_provider.clone(),
                    key_provider.clone(),
                    key_algorithm_provider.clone(),
                    params,
                    config.clone(),
                    ble_peripheral.clone(),
                    ble_central.clone(),
                ));

                providers.insert(name.to_string(), protocol);
            }
            ExchangeType::Mdl => {
                continue;
            }
        }
    }

    Ok(providers)
}
