use self::dto::{
    InvitationType, PresentationDefinitionResponseDTO, PresentedCredential, SubmitIssuerResponse,
};
use crate::{
    config::{
        core_config::{ExchangeConfig, ExchangeType},
        ConfigValidationError,
    },
    crypto::CryptoProvider,
    model::{credential::Credential, did::Did, interaction::Interaction, proof::Proof},
    provider::{
        credential_formatter::provider::CredentialFormatterProvider,
        key_storage::provider::KeyProvider,
        revocation::provider::RevocationMethodProvider,
        transport_protocol::{openid4vc::OpenID4VC, procivis_temp::ProcivisTemp},
    },
    repository::DataRepository,
    service::ssi_holder::dto::InvitationResponseDTO,
};
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{de, Serialize};
use thiserror::Error;
use url::Url;

pub mod dto;
mod mapper;
pub mod openid4vc;
pub mod procivis_temp;
pub(crate) mod provider;
#[cfg(test)]
mod test;

#[derive(Debug, Error)]
pub enum TransportProtocolError {
    #[error("Transport protocol failure: `{0}`")]
    Failed(String),
    #[error("HTTP request error: `{0}`")]
    HttpRequestError(reqwest::Error),
    #[error("HTTP response error: `{0}`")]
    HttpResponse(reqwest::Error),
    #[error("JSON error: `{0}`")]
    JsonError(serde_json::Error),
    #[error("Operation not supported")]
    OperationNotSupported,
    #[error("Base url is unknown")]
    MissingBaseUrl,
    #[error("Invalid request: `{0}`")]
    InvalidRequest(String),
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait TransportProtocol: Send + Sync {
    // holder methods
    fn detect_invitation_type(&self, url: &Url) -> Option<InvitationType>;

    async fn handle_invitation(
        &self,
        url: Url,
        own_did: Did,
    ) -> Result<InvitationResponseDTO, TransportProtocolError>;

    async fn reject_proof(&self, proof: &Proof) -> Result<(), TransportProtocolError>;

    async fn submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
    ) -> Result<(), TransportProtocolError>;

    async fn accept_credential(
        &self,
        credential: &Credential,
    ) -> Result<SubmitIssuerResponse, TransportProtocolError>;

    async fn reject_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), TransportProtocolError>;

    async fn get_presentation_definition(
        &self,
        proof: &Proof,
    ) -> Result<PresentationDefinitionResponseDTO, TransportProtocolError>;

    // issuer methods
    /// Generates QR-code content to start the credential issuance flow
    async fn share_credential(
        &self,
        credential: &Credential,
    ) -> Result<String, TransportProtocolError>;

    // verifier methods
    /// Generates QR-code content to start the proof request flow
    async fn share_proof(&self, proof: &Proof) -> Result<String, TransportProtocolError>;
}

pub(super) fn get_base_url_from_interaction(
    interaction: Option<&Interaction>,
) -> Result<Url, TransportProtocolError> {
    interaction
        .ok_or(TransportProtocolError::Failed(
            "interaction is None".to_string(),
        ))?
        .host
        .as_ref()
        .ok_or(TransportProtocolError::Failed(
            "interaction host is missing".to_string(),
        ))
        .cloned()
}

pub(super) fn serialize_interaction_data<DataDTO: ?Sized + Serialize>(
    dto: &DataDTO,
) -> Result<Vec<u8>, TransportProtocolError> {
    serde_json::to_vec(&dto).map_err(TransportProtocolError::JsonError)
}

pub(super) fn deserialize_interaction_data<DataDTO: for<'a> de::Deserialize<'a>>(
    interaction: Option<&Interaction>,
) -> Result<DataDTO, TransportProtocolError> {
    let data = interaction
        .ok_or(TransportProtocolError::Failed(
            "interaction is None".to_string(),
        ))?
        .data
        .as_ref()
        .ok_or(TransportProtocolError::Failed(
            "interaction data is missing".to_string(),
        ))?;

    serde_json::from_slice(data).map_err(TransportProtocolError::JsonError)
}

pub(crate) fn transport_protocol_providers_from_config(
    config: &ExchangeConfig,
    core_base_url: Option<String>,
    crypto: Arc<dyn CryptoProvider + Send + Sync>,
    data_provider: Arc<dyn DataRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
    key_provider: Arc<dyn KeyProvider + Send + Sync>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider + Send + Sync>,
) -> Result<HashMap<String, Arc<dyn TransportProtocol>>, ConfigValidationError> {
    let mut providers: HashMap<String, Arc<dyn TransportProtocol>> = HashMap::new();

    for (name, fields) in config.as_inner() {
        match fields.r#type {
            ExchangeType::ProcivisTemporary => {
                let protocol = Arc::new(ProcivisTemp::new(
                    core_base_url.clone(),
                    data_provider.get_credential_repository(),
                    data_provider.get_proof_repository(),
                    data_provider.get_interaction_repository(),
                    data_provider.get_credential_schema_repository(),
                    data_provider.get_did_repository(),
                    formatter_provider.clone(),
                    key_provider.clone(),
                ));

                providers.insert(name.to_string(), protocol);
            }
            ExchangeType::OpenId4Vc => {
                let params = config.get(name)?;

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
                    crypto.clone(),
                    params,
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
