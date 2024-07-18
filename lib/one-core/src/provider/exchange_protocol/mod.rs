use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use one_providers::common_models::key::Key;
use one_providers::credential_formatter::model::DetailCredential;
use one_providers::credential_formatter::provider::CredentialFormatterProvider;
use one_providers::did::provider::DidMethodProvider;
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;
use one_providers::key_storage::provider::KeyProvider;
use serde::de::{Deserialize, DeserializeOwned};
use serde::Serialize;
use thiserror::Error;
use url::Url;

use self::dto::{
    PresentationDefinitionResponseDTO, PresentedCredential, ShareResponse, SubmitIssuerResponse,
};
use super::bluetooth_low_energy::low_level::ble_central::BleCentral;
use super::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use crate::config::core_config::{CoreConfig, ExchangeType};
use crate::config::ConfigValidationError;
use crate::model::credential::Credential;
use crate::model::did::Did;
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::exchange_protocol::openid4vc::OpenID4VC;
use crate::provider::exchange_protocol::procivis_temp::ProcivisTemp;
use crate::provider::exchange_protocol::scan_to_verify::ScanToVerify;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::DataRepository;
use crate::service::ssi_holder::dto::InvitationResponseDTO;

use crate::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};

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
    #[error(transparent)]
    Other(anyhow::Error),
    #[error(transparent)]
    StorageAccessError(anyhow::Error),
}

pub type StorageAccess = dyn StorageProxy;
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait StorageProxy: Send + Sync {
    async fn create_interaction(
        &self,
        interaction: Interaction,
    ) -> Result<crate::model::interaction::InteractionId, anyhow::Error>;
    async fn get_schema(
        &self,
        schema_id: &str,
        relations: &CredentialSchemaRelations,
    ) -> Result<Option<CredentialSchema>, anyhow::Error>;
    async fn create_credential_schema(
        &self,
        schema: CredentialSchema,
    ) -> Result<shared_types::CredentialSchemaId, anyhow::Error>;
}

#[cfg_attr(test, mockall::automock(type VCInteractionContext = (); type VPInteractionContext = ();))]
#[async_trait]
pub trait ExchangeProtocolImpl: Send + Sync {
    type VCInteractionContext;
    type VPInteractionContext;

    // holder methods
    fn can_handle(&self, url: &Url) -> bool;

    async fn handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
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
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError>;

    // verifier methods
    /// Generates QR-code content to start the proof request flow
    async fn share_proof(
        &self,
        proof: &Proof,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError>;

    /// For now: Specially for ScanToVerify
    async fn verifier_handle_proof(
        &self,
        proof: &Proof,
        submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError>;
}

pub trait ExchangeProtocol:
    ExchangeProtocolImpl<
    VCInteractionContext = serde_json::Value,
    VPInteractionContext = serde_json::Value,
>
{
}

#[cfg(test)]
pub type MockExchangeProtocol = ExchangeProtocolWrapper<MockExchangeProtocolImpl>;

#[derive(Default)]
pub struct ExchangeProtocolWrapper<T> {
    pub inner: T,
}

impl<T> ExchangeProtocolWrapper<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<T> ExchangeProtocolImpl for ExchangeProtocolWrapper<T>
where
    T: ExchangeProtocolImpl,
    T::VCInteractionContext: Serialize + DeserializeOwned,
    T::VPInteractionContext: Serialize + DeserializeOwned,
{
    type VCInteractionContext = serde_json::Value;
    type VPInteractionContext = serde_json::Value;

    fn can_handle(&self, url: &Url) -> bool {
        self.inner.can_handle(url)
    }

    async fn handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        self.inner
            .handle_invitation(url, organisation, storage_access)
            .await
    }

    async fn reject_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError> {
        self.inner.reject_proof(proof).await
    }

    async fn submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
    ) -> Result<(), ExchangeProtocolError> {
        self.inner
            .submit_proof(proof, credential_presentations, holder_did, key, jwk_key_id)
            .await
    }

    async fn accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
    ) -> Result<SubmitIssuerResponse, ExchangeProtocolError> {
        self.inner
            .accept_credential(credential, holder_did, key, jwk_key_id)
            .await
    }

    async fn reject_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), ExchangeProtocolError> {
        self.inner.reject_credential(credential).await
    }

    async fn get_presentation_definition(
        &self,
        proof: &Proof,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        self.inner.get_presentation_definition(proof).await
    }

    async fn share_credential(
        &self,
        credential: &Credential,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        self.inner
            .share_credential(credential)
            .await
            .map(|resp| ShareResponse {
                url: resp.url,
                id: resp.id,
                context: serde_json::json!(resp.context),
            })
    }

    async fn share_proof(
        &self,
        proof: &Proof,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        self.inner
            .share_proof(proof)
            .await
            .map(|resp| ShareResponse {
                url: resp.url,
                id: resp.id,
                context: serde_json::json!(resp.context),
            })
    }

    async fn verifier_handle_proof(
        &self,
        proof: &Proof,
        submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError> {
        self.inner.verifier_handle_proof(proof, submission).await
    }
}

impl<T> ExchangeProtocol for ExchangeProtocolWrapper<T>
where
    T: ExchangeProtocolImpl,
    T::VCInteractionContext: Serialize + DeserializeOwned,
    T::VPInteractionContext: Serialize + DeserializeOwned,
{
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

pub fn deserialize_interaction_data<DataDTO: for<'a> Deserialize<'a>>(
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
    did_method_provider: Arc<dyn DidMethodProvider>,
    ble_peripheral: Option<Arc<dyn BlePeripheral>>,
    ble_central: Option<Arc<dyn BleCentral>>,
) -> Result<HashMap<String, Arc<dyn ExchangeProtocol>>, ConfigValidationError> {
    let mut providers: HashMap<String, Arc<dyn ExchangeProtocol>> = HashMap::new();

    for (name, fields) in config.exchange.iter() {
        match fields.r#type {
            ExchangeType::ProcivisTemporary => {
                let protocol = Arc::new(ExchangeProtocolWrapper::new(ProcivisTemp::new(
                    core_base_url.clone(),
                    data_provider.get_credential_repository(),
                    data_provider.get_interaction_repository(),
                    data_provider.get_credential_schema_repository(),
                    data_provider.get_did_repository(),
                    formatter_provider.clone(),
                    key_provider.clone(),
                    config.clone(),
                )));

                providers.insert(name.to_string(), protocol);
            }
            ExchangeType::ScanToVerify => {
                let protocol = Arc::new(ExchangeProtocolWrapper::new(ScanToVerify::new(
                    formatter_provider.clone(),
                    key_algorithm_provider.clone(),
                    did_method_provider.clone(),
                )));

                providers.insert(name.to_string(), protocol);
            }
            ExchangeType::OpenId4Vc => {
                let params = config.exchange.get(name)?;

                let protocol = Arc::new(ExchangeProtocolWrapper::new(OpenID4VC::new(
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
                )));

                providers.insert(name.to_string(), protocol);
            }
            ExchangeType::Mdl => {
                continue;
            }
        }
    }

    Ok(providers)
}
