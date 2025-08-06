use std::collections::HashMap;

use one_core::provider::issuance_protocol::openid4vci_draft13::model::{
    OpenID4VCIProofTypeSupported, OpenID4VCITxCode, OpenID4VCITxCodeInputMode,
};
use one_core::service::error::ServiceError;
use one_core::service::ssi_holder::dto::{
    ContinueIssuanceResponseDTO, CredentialConfigurationSupportedResponseDTO,
    InitiateIssuanceAuthorizationDetailDTO, InitiateIssuanceRequestDTO,
    InitiateIssuanceResponseDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner, convert_inner_of_inner};
use url::Url;

use crate::OneCoreBinding;
use crate::error::BindingError;
use crate::utils::into_id;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn handle_invitation(
        &self,
        url: String,
        organisation_id: String,
        transport: Option<Vec<String>>,
    ) -> Result<HandleInvitationResponseBindingEnum, BindingError> {
        let url = Url::parse(&url).map_err(|e| ServiceError::ValidationError(e.to_string()))?;

        let organisation_id = into_id(&organisation_id)?;

        let core = self.use_core().await?;
        let invitation_response = core
            .ssi_holder_service
            .handle_invitation(url, organisation_id, transport)
            .await?;

        Ok(invitation_response.into())
    }

    #[uniffi::method]
    pub async fn holder_accept_credential(
        &self,
        interaction_id: String,
        did_id: Option<String>,
        identifier_id: Option<String>,
        key_id: Option<String>,
        tx_code: Option<String>,
    ) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .ssi_holder_service
            .accept_credential(
                &into_id(&interaction_id)?,
                did_id.map(into_id).transpose()?,
                identifier_id.map(into_id).transpose()?,
                key_id.map(into_id).transpose()?,
                tx_code,
            )
            .await?)
    }

    #[uniffi::method]
    pub async fn holder_reject_credential(
        &self,
        interaction_id: String,
    ) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .ssi_holder_service
            .reject_credential(&into_id(&interaction_id)?)
            .await?)
    }

    #[uniffi::method]
    pub async fn initiate_issuance(
        &self,
        request: InitiateIssuanceRequestBindingDTO,
    ) -> Result<InitiateIssuanceResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .ssi_holder_service
            .initiate_issuance(request.try_into()?)
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn continue_issuance(
        &self,
        url: String,
    ) -> Result<ContinueIssuanceResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core.ssi_holder_service.continue_issuance(url).await?.into())
    }
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum HandleInvitationResponseBindingEnum {
    CredentialIssuance {
        interaction_id: String,
        credential_ids: Vec<String>,
        tx_code: Option<OpenID4VCITxCodeBindingDTO>,
        credential_configurations_supported:
            HashMap<String, CredentialConfigurationSupportedResponseBindingDTO>,
    },
    ProofRequest {
        interaction_id: String,
        proof_id: String,
    },
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ContinueIssuanceResponseBindingDTO {
    pub interaction_id: String,
    pub credential_ids: Vec<String>,
    pub credential_configurations_supported:
        HashMap<String, CredentialConfigurationSupportedResponseBindingDTO>,
}

impl From<ContinueIssuanceResponseDTO> for ContinueIssuanceResponseBindingDTO {
    fn from(value: ContinueIssuanceResponseDTO) -> Self {
        Self {
            interaction_id: value.interaction_id.to_string(),
            credential_ids: value
                .credential_ids
                .iter()
                .map(ToString::to_string)
                .collect(),
            credential_configurations_supported: value
                .credential_configurations_supported
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.into()))
                .collect(),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct CredentialConfigurationSupportedResponseBindingDTO {
    pub proof_types_supported: Option<HashMap<String, OpenID4VCIProofTypeSupportedBindingDTO>>,
}

impl From<CredentialConfigurationSupportedResponseDTO>
    for CredentialConfigurationSupportedResponseBindingDTO
{
    fn from(value: CredentialConfigurationSupportedResponseDTO) -> Self {
        Self {
            proof_types_supported: value
                .proof_types_supported
                .map(|m| m.into_iter().map(|(i, v)| (i, v.into())).collect()),
        }
    }
}

#[derive(Clone, Debug, From, Default, uniffi::Record)]
#[from(OpenID4VCIProofTypeSupported)]
pub struct OpenID4VCIProofTypeSupportedBindingDTO {
    pub proof_signing_alg_values_supported: Vec<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(OpenID4VCITxCode)]
pub struct OpenID4VCITxCodeBindingDTO {
    pub input_mode: OpenID4VCITxCodeInputModeBindingEnum,
    #[from(with_fn = convert_inner)]
    pub length: Option<i64>,
    #[from(with_fn = convert_inner)]
    pub description: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(OpenID4VCITxCodeInputMode)]
pub enum OpenID4VCITxCodeInputModeBindingEnum {
    Numeric,
    Text,
}

#[derive(Clone, Debug, uniffi::Record, TryInto)]
#[try_into(T=InitiateIssuanceRequestDTO, Error=ServiceError)]
pub struct InitiateIssuanceRequestBindingDTO {
    #[try_into(with_fn = into_id)]
    pub organisation_id: String,
    #[try_into(infallible)]
    pub protocol: String,
    #[try_into(infallible)]
    pub issuer: String,
    #[try_into(infallible)]
    pub client_id: String,
    #[try_into(with_fn = convert_inner, infallible)]
    pub redirect_uri: Option<String>,
    #[try_into(with_fn = convert_inner_of_inner, infallible)]
    pub scope: Option<Vec<String>>,
    #[try_into(with_fn = convert_inner_of_inner, infallible)]
    pub authorization_details: Option<Vec<InitiateIssuanceAuthorizationDetailBindingDTO>>,
}

#[derive(Clone, Debug, uniffi::Record, Into)]
#[into(InitiateIssuanceAuthorizationDetailDTO)]
pub struct InitiateIssuanceAuthorizationDetailBindingDTO {
    pub r#type: String,
    pub credential_configuration_id: String,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[from(InitiateIssuanceResponseDTO)]
pub struct InitiateIssuanceResponseBindingDTO {
    pub url: String,
}
