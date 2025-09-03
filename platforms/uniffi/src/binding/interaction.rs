use std::collections::HashMap;

use one_core::provider::issuance_protocol::openid4vci_draft13::model::{
    OpenID4VCIProofTypeSupported, OpenID4VCITxCode, OpenID4VCITxCodeInputMode,
};
use one_core::service::error::ServiceError;
use one_core::service::ssi_holder::dto::{
    ContinueIssuanceResponseDTO, CredentialConfigurationSupportedResponseDTO,
    InitiateIssuanceAuthorizationDetailDTO, InitiateIssuanceResponseDTO,
};
use one_dto_mapper::{From, Into};
use url::Url;

use crate::OneCoreBinding;
use crate::error::BindingError;
use crate::utils::into_id;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    /// For a wallet, handles the interaction once the wallet connects to a share
    /// endpoint URL (for example, scans the QR code of an offered credential or
    /// request for proof).
    #[uniffi::method]
    pub async fn handle_invitation(
        &self,
        request: HandleInvitationRequestBindingDTO,
    ) -> Result<HandleInvitationResponseBindingEnum, BindingError> {
        let url =
            Url::parse(&request.url).map_err(|e| ServiceError::ValidationError(e.to_string()))?;

        let organisation_id = into_id(&request.organisation_id)?;

        let core = self.use_core().await?;
        let invitation_response = core
            .ssi_holder_service
            .handle_invitation(
                url,
                organisation_id,
                request.transport,
                request.redirect_uri,
            )
            .await?;

        Ok(invitation_response.into())
    }

    /// Accepts an offered credential. The chosen identifier will be listed as
    /// the subject of the issued credential.
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

    /// Rejects an offered credential.
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

    /// For wallets, starts the OpenID4VCI Authorization Code Flow.
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

    /// For wallet-initiated flows, continues the OpenID4VCI issuance
    /// process after completing authorization.
    ///
    /// * url - Starts with the `redirectUri` and is used to continue the
    ///   Authorization Code Flow issuance process. For example:
    ///   `myapp://example/credential-offer?code=xxx&clientId=myWallet&...`
    #[uniffi::method]
    pub async fn continue_issuance(
        &self,
        url: String,
    ) -> Result<ContinueIssuanceResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core.ssi_holder_service.continue_issuance(url).await?.into())
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct HandleInvitationRequestBindingDTO {
    /// Typically encoded as a QR code or deep link by the issuer or
    /// verifier. For example: "https://example.com/credential-offer".
    pub url: String,
    pub organisation_id: String,
    /// For configurations with multiple transport protocols enabled you
    /// can specify which one to use for this interaction. For example:
    /// "HTTP".
    pub transport: Option<Vec<String>>,
    /// For issuer-initiated Authorization Code Flows, provide the
    /// authorization server with the URI it should return the user
    /// to once authorization is complete. For example:
    /// "myapp://example".
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum HandleInvitationResponseBindingEnum {
    CredentialIssuance {
        /// For reference.
        interaction_id: String,
        /// Offered credential.
        credential_ids: Vec<String>,
        /// Metadata for entering a transaction code
        /// If a pre-authorized code is issued with a transaction code object, the
        /// wallet user must input a transaction code to receive the offered credential.
        /// This code is typically sent through a separate channel such as SMS or email.
        tx_code: Option<OpenID4VCITxCodeBindingDTO>,
        /// Metadata for selecting an appropriate key.
        credential_configurations_supported:
            HashMap<String, CredentialConfigurationSupportedResponseBindingDTO>,
    },
    AuthorizationCodeFlow {
        /// For reference.
        interaction_id: String,
        /// For issuer-initiated Authorization Code Flows, use this URL to start
        /// the authorization process with the authorization server.
        authorization_code_flow_url: String,
    },
    ProofRequest {
        /// For reference.
        interaction_id: String,
        /// Proof request.
        proof_id: String,
    },
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ContinueIssuanceResponseBindingDTO {
    /// For reference.
    pub interaction_id: String,
    /// Offered credential.
    pub credential_ids: Vec<String>,
    /// Metadata for selecting an appropriate key.
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
    pub length: Option<i64>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(OpenID4VCITxCodeInputMode)]
pub enum OpenID4VCITxCodeInputModeBindingEnum {
    Numeric,
    Text,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct InitiateIssuanceRequestBindingDTO {
    pub organisation_id: String,
    pub protocol: String,
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<Vec<String>>,
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
