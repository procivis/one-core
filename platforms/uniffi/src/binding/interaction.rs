use one_core::provider::issuance_protocol::model::{OpenID4VCITxCode, OpenID4VCITxCodeInputMode};
use one_core::service::error::ServiceError;
use one_core::service::ssi_holder::dto::{
    ContinueIssuanceResponseDTO, InitiateIssuanceAuthorizationDetailDTO,
    InitiateIssuanceResponseDTO,
};
use one_dto_mapper::{From, Into, convert_inner_of_inner};
use url::Url;

use super::credential_schema::KeyStorageSecurityBindingEnum;
use crate::OneCore;
use crate::error::BindingError;
use crate::utils::{into_id, into_id_opt};

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
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

    /// Accepts an offered credential. The system will generate a new
    /// identifier that matches issuer's restrictions. Alternatively,
    /// you can specify an existing identifier.
    #[uniffi::method]
    pub async fn holder_accept_credential(
        &self,
        request: HolderAcceptCredentialRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .ssi_holder_service
            .accept_credential(
                into_id(request.interaction_id)?,
                into_id_opt(request.did_id)?,
                into_id_opt(request.identifier_id)?,
                into_id_opt(request.key_id)?,
                request.tx_code,
                into_id_opt(request.holder_wallet_unit_id)?,
            )
            .await?
            .to_string())
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
#[uniffi(name = "HandleInvitationRequest")]
pub struct HandleInvitationRequestBindingDTO {
    /// Typically encoded as a QR code or deep link by the issuer or
    /// verifier. For example: "https://example.com/credential-offer".
    pub url: String,
    /// Specifies the organizational context for this operation.
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
#[uniffi(name = "HandleInvitationResponse")]
pub enum HandleInvitationResponseBindingEnum {
    CredentialIssuance {
        /// For reference.
        interaction_id: String,
        /// Key storage required to complete issuance.
        key_storage_security_levels: Option<Vec<KeyStorageSecurityBindingEnum>>,
        /// Key algorithms suitable for issuance.
        key_algorithms: Option<Vec<String>>,
        /// Metadata for entering a transaction code
        /// If a pre-authorized code is issued with a transaction code object, the
        /// wallet user must input a transaction code to receive the offered credential.
        /// This code is typically sent through a separate channel such as SMS or email.
        tx_code: Option<OpenID4VCITxCodeBindingDTO>,
        /// Protocol used for issuance.
        protocol: String,
        /// Whether a valid WIA is required to complete issuance.
        requires_wallet_instance_attestation: bool,
    },
    AuthorizationCodeFlow {
        /// For reference.
        interaction_id: String,
        /// For issuer-initiated Authorization Code Flows, use this URL to start
        /// the authorization process with the authorization server.
        authorization_code_flow_url: String,
        /// Protocol used for issuance.
        protocol: String,
    },
    ProofRequest {
        /// For reference.
        interaction_id: String,
        /// Proof request.
        proof_id: String,
        /// Protocol used for issuance.
        protocol: String,
    },
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ContinueIssuanceResponseDTO)]
#[uniffi(name = "ContinueIssuanceResponse")]
pub struct ContinueIssuanceResponseBindingDTO {
    /// For reference.
    #[from(with_fn_ref = "ToString::to_string")]
    pub interaction_id: String,
    /// Key storage required to complete issuance.
    #[from(with_fn = convert_inner_of_inner )]
    pub key_storage_security_levels: Option<Vec<KeyStorageSecurityBindingEnum>>,
    /// Key algorithms suitable for issuance.
    pub key_algorithms: Option<Vec<String>>,
    /// Whether a valid WIA is required to complete issuance.
    pub requires_wallet_instance_attestation: bool,
    /// Protocol used for issuance.
    pub protocol: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(OpenID4VCITxCode)]
#[uniffi(name = "OpenID4VCITxCode")]
pub struct OpenID4VCITxCodeBindingDTO {
    /// For validation.
    pub input_mode: OpenID4VCITxCodeInputModeBindingEnum,
    /// Character length of code, to assist the user.
    pub length: Option<i64>,
    /// Guidance text displayed in the wallet, describing how to
    /// obtain the transaction code.
    pub description: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(OpenID4VCITxCodeInputMode)]
#[uniffi(name = "OpenID4VCITxCodeInputMode")]
pub enum OpenID4VCITxCodeInputModeBindingEnum {
    Numeric,
    Text,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "InitiateIssuanceRequest")]
pub struct InitiateIssuanceRequestBindingDTO {
    /// Specifies the organizational context for this operation.
    pub organisation_id: String,
    /// Choose a protocol to complete issuance.
    pub protocol: String,
    /// OpenID4VCI authorization request parameter.
    pub issuer: String,
    /// OpenID4VCI authorization request parameter.
    pub client_id: String,
    /// OpenID4VCI authorization request parameter.
    pub redirect_uri: Option<String>,
    /// OpenID4VCI authorization request parameter.
    pub scope: Option<Vec<String>>,
    /// OpenID4VCI authorization request parameter.
    pub authorization_details: Option<Vec<InitiateIssuanceAuthorizationDetailBindingDTO>>,
}

#[derive(Clone, Debug, uniffi::Record, Into)]
#[into(InitiateIssuanceAuthorizationDetailDTO)]
#[uniffi(name = "InitiateIssuanceAuthorizationDetail")]
pub struct InitiateIssuanceAuthorizationDetailBindingDTO {
    pub r#type: String,
    pub credential_configuration_id: String,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[from(InitiateIssuanceResponseDTO)]
#[uniffi(name = "InitiateIssuanceResponse")]
pub struct InitiateIssuanceResponseBindingDTO {
    pub url: String,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "HolderAcceptCredentialRequest")]
pub struct HolderAcceptCredentialRequestBindingDTO {
    /// ID for this issuance.
    pub interaction_id: String,
    /// Deprecated. Use `identifierId`.
    pub did_id: Option<String>,
    pub identifier_id: Option<String>,
    /// If you are using an identifier with multiple keys for authentication,
    /// specify which key to use. If no key is specified, the first suitable
    /// key listed will be used.
    pub key_id: Option<String>,
    /// User-provided transaction code.
    pub tx_code: Option<String>,
    pub holder_wallet_unit_id: Option<String>,
}
