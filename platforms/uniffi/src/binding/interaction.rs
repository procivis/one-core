use std::collections::HashMap;

use one_core::service::ssi_holder::dto::{
    ContinueIssuanceResponseDTO, InitiateIssuanceResponseDTO,
};
use one_dto_mapper::{From, Into, convert_inner, convert_inner_of_inner};
use standardized_types::openid4vci::{AuthorizationDetail, TxCode, TxCodeInputMode};

use super::credential_schema::KeyStorageSecurityBindingEnum;
use super::history::EcosystemOutcomeBindingDTO;
use super::mapper::convert_ecosystem_outcomes;
use crate::OneCore;
use crate::error::BindingError;
use crate::utils::{into_id, into_id_opt, into_id_opt_vec};

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
        let core = self.use_core().await?;
        let invitation_response = core
            .ssi_holder_service
            .handle_invitation(request.try_into()?)
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
    ) -> Result<HolderAcceptCredentialResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let response = core
            .ssi_holder_service
            .accept_credential(
                into_id(request.interaction_id)?,
                into_id_opt(request.did_id)?,
                into_id_opt(request.identifier_id)?,
                into_id_opt(request.key_id)?,
                request.tx_code,
            )
            .await?;
        Ok(HolderAcceptCredentialResponseBindingDTO {
            credential_ids: response
                .credential_ids
                .iter()
                .map(ToString::to_string)
                .collect(),
            partially_successful: response.partially_successful,
            ecosystem_errors: convert_ecosystem_outcomes(&response.ecosystem_errors),
        })
    }

    /// Rejects offered credentials. Without `credential_ids`, all credentials of the interaction are rejected.
    #[uniffi::method]
    pub async fn holder_reject_credential(
        &self,
        interaction_id: String,
        credential_ids: Option<Vec<String>>,
    ) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .ssi_holder_service
            .reject_credential(
                &into_id(&interaction_id)?,
                into_id_opt_vec(&credential_ids)?,
            )
            .await?)
    }

    /// Receive a new credential batch
    #[uniffi::method]
    pub async fn holder_refresh_credential(
        &self,
        interaction_id: String,
    ) -> Result<HolderRefreshCredentialResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let ids = core
            .ssi_holder_service
            .refresh_credentials(into_id(interaction_id)?)
            .await?;
        Ok(HolderRefreshCredentialResponseBindingDTO {
            credential_ids: ids.iter().map(ToString::to_string).collect(),
        })
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
    pub ecosystem: Option<String>,
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
        ecosystem: Option<String>,
        /// One entry per ecosystem provider consulted, keyed by provider id.
        ecosystem_errors: HashMap<String, EcosystemOutcomeBindingDTO>,
    },
    AuthorizationCodeFlow {
        /// For reference.
        interaction_id: String,
        /// For issuer-initiated Authorization Code Flows, use this URL to start
        /// the authorization process with the authorization server.
        authorization_code_flow_url: String,
        /// Protocol used for issuance.
        protocol: String,
        ecosystem: Option<String>,
        /// One entry per ecosystem provider consulted, keyed by provider id.
        ecosystem_errors: HashMap<String, EcosystemOutcomeBindingDTO>,
    },
    ProofRequest {
        /// For reference.
        interaction_id: String,
        /// Proof request.
        proof_id: String,
        /// Protocol used for issuance.
        protocol: String,
        ecosystem: Option<String>,
        /// One entry per ecosystem provider consulted, keyed by provider id.
        ecosystem_errors: HashMap<String, EcosystemOutcomeBindingDTO>,
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
    #[from(with_fn = convert_inner )]
    pub ecosystem: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(TxCode)]
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
#[from(TxCodeInputMode)]
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
    pub ecosystem: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record, Into)]
#[into(AuthorizationDetail)]
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
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "HolderRefreshCredentialResponse")]
pub struct HolderRefreshCredentialResponseBindingDTO {
    pub credential_ids: Vec<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "HolderAcceptCredentialResponse")]
pub struct HolderAcceptCredentialResponseBindingDTO {
    /// One credential per accepted credential configuration.
    pub credential_ids: Vec<String>,
    /// Some of the offered credential configurations could not be issued.
    /// Only set when several configurations were offered.
    pub partially_successful: Option<bool>,
    /// One entry per ecosystem provider consulted, keyed by provider id.
    pub ecosystem_errors: HashMap<String, EcosystemOutcomeBindingDTO>,
}
