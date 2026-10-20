use std::collections::HashMap;
use std::sync::Arc;

use one_core::service::ssi_holder::dto::{
    ContinueIssuanceResponseDTO, InitiateIssuanceResponseDTO,
};
use one_dto_mapper::{From, Into, convert_inner, convert_inner_of_inner};
use standardized_types::openid4vci::{AuthorizationDetail, TxCode, TxCodeInputMode};

use super::credential_manager::DcApiResponseHandler;
use super::credential_schema::KeyStorageSecurityBindingEnum;
use super::history::EcosystemOutcomeBindingDTO;
use super::mapper::convert_ecosystem_errors;
use crate::OneCore;
use crate::error::BindingError;
use crate::utils::{into_id, into_id_opt, into_id_opt_vec};

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// For a wallet, handles the interaction once the wallet connects to a share
    /// endpoint URL (for example, scans the QR code of an offered credential or
    /// request for proof).
    ///
    /// Not for use with `ISO_MDL` proximity flows, where the wallet initiates the
    /// flow using `proposeProof` instead.
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
            ecosystem_errors: convert_ecosystem_errors(&response.ecosystem_outcomes),
        })
    }

    /// Rejects credentials or individual batch items. Selecting a batch parent rejects all its items.
    /// Without `credential_ids`, all credentials of the interaction are rejected.
    /// A batch format is notified as rejected and excluded from refreshes only when all its items are rejected.
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

    /// Request a new credential batch.
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

#[derive(Clone, uniffi::Record)]
#[uniffi(name = "HandleInvitationRequest")]
pub struct HandleInvitationRequestBindingDTO {
    pub data: HandleInvitationRequestDataBindingEnum,
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
    /// Use this to enforce the constraints of a regulatory ecosystem
    /// for this interaction. If omitted, every ecosystem available to
    /// the wallet checks the interaction. See
    /// [Enforcing an Ecosystem as a Wallet](https://docs.procivis.ch/hold/ecosystem-enforcement)
    /// for more information.
    pub ecosystem: Option<String>,
}

#[derive(Clone, uniffi::Enum)]
#[uniffi(name = "HandleInvitationRequestData")]
pub enum HandleInvitationRequestDataBindingEnum {
    /// OpenID4VCI, OpenID4VP
    Url {
        /// Typically encoded as a QR code or deep link by the issuer or
        /// verifier. For example: "https://example.com/credential-offer".
        url: String,
    },
    /// ISO 18013-7, Annex C
    Iso18013DcApi {
        /// ISO 18013-7, Annex C.2, `Base64DeviceRequest`
        device_request: String,
        /// ISO 18013-7, Annex C.2, `Base64EncryptionInfo`
        encryption_info: String,
        /// verifier identity (website URL, or android app)
        /// <https://developer.android.com/identity/digital-credentials/credential-holder/credential-holder#check-verifier-origin>
        /// <https://developer.apple.com/documentation/identitydocumentservices/implenting-as-an-identity-document-provider#Create-your-authorization-UI>
        origin: String,
        response_handler: Arc<dyn DcApiResponseHandler>,
    },
    /// OpenID4VP over the Digital Credentials API
    /// <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-openid4vp-over-the-digital->
    OpenID4vpDcApi {
        /// <https://developer.android.com/reference/kotlin/androidx/credentials/GetDigitalCredentialOption#requestJson()>
        request_json: String,
        /// verifier identity (website URL, or android app)
        /// <https://developer.android.com/identity/digital-credentials/credential-holder/credential-holder#check-verifier-origin>
        origin: String,
        response_handler: Arc<dyn DcApiResponseHandler>,
    },
}

#[derive(Clone, Debug, uniffi::Enum)]
#[uniffi(name = "HandleInvitationResponse")]
pub enum HandleInvitationResponseBindingEnum {
    CredentialIssuance {
        /// Use with `holderAcceptCredential` and `holderRejectCredential`.
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
        /// Ecosystem applied to this interaction.
        ecosystem: Option<String>,
        /// One entry per ecosystem provider that rejected the artifact, keyed by provider id.
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
        /// Ecosystem applied to this interaction.
        ecosystem: Option<String>,
        /// One entry per ecosystem provider that rejected the artifact, keyed by provider id.
        ecosystem_errors: HashMap<String, EcosystemOutcomeBindingDTO>,
    },
    ProofRequest {
        /// Use with `holderSubmitProofV2` and `holderRejectProof`.
        interaction_id: String,
        /// ID of the proof request. Use it with `getProof` and
        /// `getPresentationDefinitionV2`.
        proof_id: String,
        /// Protocol used for issuance.
        protocol: String,
        /// Ecosystem applied to this interaction.
        ecosystem: Option<String>,
        /// One entry per ecosystem provider that rejected the artifact, keyed by provider id.
        ecosystem_errors: HashMap<String, EcosystemOutcomeBindingDTO>,
    },
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ContinueIssuanceResponseDTO)]
#[uniffi(name = "ContinueIssuanceResponse")]
pub struct ContinueIssuanceResponseBindingDTO {
    /// Use with `holderAcceptCredential` and `holderRejectCredential`.
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
    /// Ecosystem applied to this interaction.
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
    /// Use this to enforce the constraints of a regulatory ecosystem
    /// for this issuance. See
    /// [Enforcing an Ecosystem as a Wallet](https://docs.procivis.ch/hold/ecosystem-enforcement)
    /// for more information.
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
    /// Pass nothing here for the recommended key auto-generation. See
    /// [Auto-generate Keys for Issuance](https://docs.procivis.ch/configure/auto-generate-keys)
    /// for more information.
    ///
    /// Alternatively, choose an existing identifier to hold the credential.
    /// If neither this nor the deprecated `didId` is set, the system generates
    /// a new identifier that matches the issuer's restrictions.
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
    /// One entry per ecosystem provider that rejected the artifact, keyed by provider id.
    pub ecosystem_errors: HashMap<String, EcosystemOutcomeBindingDTO>,
}
