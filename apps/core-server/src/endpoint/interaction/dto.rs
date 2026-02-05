use std::collections::HashMap;

use one_core::model::interaction::InteractionType;
use one_core::provider::issuance_protocol::model::{
    OpenID4VCIProofTypeSupported, OpenID4VCITxCode, OpenID4VCITxCodeInputMode,
};
use one_core::service::error::ServiceError;
use one_core::service::proof::dto::{ProposeProofRequestDTO, ProposeProofResponseDTO};
use one_core::service::ssi_holder::dto::{
    ContinueIssuanceResponseDTO, CredentialConfigurationSupportedResponseDTO,
    InitiateIssuanceAuthorizationDetailDTO, InitiateIssuanceResponseDTO,
    PresentationSubmitCredentialRequestDTO, PresentationSubmitRequestDTO,
    PresentationSubmitV2CredentialRequestDTO, PresentationSubmitV2RequestDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner_of_inner};
use proc_macros::{ModifySchema, options_not_nullable};
use serde::{Deserialize, Serialize};
use shared_types::{
    CredentialId, DidId, HolderWalletUnitId, IdentifierId, InteractionId, KeyId, OrganisationId,
    ProofId,
};
use strum::Display;
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::credential_schema::dto::KeyStorageSecurityRestEnum;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, ModifySchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HandleInvitationRequestRestDTO {
    #[schema(example = "https://example.com/credential-offer")]
    /// Typically encoded as a QR code or deep link by the issuer or verifier.
    pub url: Url,
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    pub organisation_id: Option<OrganisationId>,
    #[schema(example = json!(["HTTP"]))]
    /// For configurations with multiple transport protocols enabled you can
    /// specify which one to use for this interaction.
    #[modify_schema(field = transport)]
    #[schema(nullable = false)]
    pub transport: Option<Vec<String>>,
    /// For issuer-initiated Authorization Code Flow, provide the authorization server
    /// with the URI it should return the user to once authorization is complete.
    pub redirect_uri: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HandleInvitationResponseRestDTO {
    pub interaction_id: InteractionId,
    pub interaction_type: InteractionTypeRestEnum,
    /// Requested proof.
    pub proof_id: Option<ProofId>,
    /// Metadata for entering a transaction code.
    /// If a pre-authorized code is issued with a transaction code object, the
    /// wallet user must input a transaction code to receive the offered credential.
    /// This code is typically sent through a separate channel such as SMS or email.
    pub tx_code: Option<OpenID4VCITxCodeRestDTO>,
    /// For issuer-initiated Authorization Code Flows, use this URL to start the
    /// authorization process with the authorization server.
    pub authorization_code_flow_url: Option<String>,
    pub key_storage_security_levels: Option<Vec<KeyStorageSecurityRestEnum>>,
    pub key_algorithms: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(InteractionType)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum InteractionTypeRestEnum {
    Issuance,
    Verification,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(ContinueIssuanceResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ContinueIssuanceResponseRestDTO {
    /// For reference.
    pub interaction_id: InteractionId,
    pub interaction_type: InteractionTypeRestEnum,
    #[from(with_fn = convert_inner_of_inner)]
    pub key_storage_security_levels: Option<Vec<KeyStorageSecurityRestEnum>>,
    pub key_algorithms: Option<Vec<String>>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(CredentialConfigurationSupportedResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialConfigurationSupportedResponseRestDTO {
    #[from(with_fn = convert_inner_of_inner)]
    pub proof_types_supported: Option<HashMap<String, ProofTypeSupported>>,
}

#[derive(Clone, Debug, Serialize, ToSchema, Default, From)]
#[from(OpenID4VCIProofTypeSupported)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProofTypeSupported {
    pub proof_signing_alg_values_supported: Vec<String>,
}

#[options_not_nullable]
#[derive(Clone, Serialize, Debug, From, ToSchema)]
#[from(OpenID4VCITxCode)]
pub(crate) struct OpenID4VCITxCodeRestDTO {
    #[schema(value_type = String, example = "numeric", default = "numeric")]
    #[serde(default)] // we always provide it, but it is optional according to OpenID4VCI standard
    /// Type of code expected.
    pub input_mode: OpenID4VCITxCodeInputModeRestDTO,
    /// Length of transaction code, to pass to the frontend for guiding the
    /// wallet holder.
    pub length: Option<i64>,
    #[schema(value_type = String, example = "Pin number", max_length = 300)]
    /// Information about the transaction code, to pass to the frontend for
    /// guiding the wallet holder.
    pub description: Option<String>,
}

#[derive(Clone, Serialize, Debug, PartialEq, Display, From, Default)]
#[from(OpenID4VCITxCodeInputMode)]
pub(crate) enum OpenID4VCITxCodeInputModeRestDTO {
    #[serde(rename = "numeric")]
    #[strum(serialize = "numeric")]
    #[default]
    Numeric,
    #[serde(rename = "text")]
    #[strum(serialize = "text")]
    Text,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IssuanceAcceptRequestRestDTO {
    /// The identifier associated with the particular issuance.
    pub interaction_id: InteractionId,
    pub did_id: Option<DidId>,
    pub identifier_id: Option<IdentifierId>,
    /// If you are using a DID and it supports multiple keys for authentication,
    /// specify which key to use. If no key is specified the first suitable key listed
    /// will be used.
    pub key_id: Option<KeyId>,
    pub tx_code: Option<String>,
    pub holder_wallet_unit_id: Option<HolderWalletUnitId>,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IssuanceRejectRequestRestDTO {
    pub interaction_id: InteractionId,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PresentationRejectRequestRestDTO {
    /// The identifier associated with a particular verification interaction.
    pub interaction_id: InteractionId,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum SingleOrArray<T> {
    Single(T),
    Array(Vec<T>),
}

impl<T> From<SingleOrArray<T>> for Vec<T> {
    fn from(value: SingleOrArray<T>) -> Self {
        match value {
            SingleOrArray::Single(v) => vec![v],
            SingleOrArray::Array(v) => v,
        }
    }
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(PresentationSubmitRequestDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PresentationSubmitRequestRestDTO {
    pub interaction_id: InteractionId,
    #[into(with_fn = convert_inner_of_inner)]
    #[serde(deserialize_with = "deserialize_submit_credentials")]
    pub submit_credentials: HashMap<String, Vec<PresentationSubmitCredentialRequestRestDTO>>,
}

fn deserialize_submit_credentials<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, Vec<PresentationSubmitCredentialRequestRestDTO>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let map =
        HashMap::<String, SingleOrArray<PresentationSubmitCredentialRequestRestDTO>>::deserialize(
            deserializer,
        )?;
    Ok(map.into_iter().map(|(k, v)| (k, v.into())).collect())
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(PresentationSubmitCredentialRequestDTO)]
pub(crate) struct PresentationSubmitCredentialRequestRestDTO {
    /// Select a credential.
    pub credential_id: Uuid,
    /// claimSchemaId of the claim to send from this credential.
    pub submit_claims: Vec<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(PresentationSubmitV2RequestDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PresentationSubmitV2RequestRestDTO {
    pub interaction_id: InteractionId,
    #[into(with_fn = convert_inner_of_inner)]
    #[serde(deserialize_with = "deserialize_credential_submission")]
    pub submission: HashMap<String, Vec<PresentationSubmitV2CredentialRequestRestDTO>>,
}

fn deserialize_credential_submission<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, Vec<PresentationSubmitV2CredentialRequestRestDTO>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let map =
        HashMap::<String, SingleOrArray<PresentationSubmitV2CredentialRequestRestDTO>>::deserialize(
            deserializer,
        )?;
    Ok(map.into_iter().map(|(k, v)| (k, v.into())).collect())
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(PresentationSubmitV2CredentialRequestDTO)]
pub(crate) struct PresentationSubmitV2CredentialRequestRestDTO {
    /// Submitted credential.
    pub credential_id: CredentialId,
    /// Path of claims that were optionally selected by the user.
    #[serde(default)]
    pub user_selections: Vec<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T = ProposeProofRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProposeProofRequestRestDTO {
    #[try_into(infallible)]
    pub protocol: String,
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    #[try_into(infallible)]
    pub engagement: Vec<String>,
    #[try_into(infallible)]
    pub ui_message: Option<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProposeProofResponseDTO)]
pub(crate) struct ProposeProofResponseRestDTO {
    pub proof_id: ProofId,
    pub interaction_id: InteractionId,
    pub url: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InitiateIssuanceRequestRestDTO {
    /// Organization to place the issued credential into.
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    pub organisation_id: Option<OrganisationId>,
    /// Selected issuance protocol.
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
    pub authorization_details: Option<Vec<InitiateIssuanceAuthorizationDetailRestDTO>>,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(InitiateIssuanceAuthorizationDetailDTO)]
#[serde(rename_all = "camelCase")]
// > Additional authorization_details data fields MAY be defined and used
// > when the type value is openid_credential. Note that this effectively
// > defines an authorization details type that is never considered invalid
// > due to unknown fields.
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.1-4
pub(crate) struct InitiateIssuanceAuthorizationDetailRestDTO {
    pub r#type: String,
    pub credential_configuration_id: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(InitiateIssuanceResponseDTO)]
pub(crate) struct InitiateIssuanceResponseRestDTO {
    /// Authorization endpoint URL
    pub url: String,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ContinueIssuanceRequestRestDTO {
    #[schema(example = "myapp://example/credential-offer?code=xxx&clientId=myWallet&...")]
    /// Starts with the `redirectUri` and is used to continue the
    /// Authorization Code Flow issuance process.
    pub url: String,
}
