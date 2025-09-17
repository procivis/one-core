use std::collections::HashMap;

use one_core::provider::issuance_protocol::model::{
    OpenID4VCIProofTypeSupported, OpenID4VCITxCode, OpenID4VCITxCodeInputMode,
};
use one_core::service::proof::dto::ProposeProofResponseDTO;
use one_core::service::ssi_holder::dto::{
    ContinueIssuanceResponseDTO, CredentialConfigurationSupportedResponseDTO,
    InitiateIssuanceAuthorizationDetailDTO, InitiateIssuanceResponseDTO,
    PresentationSubmitCredentialRequestDTO, PresentationSubmitRequestDTO,
};
use one_dto_mapper::{From, Into, convert_inner, convert_inner_of_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{CredentialId, DidId, IdentifierId, KeyId, OrganisationId, ProofId};
use strum::Display;
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HandleInvitationRequestRestDTO {
    #[schema(example = "https://example.com/credential-offer")]
    /// Typically encoded as a QR code or deep link by the issuer or verifier.
    pub url: Url,
    pub organisation_id: OrganisationId,
    #[schema(example = json!(["HTTP"]))]
    /// For configurations with multiple transport protocols enabled you can
    /// specify which one to use for this interaction.
    pub transport: Option<Vec<String>>,
    /// For issuer-initiated Authorization Code Flow, provide the authorization server
    /// with the URI it should return the user to once authorization is complete.
    pub redirect_uri: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HandleInvitationResponseRestDTO {
    pub interaction_id: Uuid,
    /// Offered credential.
    pub credential_ids: Option<Vec<CredentialId>>,
    /// Requested proof.
    pub proof_id: Option<ProofId>,
    /// Metadata for entering a transaction code.
    /// If a pre-authorized code is issued with a transaction code object, the
    /// wallet user must input a transaction code to receive the offered credential.
    /// This code is typically sent through a separate channel such as SMS or email.
    pub tx_code: Option<OpenID4VCITxCodeRestDTO>,
    /// Metadata for selecting an appropriate key.
    pub credential_configurations_supported:
        Option<HashMap<CredentialId, CredentialConfigurationSupportedResponseRestDTO>>,
    /// For issuer-initiated Authorization Code Flows, use this URL to start the
    /// authorization process with the authorization server.
    pub authorization_code_flow_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(ContinueIssuanceResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ContinueIssuanceResponseRestDTO {
    /// For reference.
    pub interaction_id: Uuid,
    /// Offered credential.
    pub credential_ids: Vec<CredentialId>,
    #[from(with_fn = convert_inner)]
    /// Metadata for selecting an appropriate key.
    pub credential_configurations_supported:
        HashMap<CredentialId, CredentialConfigurationSupportedResponseRestDTO>,
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
#[serde(rename_all = "camelCase")]
pub(crate) struct IssuanceAcceptRequestRestDTO {
    /// The identifier associated with the particular issuance.
    pub interaction_id: Uuid,
    pub did_id: Option<DidId>,
    pub identifier_id: Option<IdentifierId>,
    /// If you are using a DID and it supports multiple keys for authentication,
    /// specify which key to use. If no key is specified the first suitable key listed
    /// will be used.
    pub key_id: Option<KeyId>,
    pub tx_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IssuanceRejectRequestRestDTO {
    pub interaction_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PresentationRejectRequestRestDTO {
    /// The identifier associated with a particular verification interaction.
    pub interaction_id: Uuid,
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
#[serde(rename_all = "camelCase")]
pub(crate) struct PresentationSubmitRequestRestDTO {
    pub interaction_id: Uuid,
    #[into(with_fn = convert_inner_of_inner)]
    #[serde(deserialize_with = "deserialize_submit_credentials")]
    pub submit_credentials: HashMap<String, Vec<PresentationSubmitCredentialRequestRestDTO>>,
    pub did_id: Option<DidId>,
    pub identifier_id: Option<IdentifierId>,
    /// If the associated DID supports multiple keys for authentication,
    /// specify which key to use. If no key is specified the first suitable key listed
    /// will be used.
    pub key_id: Option<KeyId>,
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
#[serde(rename_all = "camelCase")]
#[into(PresentationSubmitCredentialRequestDTO)]
pub(crate) struct PresentationSubmitCredentialRequestRestDTO {
    /// Select a credential.
    pub credential_id: Uuid,
    /// claimSchemaId of the claim to send from this credential.
    pub submit_claims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProposeProofRequestRestDTO {
    pub protocol: String,
    pub organisation_id: OrganisationId,
    pub engagement: Vec<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProposeProofResponseDTO)]
pub(crate) struct ProposeProofResponseRestDTO {
    pub proof_id: ProofId,
    pub interaction_id: Uuid,
    pub url: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InitiateIssuanceRequestRestDTO {
    /// Organization to place the issued credential into.
    pub organisation_id: OrganisationId,
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
#[serde(rename_all = "camelCase")]
pub(crate) struct ContinueIssuanceRequestRestDTO {
    #[schema(example = "myapp://example/credential-offer?code=xxx&clientId=myWallet&...")]
    /// Starts with the `redirectUri` and is used to continue the
    /// Authorization Code Flow issuance process.
    pub url: String,
}
