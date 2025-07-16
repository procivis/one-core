use std::collections::HashMap;

use one_core::provider::issuance_protocol::openid4vci_draft13::model::{
    OpenID4VCIProofTypeSupported, OpenID4VCITxCode, OpenID4VCITxCodeInputMode,
};
use one_core::service::proof::dto::ProposeProofResponseDTO;
use one_core::service::ssi_holder::dto::{
    CredentialConfigurationSupportedResponseDTO, PresentationSubmitCredentialRequestDTO,
    PresentationSubmitRequestDTO,
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
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HandleInvitationRequestRestDTO {
    /// Typically encoded as a QR code or deep link by the issuer or verifier.
    pub url: Url,
    pub organisation_id: OrganisationId,
    pub transport: Option<Vec<String>>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HandleInvitationResponseRestDTO {
    pub interaction_id: Uuid,
    pub credential_ids: Option<Vec<CredentialId>>,
    pub proof_id: Option<ProofId>,
    /// If a pre-authorized code is issued with a transaction code object, the
    /// wallet user must input a transaction code to receive the offered credential.
    /// This code is typically sent through a separate channel such as SMS or email.
    pub tx_code: Option<OpenID4VCITxCodeRestDTO>,
    #[schema(value_type = Object)]
    pub credential_configurations_supported:
        Option<HashMap<CredentialId, CredentialConfigurationSupportedResponseRestDTO>>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(CredentialConfigurationSupportedResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct CredentialConfigurationSupportedResponseRestDTO {
    #[schema(value_type = Object)]
    #[from(with_fn = convert_inner_of_inner)]
    pub proof_types_supported: Option<HashMap<String, ProofTypeSupported>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, From)]
#[from(OpenID4VCIProofTypeSupported)]
#[serde(rename_all = "camelCase")]
pub struct ProofTypeSupported {
    pub proof_signing_alg_values_supported: Vec<String>,
}

#[options_not_nullable]
#[derive(Clone, Serialize, Deserialize, Debug, From, ToSchema)]
#[from(OpenID4VCITxCode)]
pub struct OpenID4VCITxCodeRestDTO {
    #[schema(value_type = String, example = "numeric", default = "numeric")]
    #[serde(default)]
    /// Type of code expected.
    pub input_mode: OpenID4VCITxCodeInputModeRestDTO,
    #[from(with_fn = convert_inner)]
    #[serde(default)]
    /// Length of transaction code, to pass to the frontend for guiding the
    /// wallet holder.
    pub length: Option<i64>,
    #[from(with_fn = convert_inner)]
    #[schema(value_type = String, example = "Pin number", max_length = 300)]
    #[serde(default)]
    /// Information about the transaction code, to pass to the frontend for
    /// guiding the wallet holder.
    pub description: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Display, From, Default)]
#[from(OpenID4VCITxCodeInputMode)]
pub enum OpenID4VCITxCodeInputModeRestDTO {
    #[serde(rename = "numeric")]
    #[strum(serialize = "numeric")]
    #[default]
    Numeric,
    #[serde(rename = "text")]
    #[strum(serialize = "text")]
    Text,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssuanceAcceptRequestRestDTO {
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

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssuanceRejectRequestRestDTO {
    pub interaction_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PresentationRejectRequestRestDTO {
    /// The identifier associated with a particular verification interaction.
    pub interaction_id: Uuid,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(PresentationSubmitRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct PresentationSubmitRequestRestDTO {
    pub interaction_id: Uuid,
    #[into(with_fn = convert_inner)]
    pub submit_credentials: HashMap<String, PresentationSubmitCredentialRequestRestDTO>,
    pub did_id: Option<DidId>,
    pub identifier_id: Option<IdentifierId>,
    /// If the associated DID supports multiple keys for authentication,
    /// specify which key to use. If no key is specified the first suitable key listed
    /// will be used.
    pub key_id: Option<KeyId>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(PresentationSubmitCredentialRequestDTO)]
pub struct PresentationSubmitCredentialRequestRestDTO {
    /// Select a credential.
    pub credential_id: Uuid,
    /// claimSchemaId of the claim to send from this credential.
    pub submit_claims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProposeProofRequestRestDTO {
    pub protocol: String,
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProposeProofResponseDTO)]
pub struct ProposeProofResponseRestDTO {
    pub proof_id: ProofId,
    pub interaction_id: Uuid,
    pub url: String,
}
