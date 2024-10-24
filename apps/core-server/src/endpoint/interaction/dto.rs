use std::collections::HashMap;

use one_core::service::proof::dto::ProposeProofResponseDTO;
use one_core::service::ssi_holder::dto::{
    PresentationSubmitCredentialRequestDTO, PresentationSubmitRequestDTO,
};
use one_dto_mapper::{convert_inner, From, Into};
use serde::{Deserialize, Serialize};
use shared_types::{CredentialId, DidId, KeyId, OrganisationId, ProofId};
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HandleInvitationRequestRestDTO {
    /// Typically encoded as a QR code or deep link by the issuer or verifier.
    pub url: Url,
    pub organisation_id: OrganisationId,
    pub transport: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HandleInvitationResponseRestDTO {
    pub interaction_id: Uuid,

    pub credential_ids: Option<Vec<CredentialId>>,
    pub proof_id: Option<ProofId>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssuanceAcceptRequestRestDTO {
    /// The identifier associated with the particular issuance.
    pub interaction_id: Uuid,
    pub did_id: DidId,
    /// If the associated DID supports multiple keys for authentication,
    /// specify which key to use. If no key is specified the first suitable key listed
    /// will be used.
    pub key_id: Option<KeyId>,
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

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(PresentationSubmitRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct PresentationSubmitRequestRestDTO {
    pub interaction_id: Uuid,
    #[into(with_fn = convert_inner)]
    pub submit_credentials: HashMap<String, PresentationSubmitCredentialRequestRestDTO>,
    pub did_id: DidId,
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
    pub exchange: String,
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
