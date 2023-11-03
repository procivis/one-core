use one_core::service::ssi_holder::dto::PresentationSubmitCredentialRequestDTO;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HandleInvitationRequestRestDTO {
    pub url: Url,
    pub did_id: Uuid,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HandleInvitationResponseRestDTO {
    pub interaction_id: Uuid,

    pub credential_ids: Option<Vec<Uuid>>,
    pub proof_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssuanceSubmitRequestRestDTO {
    pub interaction_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssuanceRejectRequestRestDTO {
    pub interaction_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PresentationRejectRequestRestDTO {
    pub interaction_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PresentationSubmitRequestRestDTO {
    pub interaction_id: Uuid,
    pub submit_credentials: HashMap<String, PresentationSubmitCredentialRequestRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, dto_mapper::From)]
#[serde(rename_all = "camelCase")]
#[convert(into = "PresentationSubmitCredentialRequestDTO")]
pub struct PresentationSubmitCredentialRequestRestDTO {
    pub credential_id: Uuid,
    pub submit_claims: Vec<String>,
}
