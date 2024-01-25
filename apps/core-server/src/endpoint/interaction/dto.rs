use dto_mapper::convert_inner;
use dto_mapper::Into;
use one_core::service::ssi_holder::dto::{
    PresentationSubmitCredentialRequestDTO, PresentationSubmitRequestDTO,
};
use serde::{Deserialize, Serialize};
use shared_types::DidId;
use std::collections::HashMap;
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HandleInvitationRequestRestDTO {
    pub url: Url,
    pub did_id: DidId,
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
pub struct IssuanceAcceptRequestRestDTO {
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

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(PresentationSubmitRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct PresentationSubmitRequestRestDTO {
    pub interaction_id: Uuid,
    #[into(with_fn = convert_inner)]
    pub submit_credentials: HashMap<String, PresentationSubmitCredentialRequestRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(PresentationSubmitCredentialRequestDTO)]
pub struct PresentationSubmitCredentialRequestRestDTO {
    pub credential_id: Uuid,
    pub submit_claims: Vec<String>,
}
