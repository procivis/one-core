use dto_mapper::Into;
use one_core::{
    model::trust_anchor::TrustAnchorRole, service::trust_anchor::dto::CreateTrustAnchorRequestDTO,
};
use serde::{Deserialize, Serialize};
use shared_types::OrganisationId;
use utoipa::ToSchema;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(CreateTrustAnchorRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct CreateTrustAnchorRequestRestDTO {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub publisher_reference: String,
    pub role: TrustAnchorRoleRest,
    pub priority: u32,
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into)]
#[into(TrustAnchorRole)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustAnchorRoleRest {
    Publisher,
    Client,
}
