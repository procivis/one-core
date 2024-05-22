use dto_mapper::{From, Into};
use one_core::{
    model::trust_entity::TrustEntityRole, service::trust_entity::dto::CreateTrustEntityRequestDTO,
};
use serde::{Deserialize, Serialize};
use shared_types::TrustAnchorId;
use utoipa::ToSchema;

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(CreateTrustEntityRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct CreateTrustEntityRequestRestDTO {
    entity_id: String,
    name: String,
    logo: Option<String>,
    website: Option<String>,
    terms_url: Option<String>,
    privacy_url: Option<String>,
    role: TrustEntityRoleRest,
    trust_anchor_id: TrustAnchorId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From, Into)]
#[from(TrustEntityRole)]
#[into(TrustEntityRole)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustEntityRoleRest {
    Issuer,
    Verifier,
    Both,
}
