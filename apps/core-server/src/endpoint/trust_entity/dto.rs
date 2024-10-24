use one_core::model::trust_entity::TrustEntityRole;
use one_core::service::trust_entity::dto::{
    CreateTrustEntityRequestDTO, GetTrustEntityResponseDTO, SortableTrustEntityColumnEnum,
    TrustEntitiesResponseItemDTO,
};
use one_dto_mapper::{convert_inner, From, Into};
use serde::{Deserialize, Serialize};
use shared_types::{OrganisationId, TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::dto::common::{ExactColumn, ListQueryParamsRest};
use crate::endpoint::trust_anchor::dto::GetTrustAnchorDetailResponseRestDTO;
use crate::serialize::front_time;

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(CreateTrustEntityRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct CreateTrustEntityRequestRestDTO {
    /// Pass a string as an identifier.
    entity_id: String,
    /// Specify the entity name.
    name: String,
    /// base64 encoded image.
    logo: Option<String>,
    /// Specify the entity's domain name.
    website: Option<String>,
    /// Specify a Terms of Service url.
    terms_url: Option<String>,
    /// Specify the Privacy Policy url.
    privacy_url: Option<String>,
    role: TrustEntityRoleRest,
    trust_anchor_id: TrustAnchorId,
}

/// Whether the trust entity issues credentials, verifies credentials, or both.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[into(TrustEntityRole)]
#[from(TrustEntityRole)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustEntityRoleRest {
    Issuer,
    Verifier,
    Both,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(GetTrustEntityResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct GetTrustEntityResponseRestDTO {
    pub id: TrustEntityId,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub entity_id: String,
    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRoleRest,

    #[from(with_fn = convert_inner)]
    pub trust_anchor: Option<GetTrustAnchorDetailResponseRestDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableTrustEntityColumnEnum)]
pub enum SortableTrustEntityColumnRestEnum {
    Name,
    Role,
}

pub type ListTrustEntitiesQuery =
    ListQueryParamsRest<TrustEntityFilterQueryParamsRestDto, SortableTrustEntityColumnRestEnum>;

#[derive(Clone, Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct TrustEntityFilterQueryParamsRestDto {
    pub name: Option<String>,
    pub role: Option<TrustEntityRoleRest>,
    pub trust_anchor_id: Option<TrustAnchorId>,
    pub organisation_id: OrganisationId,
    #[param(inline, rename = "exact[]")]
    pub exact: Option<Vec<ExactColumn>>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(TrustEntitiesResponseItemDTO)]
pub struct ListTrustEntitiesResponseItemRestDTO {
    pub id: TrustEntityId,
    pub name: String,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,

    pub entity_id: String,
    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRoleRest,
    pub trust_anchor_id: TrustAnchorId,
    pub organisation_id: OrganisationId,
}
