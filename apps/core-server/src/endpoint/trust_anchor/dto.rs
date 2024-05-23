use dto_mapper::{From, Into};
use one_core::model::trust_anchor::{TrustAnchor, TrustAnchorRole};
use one_core::service::trust_anchor::dto::{
    CreateTrustAnchorRequestDTO, SortableTrustAnchorColumn, TrustAnchorsListItemResponseDTO,
};
use serde::{Deserialize, Serialize};
use shared_types::{OrganisationId, TrustAnchorId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::dto::common::ListQueryParamsRest;
use crate::serialize::front_time;

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[into(TrustAnchorRole)]
#[from(TrustAnchorRole)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustAnchorRoleRest {
    Publisher,
    Client,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(TrustAnchor)]
#[serde(rename_all = "camelCase")]
pub struct GetTrustAnchorResponseRestDTO {
    pub id: TrustAnchorId,
    pub name: String,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,

    #[from(rename = type_field)]
    pub r#type: String,

    pub publisher_reference: String,
    pub role: TrustAnchorRoleRest,
    pub priority: u32,
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(TrustAnchorsListItemResponseDTO)]
pub struct ListTrustAnchorsResponseItemRestDTO {
    pub id: TrustAnchorId,
    pub name: String,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,

    pub r#type: String,
    pub publisher_reference: String,
    pub role: TrustAnchorRoleRest,
    pub priority: u32,
    pub organisation_id: OrganisationId,
    pub entities: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ExactTrustAnchorFilterColumnRestEnum {
    Name,
    Type,
}

#[derive(Clone, Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct TrustAnchorsFilterQueryParamsRest {
    pub name: Option<String>,
    pub role: Option<TrustAnchorRoleRest>,
    pub r#type: Option<String>,
    pub organisation_id: OrganisationId,
    #[param(inline, rename = "exact[]")]
    pub exact: Option<Vec<ExactTrustAnchorFilterColumnRestEnum>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableTrustAnchorColumn)]
pub enum SortableTrustAnchorColumnRestEnum {
    Name,
    CreatedDate,
    Type,
    Role,
    Priority,
}

pub type ListTrustAnchorsQuery =
    ListQueryParamsRest<TrustAnchorsFilterQueryParamsRest, SortableTrustAnchorColumnRestEnum>;
