use serde::{Deserialize, Serialize};
use shared_types::{DidId, DidValue, OrganisationId, TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::model::list_query::ListQuery;
use crate::model::trust_entity::{TrustEntityRole, TrustEntityState};
use crate::service::did::dto::DidListItemResponseDTO;
use crate::service::trust_anchor::dto::GetTrustAnchorDetailResponseDTO;

#[derive(Clone, Debug)]
pub struct CreateTrustEntityRequestDTO {
    pub name: String,
    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub state: TrustEntityState,
    pub trust_anchor_id: TrustAnchorId,
    pub did_id: DidId,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTrustEntityFromDidPublisherRequestDTO {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_anchor_id: Option<TrustAnchorId>,
    pub did: DidValue,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    pub role: TrustEntityRole,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTrustEntityFromDidPublisherResponseDTO {
    pub id: TrustEntityId,
}

#[derive(Clone, Debug)]
pub struct CreateRemoteTrustEntityRequestDTO {
    pub did_id: DidId,
    pub trust_anchor_id: Option<TrustAnchorId>,
    pub name: String,
    pub logo: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub website: Option<String>,
    pub role: TrustEntityRole,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTrustEntityResponseDTO {
    pub id: TrustEntityId,
    pub organisation_id: Option<OrganisationId>,
    pub name: String,

    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub created_date: OffsetDateTime,
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub last_modified: OffsetDateTime,

    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub state: TrustEntityState,
    pub did: DidListItemResponseDTO,
    pub trust_anchor: GetTrustAnchorDetailResponseDTO,
}

pub type GetTrustEntitiesResponseDTO = GetListResponse<TrustEntitiesResponseItemDTO>;

pub type ListTrustEntitiesQueryDTO =
    ListQuery<SortableTrustEntityColumnEnum, TrustEntityFilterValue>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableTrustEntityColumnEnum {
    Name,
    Role,
    LastModified,
    State,
}

#[derive(Clone, Debug)]
pub struct TrustEntitiesResponseItemDTO {
    pub id: TrustEntityId,
    pub name: String,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub state: TrustEntityState,
    pub trust_anchor: GetTrustAnchorDetailResponseDTO,
    pub did: DidListItemResponseDTO,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustEntityFilterValue {
    Name(StringMatch),
    Role(TrustEntityRole),
    TrustAnchor(TrustAnchorId),
    DidId(DidId),
    OrganisationId(OrganisationId),
}

impl ListFilterValue for TrustEntityFilterValue {}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTrustEntityFromDidRequestDTO {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<UpdateTrustEntityActionFromDidRequestDTO>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "::serde_with::rust::double_option"
    )]
    pub logo: Option<Option<String>>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "::serde_with::rust::double_option"
    )]
    pub website: Option<Option<String>>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "::serde_with::rust::double_option"
    )]
    pub terms_url: Option<Option<String>>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "::serde_with::rust::double_option"
    )]
    pub privacy_url: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<TrustEntityRole>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpdateTrustEntityActionFromDidRequestDTO {
    AdminActivate,
    Activate,
    Withdraw,
    Remove,
}
