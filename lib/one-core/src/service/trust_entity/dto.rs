use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{DidId, DidValue, OrganisationId, TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::model::list_query::ListQuery;
use crate::model::trust_entity::{TrustEntityRole, TrustEntityState, TrustEntityType};
use crate::service::common_dto::{BoundedB64Image, KB};
use crate::service::did::dto::DidListItemResponseDTO;
use crate::service::trust_anchor::dto::GetTrustAnchorDetailResponseDTO;

pub type TrustListLogo = BoundedB64Image<{ 50 * KB }>;

#[derive(Clone, Debug)]
pub struct CreateTrustEntityRequestDTO {
    pub name: String,
    pub logo: Option<TrustListLogo>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub trust_anchor_id: TrustAnchorId,
    pub did_id: DidId,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTrustEntityFromDidPublisherRequestDTO {
    pub trust_anchor_id: Option<TrustAnchorId>,
    pub did: DidValue,
    pub name: String,
    pub logo: Option<TrustListLogo>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
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
    pub logo: Option<TrustListLogo>,
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
    pub did: Option<DidListItemResponseDTO>,
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
    pub did: Option<DidListItemResponseDTO>,
    pub entity_key: String,
    pub r#type: TrustEntityType,
    pub content: Option<String>,
    pub organisation_id: Option<OrganisationId>,
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

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTrustEntityFromDidRequestDTO {
    pub action: Option<UpdateTrustEntityActionFromDidRequestDTO>,
    pub name: Option<String>,
    #[serde(with = "::serde_with::rust::double_option")]
    pub logo: Option<Option<TrustListLogo>>,
    #[serde(with = "::serde_with::rust::double_option")]
    pub website: Option<Option<String>>,
    #[serde(with = "::serde_with::rust::double_option")]
    pub terms_url: Option<Option<String>>,
    #[serde(with = "::serde_with::rust::double_option")]
    pub privacy_url: Option<Option<String>>,
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
