use one_dto_mapper::{From, Into};
use serde::Deserialize;
use shared_types::{DidValue, TrustAnchorId, TrustEntityId, TrustEntityKey};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::model::list_query::ListQuery;
use crate::model::trust_anchor::TrustAnchor;
use crate::model::trust_entity::{TrustEntityRole, TrustEntityState, TrustEntityType};
use crate::service::trust_entity::dto::TrustEntityContent;

#[derive(Clone, Debug)]
pub struct CreateTrustAnchorRequestDTO {
    pub name: String,
    pub r#type: String,
    pub is_publisher: Option<bool>,
    pub publisher_reference: Option<String>,
}

#[derive(Clone, Debug, From, Deserialize)]
#[from(TrustAnchor)]
#[serde(rename_all = "camelCase")]
pub struct GetTrustAnchorDetailResponseDTO {
    pub id: TrustAnchorId,
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub created_date: OffsetDateTime,
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub r#type: String,
    pub is_publisher: bool,
    pub publisher_reference: String,
}

#[derive(Clone, Debug)]
pub struct GetTrustAnchorResponseDTO {
    pub id: TrustAnchorId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub entities: Vec<GetTrustAnchorEntityListResponseDTO>,
}

#[derive(Clone, Debug)]
pub struct GetTrustAnchorEntityListResponseDTO {
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
    pub r#type: TrustEntityType,
    pub entity_key: TrustEntityKey,
    pub content: Option<TrustEntityContent>,
    pub did: Option<DidValue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableTrustAnchorColumn {
    Name,
    CreatedDate,
    Type,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustAnchorFilterValue {
    Name(StringMatch),
    IsPublisher(bool),
    Type(StringMatch),
}

impl TrustAnchorFilterValue {
    pub fn is_publisher(v: impl Into<bool>) -> Self {
        Self::IsPublisher(v.into())
    }
}

impl ListFilterValue for TrustAnchorFilterValue {}

pub type ListTrustAnchorsQueryDTO = ListQuery<SortableTrustAnchorColumn, TrustAnchorFilterValue>;

#[derive(Clone, Debug, Into)]
#[into(TrustAnchor)]
pub struct TrustAnchorsListItemResponseDTO {
    pub id: TrustAnchorId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub r#type: String,
    pub is_publisher: bool,
    pub publisher_reference: String,
    #[into(skip)]
    pub entities: u32,
}

pub type GetTrustAnchorsResponseDTO = GetListResponse<TrustAnchorsListItemResponseDTO>;
