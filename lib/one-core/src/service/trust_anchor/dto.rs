use one_dto_mapper::From;
use shared_types::{TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::model::list_query::ListQuery;
use crate::model::trust_anchor::TrustAnchor;
use crate::model::trust_entity::{TrustEntityRole, TrustEntityState};
use crate::service::did::dto::DidListItemResponseDTO;

#[derive(Clone, Debug)]
pub struct CreateTrustAnchorRequestDTO {
    pub name: String,
    pub r#type: String,
    pub is_publisher: Option<bool>,
    pub publisher_reference: Option<String>,
}

#[derive(Clone, Debug, From)]
#[from(TrustAnchor)]
pub struct GetTrustAnchorDetailResponseDTO {
    pub id: TrustAnchorId,
    pub created_date: OffsetDateTime,
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

    pub did: DidListItemResponseDTO,
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

#[derive(Clone, Debug)]
pub struct TrustAnchorsListItemResponseDTO {
    pub id: TrustAnchorId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub r#type: String,
    pub is_publisher: bool,
    pub publisher_reference: String,
    pub entities: u32,
}

pub type GetTrustAnchorsResponseDTO = GetListResponse<TrustAnchorsListItemResponseDTO>;
