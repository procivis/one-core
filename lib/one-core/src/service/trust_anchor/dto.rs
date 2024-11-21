use shared_types::TrustAnchorId;
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::model::list_query::ListQuery;
use crate::model::trust_anchor::TrustAnchorRole;
use crate::service::trust_entity::dto::GetTrustEntityResponseDTO;

#[derive(Clone, Debug)]
pub struct CreateTrustAnchorRequestDTO {
    pub name: String,
    pub r#type: String,
    pub role: TrustAnchorRole,
}

#[derive(Clone, Debug)]
pub struct GetTrustAnchorDetailResponseDTO {
    pub id: TrustAnchorId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub r#type: String,
    pub publisher_reference: Option<String>,
    pub role: TrustAnchorRole,
}

#[derive(Clone, Debug)]
pub struct GetTrustAnchorResponseDTO {
    pub id: TrustAnchorId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub entities: Vec<GetTrustEntityResponseDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableTrustAnchorColumn {
    Name,
    CreatedDate,
    Type,
    Role,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustAnchorFilterValue {
    Name(StringMatch),
    Role(TrustAnchorRole),
    Type(StringMatch),
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
    pub publisher_reference: Option<String>,
    pub role: TrustAnchorRole,
    pub entities: u32,
}

pub type GetTrustAnchorsResponseDTO = GetListResponse<TrustAnchorsListItemResponseDTO>;
