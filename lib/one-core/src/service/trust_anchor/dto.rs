use dto_mapper::From;
use shared_types::{OrganisationId, TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::model::list_query::ListQuery;
use crate::model::trust_anchor::TrustAnchorRole;
use crate::model::trust_entity::{TrustEntity, TrustEntityRole};

#[derive(Clone, Debug)]
pub struct CreateTrustAnchorRequestDTO {
    pub name: String,
    pub type_: String,
    pub publisher_reference: String,
    pub role: TrustAnchorRole,
    pub priority: u32,
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug)]
pub struct GetTrustAnchorResponseDTO {
    pub id: TrustAnchorId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub entities: Vec<GetTrustEntityResponseDTO>,
}

#[derive(Clone, Debug, From)]
#[from(TrustEntity)]
pub struct GetTrustEntityResponseDTO {
    pub id: TrustEntityId,
    pub name: String,
    pub entity_id: String,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,

    pub trust_anchor_id: TrustAnchorId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableTrustAnchorColumn {
    Name,
    CreatedDate,
    Type,
    Role,
    Priority,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustAnchorFilterValue {
    Name(StringMatch),
    Role(TrustAnchorRole),
    Type(StringMatch),
    OrganisationId(OrganisationId),
}

impl ListFilterValue for TrustAnchorFilterValue {}

pub type ListTrustAnchorsQueryDTO = ListQuery<SortableTrustAnchorColumn, TrustAnchorFilterValue>;

pub struct TrustAnchorsListItemResponseDTO {
    pub id: TrustAnchorId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub r#type: String,
    pub publisher_reference: String,
    pub role: TrustAnchorRole,
    pub priority: u32,
    pub organisation_id: OrganisationId,
    pub entities: u32,
}

pub type GetTrustAnchorsResponseDTO = GetListResponse<TrustAnchorsListItemResponseDTO>;
