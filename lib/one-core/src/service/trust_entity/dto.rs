use shared_types::{OrganisationId, TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::model::list_query::ListQuery;
use crate::model::trust_entity::TrustEntityRole;
use crate::service::trust_anchor::dto::GetTrustAnchorDetailResponseDTO;

#[derive(Clone, Debug)]
pub struct CreateTrustEntityRequestDTO {
    pub entity_id: String,
    pub name: String,
    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub trust_anchor_id: TrustAnchorId,
}

#[derive(Clone, Debug)]
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

    pub trust_anchor: Option<GetTrustAnchorDetailResponseDTO>,
}

pub type GetTrustEntitiesResponseDTO = GetListResponse<TrustEntitiesResponseItemDTO>;

pub type ListTrustEntitiesQueryDTO =
    ListQuery<SortableTrustEntityColumnEnum, TrustEntityFilterValue>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableTrustEntityColumnEnum {
    Name,
    Role,
}

#[derive(Clone, Debug)]
pub struct TrustEntitiesResponseItemDTO {
    pub id: TrustEntityId,
    pub name: String,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    pub entity_id: String,
    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub trust_anchor_id: TrustAnchorId,
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustEntityFilterValue {
    Name(StringMatch),
    Role(TrustEntityRole),
    TrustAnchor(TrustAnchorId),
    Organisation(OrganisationId),
}

impl ListFilterValue for TrustEntityFilterValue {}
