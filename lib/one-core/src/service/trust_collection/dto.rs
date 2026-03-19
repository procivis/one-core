use one_dto_mapper::From;
use shared_types::{OrganisationId, TrustCollectionId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::trust_collection::TrustCollection;

#[derive(Clone, Debug)]
pub struct CreateTrustCollectionRequestDTO {
    pub name: String,
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug, From)]
#[from(TrustCollection)]
pub struct GetTrustCollectionResponseDTO {
    pub id: TrustCollectionId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub organisation_id: OrganisationId,
}

pub type GetTrustCollectionListResponseDTO = GetListResponse<TrustCollectionListItemResponseDTO>;

#[derive(Debug, Clone, From)]
#[from(TrustCollection)]
pub struct TrustCollectionListItemResponseDTO {
    pub id: TrustCollectionId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub organisation_id: OrganisationId,
}
