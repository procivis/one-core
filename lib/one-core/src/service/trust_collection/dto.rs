use one_dto_mapper::From;
use shared_types::{
    OrganisationId, TrustCollectionId, TrustListSubscriberId, TrustListSubscriptionId,
};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::trust_collection::TrustCollection;
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::TrustListSubscription;

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

#[derive(Clone, Debug)]
pub struct TrustCollectionPublicResponseDTO {
    pub name: String,
    pub trust_lists: Vec<TrustListDTO>,
}

#[derive(Clone, Debug, From)]
#[from(TrustListSubscription)]
pub struct TrustListDTO {
    pub id: TrustListSubscriptionId,
    pub name: String,
    pub role: TrustListRoleEnum,
    pub reference: String,
    pub r#type: TrustListSubscriberId,
}
