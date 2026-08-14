use one_dto_mapper::From;
use shared_types::{
    EcosystemId, OrganisationId, TrustCollectionId, TrustListSubscriberId, TrustListSubscriptionId,
};
use time::OffsetDateTime;
use url::Url;

use crate::model::common::GetListResponse;
use crate::model::trust_collection::{ExactTrustCollectionFilterColumn, TrustCollection};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{TrustListSubscription, TrustListSubscriptionState};

#[derive(Clone, Debug)]
pub struct CreateTrustCollectionRequestDTO {
    pub name: String,
    pub organisation_id: OrganisationId,
    pub ecosystem: EcosystemId,
}

#[derive(Clone, Debug)]
pub struct CreateTrustListSubscriptionRequestDTO {
    pub name: String,
    pub role: Option<TrustListRoleEnum>,
    pub reference: Url,
    pub r#type: TrustListSubscriberId,
}

#[derive(Clone, Debug, From)]
#[from(TrustCollection)]
pub struct GetTrustCollectionResponseDTO {
    pub id: TrustCollectionId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub organisation_id: OrganisationId,
    pub remote_trust_collection_url: Option<Url>,
    pub ecosystem: EcosystemId,
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
    pub remote_trust_collection_url: Option<Url>,
    pub ecosystem: EcosystemId,
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
    pub role: Option<TrustListRoleEnum>,
    pub reference: String,
    pub r#type: TrustListSubscriberId,
}

pub type GetTrustListSubscriptionListResponseDTO =
    GetListResponse<TrustListSubscriptionListItemResponseDTO>;

#[derive(Debug, Clone, From)]
#[from(TrustListSubscription)]
pub struct TrustListSubscriptionListItemResponseDTO {
    pub id: TrustListSubscriptionId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub role: Option<TrustListRoleEnum>,
    pub reference: String,
    pub r#type: TrustListSubscriberId,
    pub state: TrustListSubscriptionState,
}

#[derive(Clone, Debug)]
pub struct TrustCollectionFilterParamsDTO {
    pub name: Option<String>,
    pub ids: Option<Vec<TrustCollectionId>>,
    pub exact: Option<Vec<ExactTrustCollectionFilterColumn>>,
    pub organisation_id: OrganisationId,
    pub ecosystems: Option<Vec<EcosystemId>>,
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
    pub include_parent_organisation_collections: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustListSubscriptionExactColumn {
    Name,
    Reference,
}

#[derive(Clone, Debug)]
pub struct TrustListSubscriptionFilterParamsDTO {
    pub name: Option<String>,
    pub reference: Option<String>,
    pub ids: Option<Vec<TrustListSubscriptionId>>,
    pub roles: Option<Vec<TrustListRoleEnum>>,
    pub states: Option<Vec<TrustListSubscriptionState>>,
    pub types: Option<Vec<TrustListSubscriberId>>,
    pub exact: Option<Vec<TrustListSubscriptionExactColumn>>,
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
}
