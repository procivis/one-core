use proc_macros::Model;
use shared_types::{EcosystemId, OrganisationId, TrustCollectionId};
use time::OffsetDateTime;
use url::Url;

use super::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use super::list_query::ListQuery;
use super::organisation::Organisation;
use crate::model::common::GetListResponse;
use crate::model::relation::Related;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct TrustCollection {
    #[model(id)]
    pub id: TrustCollectionId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
    pub remote_trust_collection_url: Option<Url>,
    pub ecosystem: EcosystemId,

    // Relations
    pub organisation: Related<Organisation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustCollectionFilterValue {
    Name(StringMatch),
    OrganisationId {
        id: OrganisationId,
        include_inherited_collections: bool,
    },
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
    Ids(Vec<TrustCollectionId>),
    Remote(bool),
    Empty(bool),
    Ecosystems(Vec<EcosystemId>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableTrustCollectionColumn {
    Name,
    CreatedDate,
    LastModified,
}

impl ListFilterValue for TrustCollectionFilterValue {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactTrustCollectionFilterColumn {
    Name,
}

pub type TrustCollectionListQuery =
    ListQuery<SortableTrustCollectionColumn, TrustCollectionFilterValue>;

pub type GetTrustCollectionList<Count = Option<u64>> = GetListResponse<TrustCollection, Count>;
