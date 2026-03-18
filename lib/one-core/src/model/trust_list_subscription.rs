use shared_types::{TrustCollectionId, TrustListSubscriberId, TrustListSubscriptionId};
use time::OffsetDateTime;

use super::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use super::list_query::ListQuery;
use super::trust_collection::TrustCollection;
use crate::model::common::GetListResponse;
use crate::model::trust_list_role::TrustListRoleEnum;

#[derive(Clone, Debug)]
pub struct TrustListSubscription {
    pub id: TrustListSubscriptionId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
    pub r#type: TrustListSubscriberId,
    pub reference: String,
    pub role: TrustListRoleEnum,
    pub state: TrustListSubscriptionState,
    pub trust_collection_id: TrustCollectionId,

    // Relations:
    pub trust_collection: Option<TrustCollection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct TrustListSubscriptionRelations {
    pub trust_collection: Option<super::trust_collection::TrustCollectionRelations>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TrustListSubscriptionState {
    Active,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableTrustListSubscriptionColumn {
    Name,
    Type,
    Role,
    Reference,
    CreatedDate,
    LastModified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustListSubscriptionFilterValue {
    Name(StringMatch),
    TrustCollectionId(TrustCollectionId),
    Role(Vec<TrustListRoleEnum>),
    State(Vec<TrustListSubscriptionState>),
    Type(Vec<TrustListSubscriberId>),
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
    Ids(Vec<TrustListSubscriptionId>),
    Reference(StringMatch),
}

impl ListFilterValue for TrustListSubscriptionFilterValue {}

pub type TrustListSubscriptionListQuery =
    ListQuery<SortableTrustListSubscriptionColumn, TrustListSubscriptionFilterValue>;

pub type GetTrustListSubscriptionList = GetListResponse<TrustListSubscription>;
