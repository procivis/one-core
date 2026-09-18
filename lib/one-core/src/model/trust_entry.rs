use serde::{Deserialize, Serialize};
use shared_types::{IdentifierId, TrustEntryId, TrustListPublicationId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::identifier::Identifier;
use crate::model::list_filter::{ListFilterValue, ValueComparison};
use crate::model::list_query::ListQuery;
use crate::model::relation::Related;
use crate::model::trust_list_publication::TrustListPublication;

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct TrustEntry {
    pub id: TrustEntryId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub state: TrustEntryStateEnum,
    pub metadata: Vec<u8>,

    // Relations
    pub trust_list_publication: Related<TrustListPublication>,
    pub identifier: Related<Identifier>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustEntryStateEnum {
    Active,
    Suspended,
    Removed,
}

#[derive(Clone, Debug, Default)]
pub struct UpdateTrustEntryRequest {
    pub state: Option<TrustEntryStateEnum>,
    pub metadata: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableTrustEntryColumn {
    Identifier,
    State,
    LastModified,
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustEntryFilterValue {
    TrustListPublicationId(TrustListPublicationId),
    IdentifierIds(Vec<IdentifierId>),
    State(Vec<TrustEntryStateEnum>),
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
    Ids(Vec<TrustEntryId>),
}

impl ListFilterValue for TrustEntryFilterValue {}

pub type TrustEntryListQuery = ListQuery<SortableTrustEntryColumn, TrustEntryFilterValue>;

pub type GetTrustEntryList<Count = Option<u64>> = GetListResponse<TrustEntry, Count>;
