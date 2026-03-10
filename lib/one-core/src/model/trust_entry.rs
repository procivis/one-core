use serde::{Deserialize, Serialize};
use shared_types::{IdentifierId, TrustEntryId, TrustListPublicationId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::identifier::{Identifier, IdentifierRelations};
use crate::model::list_filter::{ListFilterValue, ValueComparison};
use crate::model::list_query::ListQuery;
use crate::model::trust_list_publication::{TrustListPublication, TrustListPublicationRelations};

#[derive(Clone, Debug)]
pub struct TrustEntry {
    pub id: TrustEntryId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub status: TrustEntryStatusEnum,
    pub metadata: Vec<u8>,
    pub trust_list_publication_id: TrustListPublicationId,
    pub identifier_id: IdentifierId,

    // Relations
    pub trust_list_publication: Option<TrustListPublication>,
    pub identifier: Option<Identifier>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustEntryStatusEnum {
    Active,
    Suspended,
    Removed,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct TrustEntryRelations {
    pub trust_list_publication: Option<TrustListPublicationRelations>,
    pub identifier: Option<IdentifierRelations>,
}

#[derive(Clone, Debug, Default)]
pub struct UpdateTrustEntryRequest {
    pub status: Option<TrustEntryStatusEnum>,
    pub metadata: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableTrustEntryColumn {
    Status,
    LastModified,
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustEntryFilterValue {
    TrustListPublicationId(TrustListPublicationId),
    Status(Vec<TrustEntryStatusEnum>),
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
    Ids(Vec<TrustEntryId>),
}

impl ListFilterValue for TrustEntryFilterValue {}

pub type TrustEntryListQuery = ListQuery<SortableTrustEntryColumn, TrustEntryFilterValue>;

pub type GetTrustEntryList = GetListResponse<TrustEntry>;
