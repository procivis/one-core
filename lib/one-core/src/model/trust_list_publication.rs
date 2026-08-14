use proc_macros::Model;
use shared_types::{OrganisationId, TrustListPublicationId, TrustListPublisherId};
use time::OffsetDateTime;

use crate::model::certificate::Certificate;
use crate::model::common::GetListResponse;
use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::model::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use crate::model::list_query::ListQuery;
use crate::model::organisation::Organisation;
use crate::model::relation::Related;
use crate::model::trust_list_role::TrustListRoleEnum;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct TrustListPublication {
    #[model(id)]
    pub id: TrustListPublicationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub role: TrustListRoleEnum,
    pub r#type: TrustListPublisherId,
    pub metadata: Vec<u8>,
    pub deleted_at: Option<OffsetDateTime>,
    pub content: Vec<u8>,
    pub sequence_number: u32,

    // Relations
    pub organisation: Related<Organisation>,
    pub identifier: Related<Identifier>,
    pub key: Option<Related<Key>>,
    pub certificate: Option<Related<Certificate>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct TrustListPublicationRelations {}

#[derive(Clone, Debug, Default)]
pub struct UpdateTrustListPublicationRequest {
    pub content: Option<Vec<u8>>,
    pub sequence_number: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableTrustListPublicationColumn {
    Role,
    Type,
    Name,
    LastModified,
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustListPublicationFilterValue {
    OrganisationId(OrganisationId),
    Name(StringMatch),
    Type(Vec<TrustListPublisherId>),
    Role(Vec<TrustListRoleEnum>),
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
    Ids(Vec<TrustListPublicationId>),
}

impl ListFilterValue for TrustListPublicationFilterValue {}

pub type TrustListPublicationListQuery =
    ListQuery<SortableTrustListPublicationColumn, TrustListPublicationFilterValue>;

pub type GetTrustListPublicationList = GetListResponse<TrustListPublication>;
