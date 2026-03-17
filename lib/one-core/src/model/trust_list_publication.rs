use shared_types::{
    CertificateId, IdentifierId, KeyId, OrganisationId, TrustListPublicationId,
    TrustListPublisherId,
};
use time::OffsetDateTime;

use crate::model::certificate::{Certificate, CertificateRelations};
use crate::model::common::GetListResponse;
use crate::model::identifier::{Identifier, IdentifierRelations};
use crate::model::key::{Key, KeyRelations};
use crate::model::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use crate::model::list_query::ListQuery;
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::trust_list_role::TrustListRoleEnum;

#[derive(Clone, Debug)]
pub struct TrustListPublication {
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

    pub organisation_id: OrganisationId,
    pub identifier_id: IdentifierId,
    pub key_id: Option<KeyId>,
    pub certificate_id: Option<CertificateId>,

    // Relations
    pub organisation: Option<Organisation>,
    pub identifier: Option<Identifier>,
    pub key: Option<Key>,
    pub certificate: Option<Certificate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct TrustListPublicationRelations {
    pub organisation: Option<OrganisationRelations>,
    pub identifier: Option<IdentifierRelations>,
    pub key: Option<KeyRelations>,
    pub certificate: Option<CertificateRelations>,
}

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
