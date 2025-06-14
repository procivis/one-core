use serde::{Deserialize, Serialize};
use shared_types::{CertificateId, IdentifierId};
use time::OffsetDateTime;

use super::common::GetListResponse;
use super::key::{Key, KeyRelations};
use super::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use super::list_query::ListQuery;
use super::organisation::{Organisation, OrganisationRelations};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    pub id: CertificateId,
    pub identifier_id: IdentifierId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiry_date: OffsetDateTime,
    pub name: String,
    pub chain: String,
    pub state: CertificateState,

    // Relations:
    pub key: Option<Key>,
    pub organisation: Option<Organisation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateState {
    NotYetActive,
    Active,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct CertificateRelations {
    pub key: Option<KeyRelations>,
    pub organisation: Option<OrganisationRelations>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateCertificateRequest {
    pub name: Option<String>,
    pub state: Option<CertificateState>,
}

#[derive(Clone, Debug)]
pub enum SortableCertificateColumn {
    Name,
    CreatedDate,
    ExpiryDate,
    State,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateFilterValue {
    Ids(Vec<CertificateId>),
    Name(StringMatch),
    State(CertificateState),
    ExpiryDate(ValueComparison<OffsetDateTime>),
}

impl ListFilterValue for CertificateFilterValue {}

pub type GetCertificateList = GetListResponse<Certificate>;

pub type CertificateListQuery = ListQuery<SortableCertificateColumn, CertificateFilterValue>;
