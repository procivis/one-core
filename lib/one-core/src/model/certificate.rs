use proc_macros::Model;
use serde::{Deserialize, Serialize};
use shared_types::{CertificateId, IdentifierId, OrganisationId};
use strum::{Display, EnumString};
use time::OffsetDateTime;

use super::common::GetListResponse;
use super::key::Key;
use super::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use super::list_query::ListQuery;
use super::organisation::Organisation;
use super::relation::Related;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct Certificate {
    #[model(id)]
    pub id: CertificateId,
    pub identifier_id: IdentifierId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub expiry_date: OffsetDateTime,
    pub name: String,
    /// PEM chain
    pub chain: String,
    pub fingerprint: String,
    pub state: CertificateState,
    pub roles: Vec<CertificateRole>,

    pub key: Option<Related<Key>>,
    pub organisation: Related<Organisation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, EnumString, Display)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateRole {
    Authentication,
    AssertionMethod,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateState {
    NotYetActive,
    Active,
    Revoked,
    Expired,
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
    Fingerprint(String),
    State(CertificateState),
    ExpiryDate(ValueComparison<OffsetDateTime>),
    OrganisationId(OrganisationId),
    IdentifierId(IdentifierId),
    Deleted(bool),
}

impl ListFilterValue for CertificateFilterValue {}

pub type GetCertificateList<Count = Option<u64>> = GetListResponse<Certificate, Count>;

pub type CertificateListQuery = ListQuery<SortableCertificateColumn, CertificateFilterValue>;
