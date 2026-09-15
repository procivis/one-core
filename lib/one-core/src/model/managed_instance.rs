use proc_macros::Model;
use serde::{Deserialize, Serialize};
use shared_types::{ManagedInstanceId, OrganisationId, RevocationListEntryId};
use standardized_types::jwk::PublicJwk;
use strum::Display;
use time::OffsetDateTime;

use super::common::GetListResponse;
use super::list_query::ListQuery;
use crate::model::instance::{InstanceRole, InstanceStatus};
use crate::model::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use crate::model::managed_instance_attestation::ManagedInstanceAttestation;
use crate::model::organisation::Organisation;
use crate::model::relation::{Related, RelatedVec};

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct ManagedInstance {
    #[model(id)]
    pub id: ManagedInstanceId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub os: ManagedInstanceOs,
    pub status: InstanceStatus,
    pub role: InstanceRole,
    pub provider: String,
    pub authentication_key_jwk: Option<PublicJwk>,
    pub last_issuance: Option<OffsetDateTime>,
    pub nonce: Option<String>,
    pub user_nonce: Option<String>,
    pub user_sub: Option<String>,
    pub verifier_csr: Option<String>,
    pub verifier_signature_ids: Option<Vec<RevocationListEntryId>>,

    // Relations:
    pub organisation: Related<Organisation>,
    pub attestations: RelatedVec<ManagedInstanceAttestation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(ascii_case_insensitive, serialize_all = "UPPERCASE")]
pub enum ManagedInstanceOs {
    Ios,
    Android,
    Web,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableManagedInstanceColumn {
    CreatedDate,
    LastModified,
    Name,
    Status,
    Os,
    UserSub,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagedInstanceFilterValue {
    OrganisationId(OrganisationId),
    Name(StringMatch),
    Ids(Vec<ManagedInstanceId>),
    Status(Vec<InstanceStatus>),
    ProviderName(Vec<String>),
    Role(Vec<InstanceRole>),
    Os(Vec<ManagedInstanceOs>),
    AttestationHash(String),
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
    UserSub(StringMatch),
}

impl ListFilterValue for ManagedInstanceFilterValue {}

pub type ManagedInstanceListQuery =
    ListQuery<SortableManagedInstanceColumn, ManagedInstanceFilterValue>;

pub type ManagedInstanceList = GetListResponse<ManagedInstance>;

#[derive(Clone, Debug, Default)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct UpdateManagedInstanceRequest {
    pub status: Option<InstanceStatus>,
    pub last_issuance: Option<OffsetDateTime>,
    pub authentication_key_jwk: Option<PublicJwk>,
    pub user_sub: Option<String>,
    pub verifier_csr: Option<Option<String>>,
    pub verifier_signature_ids: Option<Vec<RevocationListEntryId>>,
}
