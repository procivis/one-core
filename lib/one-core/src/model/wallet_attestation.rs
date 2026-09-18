use proc_macros::Model;
use serde::{Deserialize, Serialize};
use shared_types::{InstanceId, WalletAttestationId};
use strum::Display;
use time::OffsetDateTime;

use super::common::GetListResponse;
use super::key::Key;
use super::list_filter::{ListFilterValue, ValueComparison};
use super::list_query::ListQuery;
use super::relation::Related;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct WalletAttestation {
    #[model(id)]
    pub id: WalletAttestationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiration_date: Option<OffsetDateTime>,
    pub attestation: String,
    pub instance_id: InstanceId, // not a relation because of reverse relation exists
    pub r#type: AttestationType,

    // Relations:
    pub attested_key: Option<Related<Key>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttestationType {
    // OpenID4VCI attestations
    WalletInstanceAttestation,
    KeyAttestation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableWalletAttestationColumn {
    CreatedDate,
    LastModified,
    ExpirationDate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalletAttestationFilterValue {
    ExpirationDate(ValueComparison<OffsetDateTime>),
    Instance(InstanceId),
}

impl ListFilterValue for WalletAttestationFilterValue {}

pub type WalletAttestationListQuery =
    ListQuery<SortableWalletAttestationColumn, WalletAttestationFilterValue>;

pub type WalletAttestationList<Count = Option<u64>> = GetListResponse<WalletAttestation, Count>;
