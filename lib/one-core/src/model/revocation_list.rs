use std::ops::{Bound, RangeBounds};

use proc_macros::Model;
use serde::{Deserialize, Serialize};
use shared_types::{
    CredentialId, ManagedInstanceAttestationId, RevocationListEntryId, RevocationListId,
    RevocationMethodId, SignerId,
};
use standardized_types::x509::CertificateSerial;
use strum::Display;
use time::OffsetDateTime;

use super::certificate::Certificate;
use super::common::GetListResponse;
use super::identifier::Identifier;
use super::list_filter::ListFilterValue;
use super::list_query::ListQuery;
use super::relation::Related;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct RevocationList {
    #[model(id)]
    pub id: RevocationListId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub formatted_list: Vec<u8>,
    pub format: StatusListCredentialFormat,
    pub r#type: RevocationMethodId,
    pub purpose: RevocationListPurpose,

    /// persisted parameters specific to used revocation method
    pub params: Option<Vec<u8>>,

    /// Distinction between multiple lists of the same issuer
    pub sequence_number: usize,

    // Relations:
    pub issuer_identifier: Related<Identifier>,
    pub issuer_certificate: Option<Related<Certificate>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Display, Serialize)]
pub enum RevocationListPurpose {
    Revocation,
    Suspension,
    RevocationAndSuspension,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Display, Serialize, Deserialize)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StatusListCredentialFormat {
    Jwt,
    JsonLdClassic,
    X509Crl,
    Cwt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationListEntry {
    pub id: RevocationListEntryId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub entity_info: RevocationListEntityInfo,
    pub index: Option<usize>,
    pub state: RevocationListEntryState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationListEntryState {
    Active,
    Revoked,
    Suspended,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationListEntityId {
    /// Set to `None` for reserving a slot on the list, without linking it to a credential yet.
    /// Later use `UpdateRevocationListEntryRequest.credential_id` to set the ID via `UpdateRevocationListEntryId.Id`
    Credential(Option<CredentialId>),
    Signature(SignerId, Option<CertificateSerial>),
    KeyAttestation(ManagedInstanceAttestationId),
    WalletInstanceAttestation(ManagedInstanceAttestationId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationListEntityInfo {
    Credential(Option<CredentialId>),
    Signature(SignerId, Option<CertificateSerial>),
    KeyAttestation,
    WalletInstanceAttestation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateRevocationListEntryId {
    Credential(CredentialId),
    Id(RevocationListEntryId),
    Index(RevocationListId, usize),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateRevocationListEntryRequest {
    pub state: Option<RevocationListEntryState>,
    /// set id on a previously reserved credential entry
    pub credential_id: Option<CredentialId>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RevocationListEntryFilterValue {
    List(RevocationListId),
    Ids(Vec<RevocationListEntryId>),
    IndexRange {
        /// inclusive
        from: Option<usize>,
        /// exclusive (to avoid panic on empty range 0..0)
        to: Option<usize>,
    },
    States(Vec<RevocationListEntryState>),
}

impl ListFilterValue for RevocationListEntryFilterValue {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableRevocationListEntryColumn {
    Index,
}

pub type RevocationListEntryList<Count = Option<u64>> = GetListResponse<RevocationListEntry, Count>;
pub type RevocationListEntryListQuery =
    ListQuery<SortableRevocationListEntryColumn, RevocationListEntryFilterValue>;

impl RevocationListEntryFilterValue {
    pub fn index_range(range: impl RangeBounds<usize>) -> Self {
        let from = match range.start_bound() {
            Bound::Included(&from) => Some(from),
            Bound::Excluded(&from) => Some(from + 1),
            Bound::Unbounded => None,
        };
        let to = match range.end_bound() {
            Bound::Included(&to) => Some(to + 1),
            Bound::Excluded(&to) => Some(to),
            Bound::Unbounded => None,
        };
        Self::IndexRange { from, to }
    }
}
