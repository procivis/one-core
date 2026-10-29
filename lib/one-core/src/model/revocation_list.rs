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

use crate::model::certificate::Certificate;
use crate::model::identifier::Identifier;
use crate::model::relation::Related;

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

#[derive(Clone, Debug, PartialEq, Default)]
pub struct RevocationListEntryFilter {
    /// inclusive
    pub index_from: Option<usize>,
    /// exclusive (to avoid panic on empty range 0..0)
    pub index_to: Option<usize>,
    pub states: Option<Vec<RevocationListEntryState>>,
}

impl RevocationListEntryFilter {
    pub fn from_index_range(range: impl RangeBounds<usize>) -> Self {
        let index_from = match range.start_bound() {
            Bound::Included(&from) => Some(from),
            Bound::Excluded(&from) => Some(from + 1),
            Bound::Unbounded => None,
        };
        let index_to = match range.end_bound() {
            Bound::Included(&to) => Some(to + 1),
            Bound::Excluded(&to) => Some(to),
            Bound::Unbounded => None,
        };
        Self {
            index_from,
            index_to,
            ..Default::default()
        }
    }
}
