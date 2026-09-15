use serde::{Deserialize, Serialize};
use shared_types::{InstanceId, WalletInstanceAttestationId};
use strum::Display;
use time::OffsetDateTime;

use crate::model::key::Key;
use crate::model::relation::Related;

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct WalletInstanceAttestation {
    pub id: WalletInstanceAttestationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiration_date: OffsetDateTime,
    pub attestation: String,
    pub holder_wallet_unit_id: InstanceId, // not a relation because of reverse relation exists
    pub revocation_list_url: Option<String>,
    pub revocation_list_index: Option<i64>,

    // Relations:
    pub attested_key: Related<Key>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UpdateWalletInstanceAttestationRequest {
    pub expiration_date: Option<OffsetDateTime>,
    pub attestation: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttestationType {
    WalletInstanceAttestation,
    KeyAttestation,
}
