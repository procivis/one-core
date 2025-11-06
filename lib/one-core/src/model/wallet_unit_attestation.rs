use serde::{Deserialize, Serialize};
use shared_types::{HolderWalletUnitId, WalletUnitAttestationId};
use time::OffsetDateTime;

use crate::model::key::{Key, KeyRelations};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletUnitAttestation {
    pub id: WalletUnitAttestationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiration_date: OffsetDateTime,
    pub attestation: String,
    pub holder_wallet_unit_id: HolderWalletUnitId, // not a relation because of reverse relation exists
    pub revocation_list_url: Option<String>,
    pub revocation_list_index: Option<i64>,

    // Relations:
    pub attested_key: Option<Key>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct WalletUnitAttestationRelations {
    pub attested_key: Option<KeyRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UpdateWalletUnitAttestationRequest {
    pub expiration_date: Option<OffsetDateTime>,
    pub attestation: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum KeyStorageSecurityLevel {
    #[serde(rename = "iso_18045_high")]
    High,
    #[serde(rename = "iso_18045_moderate")]
    Moderate,
    #[serde(rename = "iso_18045_enhanced-basic")]
    EnhancedBasic,
    #[serde(rename = "iso_18045_basic")]
    Basic,
}
