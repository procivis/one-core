use shared_types::{WalletUnitAttestationId, WalletUnitId};
use strum::Display;
use time::OffsetDateTime;

use super::organisation::{Organisation, OrganisationRelations};
use crate::model::key::{Key, KeyRelations};
use crate::model::wallet_unit::WalletProviderType;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletUnitAttestation {
    pub id: WalletUnitAttestationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiration_date: Option<OffsetDateTime>,
    pub status: WalletUnitAttestationStatus,
    pub attestation: String,
    pub wallet_unit_id: WalletUnitId,
    pub wallet_provider_url: String,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,

    // Relations:
    pub organisation: Option<Organisation>,
    pub key: Option<Key>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Display)]
pub enum WalletUnitAttestationStatus {
    Active,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct WalletUnitAttestationRelations {
    pub key: Option<KeyRelations>,
    pub organisation: Option<OrganisationRelations>,
}
