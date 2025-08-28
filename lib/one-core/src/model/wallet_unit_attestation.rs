use shared_types::{WalletUnitAttestationId, WalletUnitId};
use time::OffsetDateTime;

use super::organisation::{Organisation, OrganisationRelations};
use crate::model::key::{Key, KeyRelations};
use crate::model::wallet_unit::{WalletProviderType, WalletUnitStatus};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletUnitAttestation {
    pub id: WalletUnitAttestationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiration_date: OffsetDateTime,
    pub status: WalletUnitStatus,
    pub attestation: String,
    pub wallet_unit_id: WalletUnitId,
    pub wallet_provider_url: String,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,

    // Relations:
    pub organisation: Option<Organisation>,
    pub key: Option<Key>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct WalletUnitAttestationRelations {
    pub key: Option<KeyRelations>,
    pub organisation: Option<OrganisationRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UpdateWalletUnitAttestationRequest {
    pub expiration_date: Option<OffsetDateTime>,
    pub status: Option<WalletUnitStatus>,
    pub attestation: Option<String>,
}
