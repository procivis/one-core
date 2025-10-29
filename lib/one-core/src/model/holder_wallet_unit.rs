use shared_types::{HolderWalletUnitId, WalletUnitId};
use time::OffsetDateTime;

use crate::model::key::{Key, KeyRelations};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::wallet_unit::{WalletProviderType, WalletUnitStatus};
use crate::model::wallet_unit_attestation::{
    WalletUnitAttestation, WalletUnitAttestationRelations,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HolderWalletUnit {
    pub id: HolderWalletUnitId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,
    pub wallet_provider_url: String,
    pub provider_wallet_unit_id: WalletUnitId,
    pub status: WalletUnitStatus,

    // Relations:
    pub organisation: Option<Organisation>,
    pub authentication_key: Option<Key>,
    pub wallet_unit_attestations: Option<Vec<WalletUnitAttestation>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct HolderWalletUnitRelations {
    pub wallet_unit_attestations: Option<WalletUnitAttestationRelations>,
    pub organisation: Option<OrganisationRelations>,
    pub authentication_key: Option<KeyRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UpdateHolderWalletUnitRequest {
    pub status: Option<WalletUnitStatus>,
    pub wallet_unit_attestations: Option<Vec<WalletUnitAttestation>>,
}
