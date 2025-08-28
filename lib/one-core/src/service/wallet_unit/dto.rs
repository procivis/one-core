use shared_types::{KeyId, OrganisationId, WalletUnitAttestationId, WalletUnitId};
use time::OffsetDateTime;

use crate::model::wallet_unit::{WalletProviderType, WalletUnitStatus};

#[derive(Debug, Clone)]
pub struct HolderRegisterWalletUnitRequestDTO {
    pub organisation_id: OrganisationId,
    pub wallet_provider: WalletProviderDTO,
    pub key: KeyId,
}

#[derive(Debug, Clone)]
pub struct HolderRefreshWalletUnitRequestDTO {
    pub organisation_id: OrganisationId,
}

#[derive(Debug, Clone)]
pub struct WalletProviderDTO {
    pub name: String,
    pub r#type: WalletProviderType,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct HolderWalletUnitAttestationResponseDTO {
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub id: WalletUnitAttestationId,
    pub expiration_date: OffsetDateTime,
    pub status: WalletUnitStatus,
    pub attestation: String,
    pub wallet_unit_id: WalletUnitId,
    pub wallet_provider_url: String,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,
}
