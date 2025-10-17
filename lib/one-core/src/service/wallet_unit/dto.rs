use serde::{Deserialize, Serialize};
use shared_types::{KeyId, OrganisationId, WalletUnitAttestationId, WalletUnitId};
use time::OffsetDateTime;

pub use crate::model::wallet_unit::{
    WalletProviderType, WalletUnit, WalletUnitOs, WalletUnitStatus,
};

pub struct AttestationKeyRequestDTO {
    pub organisation_id: OrganisationId,
    pub name: String,
    pub key_type: String,
    pub nonce: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HolderRegisterWalletUnitRequestDTO {
    pub organisation_id: OrganisationId,
    pub key_type: String,
    pub wallet_provider: WalletProviderDTO,
}

#[derive(Debug, Clone)]
pub struct HolderRegisterWalletUnitResponseDTO {
    pub id: WalletUnitId,
    pub key_id: KeyId,
}

#[derive(Debug, Clone)]
pub struct HolderRefreshWalletUnitRequestDTO {
    pub organisation_id: OrganisationId,
    pub app_integrity_check_required: bool,
}

#[derive(Debug, Clone)]
pub struct WalletProviderDTO {
    pub name: String,
    pub r#type: WalletProviderType,
    pub url: String,
    pub app_integrity_check_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Serialize)]
pub(super) struct NoncePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}
