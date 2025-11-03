use serde::Serialize;
use shared_types::{HolderWalletUnitId, OrganisationId, WalletUnitId};
use time::OffsetDateTime;

pub use crate::model::wallet_unit::{
    WalletProviderType, WalletUnit, WalletUnitOs, WalletUnitStatus,
};
use crate::service::key::dto::KeyListItemResponseDTO;

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
pub struct HolderRefreshWalletUnitRequestDTO {
    pub organisation_id: OrganisationId,
    pub app_integrity_check_required: bool,
}

#[derive(Debug, Clone)]
pub struct WalletProviderDTO {
    pub r#type: WalletProviderType,
    pub url: String,
}

#[derive(Serialize)]
pub(super) struct NoncePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Serialize)]
pub struct HolderWalletUnitResponseDTO {
    pub id: HolderWalletUnitId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub provider_wallet_unit_id: WalletUnitId,
    pub wallet_provider_url: String,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,
    pub status: WalletUnitStatus,
    pub authentication_key: KeyListItemResponseDTO,
}
