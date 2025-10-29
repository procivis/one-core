use serde::Serialize;
use shared_types::OrganisationId;

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
