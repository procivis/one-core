use crate::service::wallet_provider::dto::RefreshWalletUnitResponseDTO;

#[derive(Clone, Debug)]
pub enum RefreshWalletUnitResponse {
    Active(RefreshWalletUnitResponseDTO),
    Revoked,
}
