use crate::service::ssi_wallet_provider::dto::RefreshWalletUnitResponseDTO;

#[derive(Clone, Debug)]
pub enum RefreshWalletUnitResponse {
    Active(RefreshWalletUnitResponseDTO),
    Suspended,
}
