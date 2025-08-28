use one_dto_mapper::{From, Into};
use serde::{Deserialize, Serialize};
use shared_types::WalletUnitId;

use crate::service::key::dto::PublicKeyJwkDTO;
use crate::service::ssi_wallet_provider::dto::{
    RefreshWalletUnitRequestDTO, RefreshWalletUnitResponseDTO, RegisterWalletUnitRequestDTO,
    RegisterWalletUnitResponseDTO,
};

#[allow(dead_code)]
#[derive(Clone, Debug, Serialize, From)]
#[from(RegisterWalletUnitRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterWalletUnitRequestRestDTO {
    pub wallet_provider: String,
    pub os: String,
    pub public_key: PublicKeyJwkDTO,
    pub proof: String,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[into(RegisterWalletUnitResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterWalletUnitResponseRestDTO {
    pub id: WalletUnitId,
    pub attestation: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Serialize, From)]
#[from(RefreshWalletUnitRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RefreshWalletUnitRequestRestDTO {
    pub proof: String,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[into(RefreshWalletUnitResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RefreshWalletUnitResponseRestDTO {
    pub id: WalletUnitId,
    pub attestation: String,
}
