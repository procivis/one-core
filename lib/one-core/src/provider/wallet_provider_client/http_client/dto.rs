use one_dto_mapper::{From, Into};
use serde::{Deserialize, Serialize};
use shared_types::WalletUnitId;

use crate::model::wallet_unit::WalletUnitOs;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::service::ssi_wallet_provider::dto::{
    ActivateWalletUnitRequestDTO, ActivateWalletUnitResponseDTO, RefreshWalletUnitRequestDTO,
    RefreshWalletUnitResponseDTO, RegisterWalletUnitRequestDTO, RegisterWalletUnitResponseDTO,
};

#[derive(Clone, Debug, Serialize, From)]
#[from(RegisterWalletUnitRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterWalletUnitRequestRestDTO {
    pub wallet_provider: String,
    pub os: WalletUnitOs,
    pub public_key: Option<PublicKeyJwkDTO>,
    pub proof: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[into(RegisterWalletUnitResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterWalletUnitResponseRestDTO {
    pub id: WalletUnitId,
    pub attestation: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Clone, Debug, Serialize, From)]
#[from(ActivateWalletUnitRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct ActivateWalletUnitRequestRestDTO {
    pub attestation: Vec<String>,
    pub proof: String,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[into(ActivateWalletUnitResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct ActivateWalletUnitResponseRestDTO {
    pub attestation: String,
}

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
