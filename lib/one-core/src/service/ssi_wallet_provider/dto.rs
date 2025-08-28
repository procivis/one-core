use serde::Deserialize;
use shared_types::{IdentifierId, WalletUnitId};

use crate::service::key::dto::PublicKeyJwkDTO;

#[derive(Clone, Debug)]
pub struct RegisterWalletUnitRequestDTO {
    pub wallet_provider: String,
    pub os: String,
    pub public_key: PublicKeyJwkDTO,
    pub proof: String,
}

#[derive(Clone, Debug)]
pub struct RegisterWalletUnitResponseDTO {
    pub id: WalletUnitId,
    pub attestation: String,
}

#[derive(Clone, Debug)]
pub struct RefreshWalletUnitRequestDTO {
    pub proof: String,
}

#[derive(Clone, Debug)]
pub struct RefreshWalletUnitResponseDTO {
    pub id: WalletUnitId,
    pub attestation: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WalletProviderParams {
    pub wallet_name: String,
    pub wallet_link: String,
    pub android: Option<Bundle>,
    pub ios: Option<Bundle>,
    pub lifetime: Lifetime,
    pub issuer_identifier: IdentifierId,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Lifetime {
    pub expiration_time: i64,
    pub minimum_refresh_time: i64,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Bundle {
    pub bundle_id: String,
}
