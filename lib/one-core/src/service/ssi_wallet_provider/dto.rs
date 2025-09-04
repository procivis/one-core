use serde::Deserialize;
use shared_types::{IdentifierId, WalletUnitId};

use crate::model::wallet_unit::WalletUnitOs;
use crate::service::key::dto::PublicKeyJwkDTO;

#[derive(Clone, Debug)]
pub struct RegisterWalletUnitRequestDTO {
    pub wallet_provider: String,
    pub os: WalletUnitOs,
    pub public_key: Option<PublicKeyJwkDTO>,
    pub proof: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RegisterWalletUnitResponseDTO {
    pub id: WalletUnitId,
    pub attestation: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Clone, Debug)]
pub struct WalletUnitActivationRequestDTO {
    pub attestation: Vec<String>,
    pub proof: String,
}

#[derive(Clone, Debug)]
pub struct WalletUnitActivationResponseDTO {
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

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WalletProviderParams {
    #[allow(unused)]
    pub wallet_name: String,
    #[allow(unused)]
    pub wallet_link: String,
    #[allow(unused)]
    pub android: Option<Bundle>,
    #[allow(unused)]
    pub ios: Option<Bundle>,
    pub lifetime: Lifetime,
    pub issuer_identifier: IdentifierId,
    #[serde(default)]
    pub integrity_check: IntegrityCheck,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct IntegrityCheck {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[allow(unused)]
    #[serde(default = "default_attestation_timeout")]
    pub timeout: usize,
}

impl Default for IntegrityCheck {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout: 300,
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_attestation_timeout() -> usize {
    300
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Lifetime {
    pub expiration_time: i64,
    pub minimum_refresh_time: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(unused)]
pub(super) struct Bundle {
    pub bundle_id: String,
    #[serde(rename = "trustedAttestationCAs")]
    pub trusted_attestation_cas: Vec<String>,
}
