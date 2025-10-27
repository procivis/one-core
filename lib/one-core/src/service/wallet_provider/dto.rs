use one_dto_mapper::{From, convert_inner};
use serde::{Deserialize, Deserializer, Serialize};
use shared_types::WalletUnitId;
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::wallet_unit::{WalletProviderType, WalletUnit, WalletUnitOs, WalletUnitStatus};
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
pub struct ActivateWalletUnitRequestDTO {
    pub attestation: Vec<String>,
    pub attestation_key_proof: String,
    pub device_signing_key_proof: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ActivateWalletUnitResponseDTO {
    pub attestation: String,
}

#[derive(Clone, Debug)]
pub struct WalletUnitActivationRequestDTO {
    pub attestation: Vec<String>,
    pub attestation_key_proof: String,
    pub device_signing_key_proof: Option<String>,
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
    pub wallet_unit_attestation: WalletUnitAttestationParams,
    pub app_version: Option<AppVersionDTO>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WalletUnitAttestationParams {
    pub wallet_name: String,
    pub wallet_link: String,
    pub android: Option<AndroidBundle>,
    pub ios: Option<IOSBundle>,
    pub lifetime: Lifetime,
    pub revocation_method: Option<String>,
    #[serde(default)]
    pub integrity_check: IntegrityCheck,
    // Information for wallet whether it enforce having a wallet unit attestation when starting app
    pub required: bool,
    // Information for wallet if wallet unit attestation is enabled as a functionality
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppVersionDTO {
    pub minimum: String,
    pub minimum_recommended: Option<String>,
    #[serde(default)]
    pub reject: Vec<String>,
    pub update_screen: Option<UpdateScreenDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateScreenDTO {
    pub link: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AndroidBundle {
    pub bundle_id: String,
    #[serde(
        rename = "signingCertificateFingerprints",
        deserialize_with = "deserialize_signing_certificate_fingerprints"
    )]
    pub signing_certificate_fingerprints: Vec<String>,
    #[serde(rename = "trustedAttestationCAs")]
    pub trusted_attestation_cas: Vec<String>,
}

fn deserialize_signing_certificate_fingerprints<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Vec<String> = Deserialize::deserialize(d)?;
    Ok(s.iter()
        .map(|s| s.replace(":", "").to_uppercase())
        .collect())
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
pub(super) struct IOSBundle {
    pub bundle_id: String,
    #[serde(rename = "trustedAttestationCAs")]
    pub trusted_attestation_cas: Vec<String>,
    pub enforce_production_build: bool,
}

#[derive(From)]
#[from(WalletUnit)]
pub struct GetWalletUnitResponseDTO {
    pub id: WalletUnitId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub last_issuance: Option<OffsetDateTime>,
    pub name: String,
    pub os: WalletUnitOs,
    pub status: WalletUnitStatus,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,
    #[from(with_fn = convert_inner)]
    pub authentication_key_jwk: Option<PublicKeyJwkDTO>,
}

pub type GetWalletUnitListResponseDTO = GetListResponse<GetWalletUnitResponseDTO>;

#[derive(Clone, Debug)]
pub struct WalletProviderMetadataResponseDTO {
    pub wallet_unit_attestation: WalletUnitAttestationMetadataDTO,
    pub name: String,
    pub app_version: Option<AppVersionDTO>,
}

#[derive(Clone, Debug)]
pub struct WalletUnitAttestationMetadataDTO {
    pub app_integrity_check_required: bool,
    pub enabled: bool,
    pub required: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct NoncePayload {
    pub nonce: Option<String>,
}
