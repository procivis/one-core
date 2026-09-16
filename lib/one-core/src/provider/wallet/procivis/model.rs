use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use shared_types::RevocationMethodId;
use time::Duration;

use crate::config::core_config::IdentifierType;
use crate::service::managed_instance::dto::{
    AppVersionDTO, IntegrityCheck, UserAuthenticationParams, WscdType,
};

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Params {
    pub wallet_name: String,
    pub wallet_link: String,
    pub wallet_client_id: String,
    // Information for wallet whether it enforces having a wallet unit attestation when starting app
    pub wallet_registration: WalletRegistrationRequirement,
    pub wallet_instance_attestation: WalletInstanceAttestationParams,
    pub wallet_key_attestation: WalletUnitAttestationParams,
    pub wallet_certification: serde_json::Value,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub device_auth_leeway_seconds: Duration,
    pub app_version: Option<AppVersionDTO>,
    pub eudi_wallet_info: Option<EudiWalletInfoConfig>,
    #[serde(default)]
    pub document_signers: Vec<String>,
    pub feature_flags: FeatureFlagsParams,
    pub user_authentication: Option<UserAuthenticationParams>,
    pub signer_identifier_types: Vec<IdentifierType>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum WalletRegistrationRequirement {
    Mandatory,
    Optional,
    Disabled,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WalletInstanceAttestationParams {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub expiration_seconds: Duration,
    #[serde(default)]
    pub integrity_check: IntegrityCheck,
    pub revocation_method: Option<RevocationMethodId>,
    #[serde_as(as = "DurationSeconds<i64>")]
    #[serde(default = "default_31_days")]
    pub status_period_seconds: Duration,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WalletUnitAttestationParams {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub expiration_seconds: Duration,
    pub revocation_method: Option<RevocationMethodId>,
    #[serde_as(as = "DurationSeconds<i64>")]
    #[serde(default = "default_31_days")]
    pub status_period_seconds: Duration,
}

fn default_31_days() -> Duration {
    Duration::days(31)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct EudiWalletInfoConfig {
    pub provider_name: String,
    pub solution_id: String,
    pub solution_version: String,
    pub solution_certification_information: serde_json::Value,
    pub wscd_type: WscdType,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FeatureFlagsParams {
    pub ecosystems_enabled: bool,
    pub refresh_credential_batch_enabled: bool,
    #[serde(default)]
    pub document_signing_enabled: bool,
    #[serde(default)]
    pub ecosystems_enforcement_enabled: bool,
}
