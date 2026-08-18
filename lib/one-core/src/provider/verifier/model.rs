use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{IdentifierId, OrganisationId};
use time::Duration;

use crate::service::managed_instance::dto::{
    UserAuthenticationParams, WalletInstanceAttestationParams,
};

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerifierParams {
    pub app_version: Option<VerifierAppVersion>,
    pub feature_flags: ConfigFeatureFlags,
    pub verifier_instance_attestation: Option<WalletInstanceAttestationParams>,
    pub user_authentication: Option<UserAuthenticationParams>,
    pub access_certificate_configuration: Option<AccessCertificateConfiguration>,
    // Defaulted so existing verifierProvider config entries without this key keep working.
    #[serde(default = "default_device_auth_leeway")]
    #[serde_as(as = "DurationSeconds<i64>")]
    pub device_auth_leeway_seconds: Duration,
}

fn default_device_auth_leeway() -> Duration {
    Duration::seconds(60)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigFeatureFlags {
    #[serde(alias = "trustEcosystemsEnabled")]
    pub ecosystems_enabled: bool,
    #[serde(default)]
    pub ecosystems_enforcement_enabled: bool,
}

#[expect(unused)]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccessCertificateConfiguration {
    pub provider_url: String,
    pub organisation_id: OrganisationId,
    pub relying_party_public_identifier: String,
    pub relying_party_national_registry: String,
    pub issuer_id: IdentifierId,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierAppVersion {
    pub minimum: Option<String>,
    pub minimum_recommended: Option<String>,
    pub reject: Option<Vec<String>>,
    pub update_screen: Option<VerifierUpdateScreen>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierUpdateScreen {
    pub link: String,
}
