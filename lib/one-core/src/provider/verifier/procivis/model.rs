use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{ManagedInstanceId, OrganisationId};
use time::Duration;

use crate::config::core_config::IdentifierType;
use crate::provider::verifier::dto::{AccessCertificateConfiguration, VerifierAppVersion};
use crate::service::managed_instance::dto::{IntegrityCheck, UserAuthenticationParams};

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Params {
    pub app_version: Option<VerifierAppVersion>,
    pub feature_flags: ConfigFeatureFlags,
    pub integrity_check: Option<IntegrityCheck>,
    pub user_authentication: Option<UserAuthenticationParams>,
    pub access_certificate_configuration: Option<AccessCertificateConfiguration>,
    // Defaulted so existing verifierProvider config entries without this key keep working.
    #[serde(default = "default_device_auth_leeway")]
    #[serde_as(as = "DurationSeconds<i64>")]
    pub device_auth_leeway_seconds: Duration,
    pub signer_identifier_types: Vec<IdentifierType>,
}

fn default_device_auth_leeway() -> Duration {
    Duration::seconds(60)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ConfigFeatureFlags {
    pub ecosystems_enabled: bool,
    #[serde(default)]
    pub ecosystems_enforcement_enabled: bool,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AccessCertificateProvisioningRequest {
    pub provider: String,
    pub managed_instance_id: ManagedInstanceId,
    pub verifier_provider_organisation_id: OrganisationId,
}
