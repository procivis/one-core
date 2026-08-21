use serde::Deserialize;

use crate::provider::verifier::model::VerifierAppVersion;
use crate::service::managed_instance::dto::{
    EcosystemMetadataDTO, ProviderTrustCollectionDTO, UserAuthenticationDTO,
    WalletUnitAttestationMetadataDTO,
};

#[derive(Clone, Debug)]
pub struct VerifierProviderMetadataResponseDTO {
    pub name: String,
    pub app_version: Option<VerifierAppVersion>,
    /// Deprecated, superseded by the trust collections of `ecosystems`
    pub trust_collections: Vec<ProviderTrustCollectionDTO>,
    pub feature_flags: FeatureFlags,
    pub verifier_app_attestation: WalletUnitAttestationMetadataDTO,
    pub user_authentication: Option<UserAuthenticationDTO>,
    pub proof_schemas: Option<Vec<String>>,
    pub credential_schemas: Option<Vec<String>>,
    pub ecosystems: Vec<EcosystemMetadataDTO>,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase", try_from = "FeatureFlagsWire")]
pub struct FeatureFlags {
    pub ecosystems_enabled: bool,
    pub access_certificate_provisioning_enabled: bool,
    /// Whether the instances of this provider must enforce the ecosystems
    /// advertised in `ecosystems`.
    #[serde(default)]
    pub ecosystems_enforcement_enabled: bool,
}

/// Wire format of [`FeatureFlags`]. `ecosystemsEnabled` was previously named
/// `trustEcosystemsEnabled`: verifier providers running an older core report
/// only the old name, ones running a current core report both.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FeatureFlagsWire {
    ecosystems_enabled: Option<bool>,
    trust_ecosystems_enabled: Option<bool>,
    access_certificate_provisioning_enabled: bool,
    #[serde(default)]
    ecosystems_enforcement_enabled: bool,
}

impl TryFrom<FeatureFlagsWire> for FeatureFlags {
    type Error = String;

    fn try_from(value: FeatureFlagsWire) -> Result<Self, Self::Error> {
        Ok(Self {
            ecosystems_enabled: value
                .ecosystems_enabled
                .or(value.trust_ecosystems_enabled)
                .ok_or("missing field `ecosystemsEnabled`")?,
            access_certificate_provisioning_enabled: value.access_certificate_provisioning_enabled,
            ecosystems_enforcement_enabled: value.ecosystems_enforcement_enabled,
        })
    }
}
