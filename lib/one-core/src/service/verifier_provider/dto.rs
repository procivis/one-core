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

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeatureFlags {
    // Older verifier providers still report this flag under its previous name.
    #[serde(alias = "trustEcosystemsEnabled")]
    pub ecosystems_enabled: bool,
    pub access_certificate_provisioning_enabled: bool,
    /// Whether the instances of this provider must enforce the ecosystems
    /// advertised in `ecosystems`.
    #[serde(default)]
    pub ecosystems_enforcement_enabled: bool,
}
