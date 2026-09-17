use one_dto_mapper::{Into, convert_inner};
use serde::Deserialize;

use crate::provider::verifier::dto::VerifierAppVersion;
use crate::service::managed_instance::dto::{
    EcosystemMetadataDTO, ProviderTrustCollectionDTO, UserAuthenticationDTO,
    WalletUnitAttestationMetadataDTO,
};
use crate::service::verifier_provider::dto;

#[derive(Clone, Debug, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(dto::VerifierProviderMetadataResponseDTO)]
pub(super) struct VerifierProviderMetadataResponseRestDTO {
    pub name: String,
    #[into(with_fn = convert_inner)]
    pub app_version: Option<VerifierAppVersion>,
    /// Deprecated, superseded by the trust collections of `ecosystems`, which is
    /// what this client reads.
    #[serde(default)]
    pub trust_collections: Vec<ProviderTrustCollectionDTO>,
    pub feature_flags: dto::FeatureFlags,
    pub verifier_app_attestation: WalletUnitAttestationMetadataDTO,
    pub user_authentication: Option<UserAuthenticationDTO>,
    #[serde(default)]
    pub proof_schemas: Vec<String>,
    #[serde(default)]
    pub credential_schemas: Vec<String>,
    #[serde(default)]
    pub ecosystems: Vec<EcosystemMetadataDTO>,
}
