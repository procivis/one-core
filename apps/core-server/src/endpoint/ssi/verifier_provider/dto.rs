use one_core::provider::verifier::model::{VerifierAppVersion, VerifierUpdateScreen};
use one_core::service::managed_instance::dto::EcosystemMetadataDTO;
use one_core::service::verifier_provider::dto::{
    FeatureFlags, VerifierProviderMetadataResponseDTO,
};
use one_dto_mapper::{From, convert_inner};
use proc_macros::options_not_nullable;
use serde::Serialize;
use shared_types::EcosystemId;
use utoipa::ToSchema;

use crate::endpoint::ssi::wallet_provider::dto::{
    DisplayNameRestDTO, EcosystemTrustCollectionRestDTO, ProviderTrustCollectionRestDTO,
    UserAuthenticationRestDTO, WalletUnitAttestationMetadataRestDTO,
};

#[options_not_nullable]
#[derive(Clone, From, Serialize, ToSchema)]
#[from(VerifierProviderMetadataResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerifierProviderResponseRestDTO {
    // ONE-9505: only present for backwards compatibility with old verifier apps
    // can be removed once all verifier apps updated with latest core
    #[deprecated]
    #[from(replace = "\"PROCIVIS_ONE\"")]
    pub verifier_name: String,

    pub name: String,
    #[from(with_fn = convert_inner)]
    pub app_version: Option<VerifierProviderAppVersionResponseDTO>,
    /// The trust collections of all advertised `ecosystems`, flattened. The
    /// display properties are the ones of the owning ecosystem.
    #[deprecated = "use ecosystems instead"]
    #[from(with_fn = convert_inner)]
    pub trust_collections: Vec<ProviderTrustCollectionRestDTO>,
    pub feature_flags: VerifierFeatureFlagsRestDTO,

    pub verifier_app_attestation: WalletUnitAttestationMetadataRestDTO,
    #[from(with_fn = convert_inner)]
    pub user_authentication: Option<UserAuthenticationRestDTO>,
    /// proof schema `importSourceUrl`'s
    pub proof_schemas: Option<Vec<String>>,
    /// credential schema `importSourceUrl`'s
    pub credential_schemas: Option<Vec<String>>,
    #[from(with_fn = convert_inner)]
    pub ecosystems: Vec<VerifierProviderEcosystemRestDTO>,
}

/// An ecosystem advertised by this verifier provider.
#[options_not_nullable]
#[derive(Clone, Debug, From, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[from(EcosystemMetadataDTO)]
pub(crate) struct VerifierProviderEcosystemRestDTO {
    /// ecosystem provider name
    pub name: EcosystemId,
    #[from(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub display_name: Vec<DisplayNameRestDTO>,
    #[from(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub description: Vec<DisplayNameRestDTO>,
    pub logo: String,
    /// Whether the verifier should select this ecosystem by default.
    pub default_selected: bool,
    #[from(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub trust_collections: Vec<EcosystemTrustCollectionRestDTO>,
    /// credential schema `importSourceUrl`'s
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub credential_schemas: Vec<String>,
    /// proof schema `importSourceUrl`'s
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub proof_schemas: Vec<String>,
}

#[options_not_nullable]
#[derive(Clone, From, Serialize, ToSchema)]
#[from(VerifierAppVersion)]
#[serde(rename_all = "camelCase")]
pub struct VerifierProviderAppVersionResponseDTO {
    pub minimum: Option<String>,
    pub minimum_recommended: Option<String>,
    pub reject: Option<Vec<String>>,
    #[from(with_fn = convert_inner)]
    pub update_screen: Option<VerifierProviderUpdateScreenResponseDTO>,
}

#[derive(Clone, From, Serialize, ToSchema)]
#[from(VerifierUpdateScreen)]
#[serde(rename_all = "camelCase")]
pub struct VerifierProviderUpdateScreenResponseDTO {
    pub link: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(FeatureFlags)]
pub struct VerifierFeatureFlagsRestDTO {
    pub ecosystems_enabled: bool,
    pub access_certificate_provisioning_enabled: bool,
    /// Whether the verifier app must enforce the ecosystems advertised in `ecosystems`.
    pub ecosystems_enforcement_enabled: bool,
}
