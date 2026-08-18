use one_core::config::core_config::DocumentSignerType;
use one_core::service::managed_instance::dto;
use one_dto_mapper::{From, Into, convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use serde_with::{OneOrMany, serde_as};
use shared_types::{EcosystemId, ManagedInstanceId, TrustCollectionId};
use standardized_types::jwk::PublicJwk;
use standardized_types::openid4vci::KeyStorageSecurityLevel;
use utoipa::ToSchema;

use crate::deserialize::one_or_many;
use crate::endpoint::managed_instance::dto::ManagedInstanceOsRestEnum;

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::IssueWalletUnitAttestationRequestDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IssueWalletUnitAttestationRequestRestDTO {
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub wia: Vec<IssueWiaRequestRestDTO>,
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub wua: Vec<IssueWuaRequestRestDTO>,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[serde(deny_unknown_fields)]
#[into(dto::IssueWiaRequestDTO)]
pub(crate) struct IssueWiaRequestRestDTO {
    pub proof: String,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::IssueWuaRequestDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IssueWuaRequestRestDTO {
    pub proof: String,
    pub security_level: KeyStorageSecurityLevelRestEnum,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(KeyStorageSecurityLevel)]
pub(crate) enum KeyStorageSecurityLevelRestEnum {
    #[serde(rename = "iso_18045_high")]
    High,
    #[serde(rename = "iso_18045_moderate")]
    Moderate,
    #[serde(rename = "iso_18045_enhanced-basic")]
    EnhancedBasic,
    #[serde(rename = "iso_18045_basic")]
    Basic,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(dto::IssueWalletUnitAttestationResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IssueWalletUnitAttestationResponseRestDTO {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub wia: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub wua: Vec<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RegisterWalletUnitRequestRestDTO {
    pub wallet_provider: String,
    pub os: ManagedInstanceOsRestEnum,
    pub public_key: Option<PublicJwk>,
    pub proof: Option<String>,
}

// Deprecated endpoint: only ever registers a WALLET-role instance, unlike
// `RegisterInstanceRequestRestDTO` which lets the caller choose the role.
impl From<RegisterWalletUnitRequestRestDTO> for dto::RegisterWalletUnitRequestDTO {
    fn from(value: RegisterWalletUnitRequestRestDTO) -> Self {
        Self {
            provider: value.wallet_provider,
            role: one_core::model::instance::InstanceRole::Wallet,
            os: value.os.into(),
            public_key: value.public_key,
            proof: value.proof,
        }
    }
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(dto::RegisterWalletUnitResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterWalletUnitResponseRestDTO {
    pub id: ManagedInstanceId,
    pub nonce: Option<String>,
    pub user_nonce: Option<String>,
}

#[serde_as]
#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::WalletUnitActivationRequestDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WalletUnitActivationRequestRestDTO {
    #[serde(default)]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    #[schema(schema_with = one_or_many::<String>)]
    pub attestation: Option<Vec<String>>,
    pub attestation_key_proof: Option<String>,
    pub device_signing_key_proof: Option<String>,
    pub user_id_token: Option<String>,
    pub verifier_access_certificate_csr: Option<String>,
    pub user_access_token: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(dto::WalletUnitActivationResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WalletUnitActivationResponseRestDTO {
    pub access_certificate: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WalletProviderMetadataResponseRestDTO {
    wallet_unit_attestation: WalletUnitAttestationMetadataRestDTO,
    name: String,
    app_version: Option<AppVersionRestDTO>,
    /// The trust collections of all advertised `ecosystems`, flattened. The
    /// display properties are the ones of the owning ecosystem.
    #[deprecated = "use ecosystems instead"]
    trust_collections: Vec<ProviderTrustCollectionRestDTO>,
    document_signers: Vec<DocumentSignerMetadataRestDTO>,
    feature_flags: FeatureFlagsRestDTO,
    user_authentication: Option<UserAuthenticationRestDTO>,
    ecosystems: Vec<WalletProviderEcosystemRestDTO>,
}

#[expect(deprecated)]
impl From<dto::WalletProviderMetadataResponseDTO> for WalletProviderMetadataResponseRestDTO {
    fn from(value: dto::WalletProviderMetadataResponseDTO) -> Self {
        Self {
            wallet_unit_attestation: value.wallet_unit_attestation.into(),
            name: value.name,
            app_version: convert_inner(value.app_version),
            trust_collections: trust_collections_from_ecosystems(&value.ecosystems),
            document_signers: convert_inner(value.document_signers),
            feature_flags: value.feature_flags.into(),
            user_authentication: convert_inner(value.user_authentication),
            ecosystems: convert_inner(value.ecosystems),
        }
    }
}

/// The deprecated provider-level trust collection list, flattened out of the
/// ecosystems. The display properties of the owning ecosystem stand in for the
/// ones previously configured per collection.
pub(crate) fn trust_collections_from_ecosystems(
    ecosystems: &[dto::EcosystemMetadataDTO],
) -> Vec<ProviderTrustCollectionRestDTO> {
    ecosystems
        .iter()
        .flat_map(|ecosystem| {
            ecosystem
                .trust_collections
                .iter()
                .map(|collection| ProviderTrustCollectionRestDTO {
                    id: collection.id,
                    name: collection.name.to_owned(),
                    logo: ecosystem.logo.to_owned(),
                    display_name: convert_inner(ecosystem.display_name.to_owned()),
                    description: convert_inner(ecosystem.description.to_owned()),
                    default_selected: Some(ecosystem.default_selected),
                })
        })
        .collect()
}

/// An ecosystem advertised by this wallet provider.
#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::EcosystemMetadataDTO)]
pub(crate) struct WalletProviderEcosystemRestDTO {
    /// ecosystem provider name
    pub name: EcosystemId,
    #[from(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub display_name: Vec<DisplayNameRestDTO>,
    #[from(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub description: Vec<DisplayNameRestDTO>,
    pub logo: String,
    /// Whether the wallet should select this ecosystem by default.
    pub default_selected: bool,
    #[from(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub trust_collections: Vec<EcosystemTrustCollectionRestDTO>,
    /// credential schema `importSourceUrl`'s
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub credential_schemas: Vec<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::EcosystemTrustCollectionDTO)]
pub(crate) struct EcosystemTrustCollectionRestDTO {
    pub id: TrustCollectionId,
    /// trust collection provider name
    pub name: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::UserAuthenticationDTO)]
pub(crate) struct UserAuthenticationRestDTO {
    required: bool,
    identity_provider: String,
    client_id: String,
    redirect_uri: String,
    #[from(with_fn = convert_inner)]
    token_validation: Option<TokenValidationRestDTO>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::TokenValidationDTO)]
pub(crate) struct TokenValidationRestDTO {
    aud: String,
    iss: String,
    jwks_uri: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::FeatureFlags)]
pub(crate) struct FeatureFlagsRestDTO {
    pub ecosystems_enabled: bool,
    pub refresh_credential_batch_enabled: bool,
    pub document_signing_enabled: bool,
    /// Whether the wallet must enforce the ecosystems advertised in `ecosystems`.
    pub ecosystems_enforcement_enabled: bool,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(DocumentSignerType)]
pub(crate) enum DocumentSignerTypeRestEnum {
    WalletCentric,
    RpCentric,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::DocumentSignerMetadataDTO)]
pub(crate) struct DocumentSignerMetadataRestDTO {
    pub name: String,
    pub r#type: DocumentSignerTypeRestEnum,
    #[from(with_fn = convert_inner)]
    pub display_name: Vec<DisplayNameRestDTO>,
    #[from(with_fn = convert_inner)]
    pub description: Vec<DisplayNameRestDTO>,
    pub logo: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::ProviderTrustCollectionDTO)]
pub(crate) struct ProviderTrustCollectionRestDTO {
    pub id: TrustCollectionId,
    pub name: String,
    pub logo: String,
    #[from(with_fn = convert_inner)]
    pub display_name: Vec<DisplayNameRestDTO>,
    #[from(with_fn = convert_inner)]
    pub description: Vec<DisplayNameRestDTO>,
    pub default_selected: Option<bool>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::DisplayNameDTO)]
pub(crate) struct DisplayNameRestDTO {
    pub lang: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::WalletUnitAttestationMetadataDTO)]
pub(crate) struct WalletUnitAttestationMetadataRestDTO {
    app_integrity_check_required: bool,
    enabled: bool,
    required: bool,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::AppVersionDTO)]
pub(crate) struct AppVersionRestDTO {
    minimum: String,
    minimum_recommended: Option<String>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reject: Vec<String>,
    #[from(with_fn = convert_inner)]
    update_screen: Option<UpdateScreenRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::UpdateScreenDTO)]
pub struct UpdateScreenRestDTO {
    pub link: Option<String>,
}
