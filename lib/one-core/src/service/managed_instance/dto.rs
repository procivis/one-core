use serde::{Deserialize, Deserializer, Serialize};
use serde_with::{DurationSeconds, serde_as, skip_serializing_none};
use shared_types::{EcosystemId, ManagedInstanceId, RevocationMethodId, TrustCollectionId};
use standardized_types::jwk::PublicJwk;
use standardized_types::openid4vci::KeyStorageSecurityLevel;
use time::{Duration, OffsetDateTime};

use crate::config::core_config::DocumentSignerType;
use crate::model::common::GetListResponse;
use crate::model::instance::{InstanceRole, InstanceStatus};
use crate::model::managed_instance::ManagedInstanceOs;
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SdJwtVcStatus;

#[derive(Clone, Debug)]
pub struct RegisterWalletUnitRequestDTO {
    pub provider: String,
    pub role: InstanceRole,
    pub os: ManagedInstanceOs,
    pub public_key: Option<PublicJwk>,
    pub proof: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RegisterWalletUnitResponseDTO {
    pub id: ManagedInstanceId,
    pub nonce: Option<String>,
    pub user_nonce: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ActivateWalletUnitRequestDTO {
    pub attestation: Option<Vec<String>>,
    pub attestation_key_proof: Option<String>,
    pub device_signing_key_proof: Option<String>,
    pub user_id_token: Option<String>,
    pub verifier_access_certificate_csr: Option<String>,
    pub user_access_token: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ActivateWalletUnitResponseDTO {
    pub access_certificate: Option<String>,
}

#[derive(Clone, Debug)]
pub struct WalletUnitActivationRequestDTO {
    pub attestation: Option<Vec<String>>,
    pub attestation_key_proof: Option<String>,
    pub device_signing_key_proof: Option<String>,
    pub user_id_token: Option<String>,
    pub verifier_access_certificate_csr: Option<String>,
    pub user_access_token: Option<String>,
}

#[derive(Clone, Debug)]
pub struct WalletUnitActivationResponseDTO {
    pub access_certificate: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RefreshWalletUnitRequestDTO {
    pub proof: String,
}

#[derive(Clone, Debug)]
pub struct IssueWalletUnitAttestationRequestDTO {
    pub wia: Vec<IssueWiaRequestDTO>,
    pub wua: Vec<IssueWuaRequestDTO>,
}

#[derive(Clone, Debug)]
pub struct IssueWiaRequestDTO {
    pub proof: String,
}

#[derive(Clone, Debug)]
pub struct IssueWuaRequestDTO {
    pub proof: String,
    pub security_level: KeyStorageSecurityLevel,
}

#[derive(Clone, Debug)]
pub struct IssueWalletUnitAttestationResponseDTO {
    pub wia: Vec<String>,
    pub wua: Vec<String>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WalletProviderParams {
    pub wallet_name: String,
    pub wallet_link: String,
    pub wallet_client_id: String,
    // Information for wallet whether it enforces having a wallet unit attestation when starting app
    pub wallet_registration: WalletRegistrationRequirement,
    pub wallet_instance_attestation: WalletInstanceAttestationParams,
    pub wallet_unit_attestation: WalletUnitAttestationParams,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub device_auth_leeway_seconds: Duration,
    pub app_version: Option<AppVersionDTO>,
    pub eudi_wallet_info: Option<EudiWalletInfoConfig>,
    #[serde(default)]
    pub document_signers: Vec<String>,
    pub feature_flags: FeatureFlagsParams,
    pub user_authentication: Option<UserAuthenticationParams>,
}

/// Feature flags as configured on the wallet provider config entry.
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", try_from = "FeatureFlagsWire")]
pub struct FeatureFlags {
    pub ecosystems_enabled: bool,
    pub refresh_credential_batch_enabled: bool,
    #[serde(default)]
    pub document_signing_enabled: bool,
    /// Whether the instances of this provider must enforce the ecosystems
    /// advertised in `ecosystems`.
    #[serde(default)]
    pub ecosystems_enforcement_enabled: bool,
}

/// Wire format of [`FeatureFlags`]. `ecosystemsEnabled` was previously named
/// `trustEcosystemsEnabled`: wallet providers running an older core report only
/// the old name, ones running a current core report both.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FeatureFlagsWire {
    ecosystems_enabled: Option<bool>,
    trust_ecosystems_enabled: Option<bool>,
    refresh_credential_batch_enabled: bool,
    #[serde(default)]
    document_signing_enabled: bool,
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
            refresh_credential_batch_enabled: value.refresh_credential_batch_enabled,
            document_signing_enabled: value.document_signing_enabled,
            ecosystems_enforcement_enabled: value.ecosystems_enforcement_enabled,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UserAuthenticationParams {
    pub required: bool,
    pub identity_provider: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub token_validation: TokenValidationParams,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TokenValidationParams {
    pub aud: String,
    pub iss: String,
    pub jwks_uri: String,
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
pub(crate) struct WalletInstanceAttestationParams {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub expiration_seconds: Duration,
    #[serde(default)]
    pub integrity_check: IntegrityCheck,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WalletUnitAttestationParams {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub expiration_seconds: Duration,
    pub revocation_method: Option<RevocationMethodId>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct EudiWalletInfoConfig {
    pub provider_name: String,
    pub solution_id: String,
    pub solution_version: String,
    pub wscd_type: WscdType,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WscdType {
    Remote,
    LocalExternal,
    LocalInternal,
    LocalNative,
    Hybrid,
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
pub(crate) struct AndroidBundle {
    pub bundle_id: String,
    #[serde(deserialize_with = "deserialize_signing_certificate_fingerprints")]
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

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IntegrityCheck {
    pub android: Option<AndroidBundle>,
    pub ios: Option<IOSBundle>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_attestation_timeout")]
    #[serde_as(as = "DurationSeconds<i64>")]
    pub timeout_seconds: Duration,
}

impl Default for IntegrityCheck {
    fn default() -> Self {
        Self {
            android: None,
            ios: None,
            enabled: true,
            timeout_seconds: Duration::seconds(300),
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_attestation_timeout() -> Duration {
    Duration::seconds(300)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IOSBundle {
    pub bundle_id: String,
    #[serde(rename = "trustedAttestationCAs")]
    pub trusted_attestation_cas: Vec<String>,
    pub enforce_production_build: bool,
}

#[derive(Debug)]
pub struct GetManagedInstanceResponseDTO {
    pub id: ManagedInstanceId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub last_issuance: Option<OffsetDateTime>,
    pub name: String,
    pub os: ManagedInstanceOs,
    pub status: InstanceStatus,
    pub role: InstanceRole,
    pub provider_name: String,
    pub provider_type: String,
    pub authentication_key_jwk: Option<PublicJwk>,
    pub user_sub: Option<String>,
    pub verifier_csr: Option<String>,
}

pub type GetManagedInstanceListResponseDTO = GetListResponse<GetManagedInstanceResponseDTO>;

#[derive(Clone, Debug)]
pub struct ManagedInstanceFilterParamsDTO {
    pub name: Option<String>,
    pub ids: Option<Vec<shared_types::ManagedInstanceId>>,
    pub status: Option<Vec<InstanceStatus>>,
    pub os: Option<Vec<ManagedInstanceOs>>,
    pub provider_names: Option<Vec<String>>,
    pub roles: Option<Vec<InstanceRole>>,
    pub attestation: Option<String>,
    pub organisation_id: shared_types::OrganisationId,
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub user_sub: Option<String>,
}

#[derive(Clone, Debug)]
pub struct WalletProviderMetadataResponseDTO {
    pub wallet_unit_attestation: WalletUnitAttestationMetadataDTO,
    pub name: String,
    pub app_version: Option<AppVersionDTO>,
    /// Deprecated, superseded by the trust collections of `ecosystems`
    pub trust_collections: Vec<ProviderTrustCollectionDTO>,
    pub document_signers: Vec<DocumentSignerMetadataDTO>,
    pub feature_flags: FeatureFlags,
    pub user_authentication: Option<UserAuthenticationDTO>,
    pub ecosystems: Vec<EcosystemMetadataDTO>,
}

/// An ecosystem selected by the organisation owning the provider, together with
/// the entities of that organisation belonging to the ecosystem.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcosystemMetadataDTO {
    /// Ecosystem provider name
    pub name: EcosystemId,
    #[serde(default)]
    pub display_name: Vec<DisplayNameDTO>,
    #[serde(default)]
    pub description: Vec<DisplayNameDTO>,
    pub logo: String,
    /// Whether the instance should select this ecosystem by default.
    #[serde(default)]
    pub default_selected: bool,
    #[serde(default)]
    pub trust_collections: Vec<EcosystemTrustCollectionDTO>,
    /// credential schema `importedSourceUrl`'s
    #[serde(default)]
    pub credential_schemas: Vec<String>,
    /// proof schema `importedSourceUrl`'s, only filled for verifier providers.
    #[serde(default)]
    pub proof_schemas: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcosystemTrustCollectionDTO {
    pub id: TrustCollectionId,
    /// Trust collection provider name
    pub name: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserAuthenticationDTO {
    pub required: bool,
    pub identity_provider: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub token_validation: Option<TokenValidationDTO>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenValidationDTO {
    pub aud: String,
    pub iss: String,
    pub jwks_uri: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentSignerMetadataDTO {
    pub name: String,
    pub r#type: DocumentSignerType,
    pub display_name: Vec<DisplayNameDTO>,
    pub description: Vec<DisplayNameDTO>,
    pub logo: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderTrustCollectionDTO {
    pub id: TrustCollectionId,
    pub name: String,
    pub logo: String,
    pub display_name: Vec<DisplayNameDTO>,
    pub description: Vec<DisplayNameDTO>,
    #[serde(default)]
    pub default_selected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisplayNameDTO {
    pub lang: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletUnitAttestationMetadataDTO {
    pub app_integrity_check_required: bool,
    pub enabled: bool,
    pub required: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct NoncePayload {
    pub nonce: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct WalletInstanceAttestationClaims {
    pub wallet_name: Option<String>,
    pub wallet_link: Option<String>,
    pub eudi_wallet_info: Option<EudiWalletInfo>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct WalletUnitAttestationClaims {
    pub key_storage: Vec<KeyStorageSecurityLevel>,
    pub attested_keys: Vec<PublicJwk>,
    pub eudi_wallet_info: Option<EudiWalletInfo>,
    pub status: Option<SdJwtVcStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct EudiWalletInfo {
    pub general_info: EudiWalletGeneralInfo,
    pub wscd_info: Option<WscdInfo>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct EudiWalletGeneralInfo {
    pub wallet_provider_name: String,
    pub wallet_solution_id: String,
    pub wallet_solution_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct WscdInfo {
    pub wscd_type: WscdType,
}
