use one_dto_mapper::{From, Into, convert_inner};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::ManagedInstanceId;
use standardized_types::jwk::PublicJwk;
use standardized_types::openid4vci::KeyStorageSecurityLevel;

use crate::model::instance::InstanceRole;
use crate::model::managed_instance::ManagedInstanceOs;
use crate::service::managed_instance::dto::{
    self, DocumentSignerMetadataDTO, EcosystemMetadataDTO, FeatureFlags, ProviderTrustCollectionDTO,
};

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, From)]
#[from(dto::RegisterWalletUnitRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterWalletUnitRequestRestDTO {
    pub provider: String,
    pub role: InstanceRole,
    pub os: ManagedInstanceOs,
    pub public_key: Option<PublicJwk>,
    pub proof: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Into)]
#[into(dto::RegisterWalletUnitResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterWalletUnitResponseRestDTO {
    pub id: ManagedInstanceId,
    pub nonce: Option<String>,
    pub user_nonce: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, From)]
#[from(dto::ActivateWalletUnitRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(super) struct ActivateWalletUnitRequestRestDTO {
    pub attestation: Option<Vec<String>>,
    pub attestation_key_proof: Option<String>,
    pub device_signing_key_proof: Option<String>,
    pub user_id_token: Option<String>,
    pub verifier_access_certificate_csr: Option<String>,
    pub user_access_token: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[into(dto::ActivateWalletUnitResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(super) struct ActivateWalletUnitResponseRestDTO {
    pub access_certificate: Option<String>,
}

#[derive(Clone, Debug, Serialize, From)]
#[from(dto::IssueWalletUnitAttestationRequestDTO)]
pub struct IssueWalletUnitAttestationRequestRestDTO {
    #[from(with_fn = convert_inner)]
    pub wia: Vec<IssueWiaRequestRestDTO>,
    #[from(with_fn = convert_inner)]
    pub wua: Vec<IssueWuaRequestRestDTO>,
}

#[derive(Clone, Debug, Serialize, From)]
#[from(dto::IssueWiaRequestDTO)]
pub struct IssueWiaRequestRestDTO {
    pub proof: String,
}

#[derive(Clone, Debug, Serialize, From)]
#[from(dto::IssueWuaRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct IssueWuaRequestRestDTO {
    pub proof: String,
    pub security_level: KeyStorageSecurityLevel,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[into(dto::IssueWalletUnitAttestationResponseDTO)]
pub(super) struct IssueWalletUnitAttestationResponseRestDTO {
    #[serde(default)]
    pub wia: Vec<String>,
    #[serde(default)]
    pub wua: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(dto::WalletProviderMetadataResponseDTO)]
pub struct WalletProviderMetadataResponseRestDTO {
    wallet_unit_attestation: WalletUnitAttestationMetadataRestDTO,
    name: String,
    #[into(with_fn = convert_inner)]
    app_version: Option<AppVersionRestDTO>,
    trust_collections: Vec<ProviderTrustCollectionDTO>,
    #[serde(default)]
    document_signers: Vec<DocumentSignerMetadataDTO>,
    feature_flags: FeatureFlags,
    #[into(with_fn = convert_inner)]
    user_authentication: Option<UserAuthenticationRestDTO>,
    #[serde(default)]
    ecosystems: Vec<EcosystemMetadataDTO>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(dto::UserAuthenticationDTO)]
pub struct UserAuthenticationRestDTO {
    required: bool,
    identity_provider: String,
    client_id: String,
    redirect_uri: String,
    #[into(with_fn = convert_inner)]
    token_validation: Option<TokenValidationRestDTO>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(dto::TokenValidationDTO)]
pub struct TokenValidationRestDTO {
    aud: String,
    iss: String,
    jwks_uri: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(dto::WalletUnitAttestationMetadataDTO)]
pub struct WalletUnitAttestationMetadataRestDTO {
    app_integrity_check_required: bool,
    enabled: bool,
    required: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(dto::AppVersionDTO)]
pub struct AppVersionRestDTO {
    minimum: String,
    minimum_recommended: Option<String>,
    #[serde(default)]
    reject: Vec<String>,
    #[into(with_fn = convert_inner)]
    update_screen: Option<UpdateScreenRestDTO>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(dto::UpdateScreenDTO)]
pub struct UpdateScreenRestDTO {
    pub link: Option<String>,
}
