use one_core::service::wallet_provider::dto;
use one_dto_mapper::{From, Into, convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use serde_with::{OneOrMany, serde_as};
use shared_types::WalletUnitId;
use utoipa::ToSchema;

use crate::deserialize::one_or_many;
use crate::endpoint::ssi::dto::PublicKeyJwkRestDTO;
use crate::endpoint::wallet_provider::dto::WalletUnitOsRestEnum;

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::IssueWalletUnitAttestationRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IssueWalletUnitAttestationRequestRestDTO {
    #[into(with_fn = convert_inner)]
    #[serde(default)]
    pub waa: Vec<IssueWaaRequestRestDTO>,
    #[into(with_fn = convert_inner)]
    #[serde(default)]
    pub wua: Vec<IssueWuaRequestRestDTO>,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::IssueWaaRequestDTO)]
pub struct IssueWaaRequestRestDTO {
    pub proof: String,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::IssueWuaRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct IssueWuaRequestRestDTO {
    pub proof: String,
    pub security_level: KeyStorageSecurityLevelRestEnum,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::KeyStorageSecurityLevel)]
pub enum KeyStorageSecurityLevelRestEnum {
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
    pub waa: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub wua: Vec<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::RegisterWalletUnitRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterWalletUnitRequestRestDTO {
    pub wallet_provider: String,
    pub os: WalletUnitOsRestEnum,
    #[into(with_fn = convert_inner)]
    pub public_key: Option<PublicKeyJwkRestDTO>,
    pub proof: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(dto::RegisterWalletUnitResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterWalletUnitResponseRestDTO {
    pub id: WalletUnitId,
    pub attestation: Option<String>,
    pub nonce: Option<String>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::WalletUnitActivationRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WalletUnitActivationRequestRestDTO {
    #[serde_as(as = "OneOrMany<_>")]
    #[schema(schema_with = one_or_many::<String>)]
    pub attestation: Vec<String>,
    pub attestation_key_proof: String,
    pub device_signing_key_proof: Option<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(dto::WalletUnitActivationResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WalletUnitActivationResponseRestDTO {
    pub attestation: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::WalletProviderMetadataResponseDTO)]
pub(crate) struct WalletProviderMetadataResponseRestDTO {
    wallet_unit_attestation: WalletUnitAttestationMetadataRestDTO,
    name: String,
    #[from(with_fn = convert_inner)]
    app_version: Option<AppVersionRestDTO>,
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
