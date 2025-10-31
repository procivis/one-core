use one_dto_mapper::{From, Into, convert_inner};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::WalletUnitId;

use crate::model::wallet_unit::WalletUnitOs;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::service::wallet_provider::dto;
use crate::service::wallet_provider::dto::KeyStorageSecurityLevel;

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, From)]
#[from(dto::RegisterWalletUnitRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterWalletUnitRequestRestDTO {
    pub wallet_provider: String,
    pub os: WalletUnitOs,
    pub public_key: Option<PublicKeyJwkDTO>,
    pub proof: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Into)]
#[into(dto::RegisterWalletUnitResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterWalletUnitResponseRestDTO {
    pub id: WalletUnitId,
    pub nonce: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, From)]
#[from(dto::ActivateWalletUnitRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct ActivateWalletUnitRequestRestDTO {
    pub attestation: Vec<String>,
    pub attestation_key_proof: String,
    pub device_signing_key_proof: Option<String>,
}

#[derive(Clone, Debug, Serialize, From)]
#[from(dto::IssueWalletUnitAttestationRequestDTO)]
pub struct IssueWalletUnitAttestationRequestRestDTO {
    #[from(with_fn = convert_inner)]
    pub waa: Vec<IssueWaaRequestRestDTO>,
    #[from(with_fn = convert_inner)]
    pub wua: Vec<IssueWuaRequestRestDTO>,
}

#[derive(Clone, Debug, Serialize, From)]
#[from(dto::IssueWaaRequestDTO)]
pub struct IssueWaaRequestRestDTO {
    pub proof: String,
}

#[derive(Clone, Debug, Serialize, From)]
#[from(dto::IssueWuaRequestDTO)]
pub struct IssueWuaRequestRestDTO {
    pub proof: String,
    pub security_level: KeyStorageSecurityLevel,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[into(dto::IssueWalletUnitAttestationResponseDTO)]
pub(super) struct IssueWalletUnitAttestationResponseRestDTO {
    #[serde(default)]
    pub waa: Vec<String>,
    #[serde(default)]
    pub wua: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(dto::WalletProviderMetadataResponseDTO)]
pub(super) struct WalletProviderMetadataResponseRestDTO {
    wallet_unit_attestation: WalletUnitAttestationMetadataRestDTO,
    name: String,
    #[into(with_fn = convert_inner)]
    app_version: Option<AppVersionRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(dto::WalletUnitAttestationMetadataDTO)]
pub(super) struct WalletUnitAttestationMetadataRestDTO {
    app_integrity_check_required: bool,
    enabled: bool,
    required: bool,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(dto::AppVersionDTO)]
pub(super) struct AppVersionRestDTO {
    minimum: String,
    minimum_recommended: Option<String>,
    #[serde(default)]
    reject: Vec<String>,
    #[into(with_fn = convert_inner)]
    update_screen: Option<UpdateScreenRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(dto::UpdateScreenDTO)]
pub(super) struct UpdateScreenRestDTO {
    pub link: Option<String>,
}
