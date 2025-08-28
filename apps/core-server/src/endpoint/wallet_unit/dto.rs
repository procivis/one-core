use one_core::model::wallet_unit::{WalletProviderType, WalletUnitStatus};
use one_core::service::wallet_unit::dto::{
    HolderRefreshWalletUnitRequestDTO, HolderRegisterWalletUnitRequestDTO,
    HolderWalletUnitAttestationResponseDTO, WalletProviderDTO,
};
use one_dto_mapper::{From, Into};
use serde::{Deserialize, Serialize};
use shared_types::{KeyId, OrganisationId, WalletUnitAttestationId, WalletUnitId};
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::serialize::front_time;

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(HolderRegisterWalletUnitRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HolderRegisterWalletUnitRequestRestDTO {
    pub organisation_id: OrganisationId,
    pub wallet_provider: WalletProviderRestDTO,
    pub key: KeyId,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, ToSchema, Into, From)]
#[into(WalletProviderDTO)]
#[from(WalletProviderDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WalletProviderRestDTO {
    pub url: String,
    pub r#type: WalletProviderTypeRestEnum,
    pub name: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(HolderRefreshWalletUnitRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HolderRefreshWalletUnitRequestRestDTO {
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(HolderWalletUnitAttestationResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HolderWalletUnitAttestationResponseRestDTO {
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    pub id: WalletUnitAttestationId,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub expiration_date: OffsetDateTime,
    pub status: WalletUnitStatusRestEnum,
    pub attestation: String,
    pub wallet_unit_id: WalletUnitId,
    pub wallet_provider_url: String,
    pub wallet_provider_type: WalletProviderTypeRestEnum,
    pub wallet_provider_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, Into, From)]
#[into(WalletUnitStatus)]
#[from(WalletUnitStatus)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum WalletUnitStatusRestEnum {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into, From)]
#[into(WalletProviderType)]
#[from(WalletProviderType)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum WalletProviderTypeRestEnum {
    ProcivisOne,
}
