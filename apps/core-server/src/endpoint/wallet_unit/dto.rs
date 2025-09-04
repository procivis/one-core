use one_core::model::wallet_unit::{
    SortableWalletUnitColumn, WalletProviderType, WalletUnitStatus,
};
use one_core::service::wallet_unit::dto::{
    GetWalletUnitListResponseDTO, GetWalletUnitResponseDTO, HolderRefreshWalletUnitRequestDTO,
    HolderRegisterWalletUnitRequestDTO, HolderWalletUnitAttestationResponseDTO, WalletProviderDTO,
};
use one_dto_mapper::{From, Into, convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{KeyId, OrganisationId, WalletUnitAttestationId, WalletUnitId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::dto::common::ListQueryParamsRest;
use crate::serialize::{front_time, front_time_option};

pub(crate) type ListWalletUnitsQuery =
    ListQueryParamsRest<WalletUnitFilterQueryParamsRestDTO, SortableWalletUnitColumnRest>;

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetWalletUnitListResponseDTO)]
pub(crate) struct GetWalletUnitsResponseRestDTO {
    pub total_pages: u64,
    pub total_items: u64,
    #[from(with_fn = convert_inner)]
    pub values: Vec<WalletUnitResponseRestDTO>,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetWalletUnitResponseDTO)]
pub(crate) struct WalletUnitResponseRestDTO {
    pub id: WalletUnitId,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time_option")]
    pub last_issuance: Option<OffsetDateTime>,
    pub name: String,
    pub os: String,
    pub status: WalletUnitStatusRestEnum,
    pub wallet_provider_type: WalletProviderTypeRestEnum,
    pub wallet_provider_name: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, ToSchema, From, Into)]
#[from(WalletUnitStatus)]
#[into(WalletUnitStatus)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum WalletUnitStatusRestEnum {
    Active,
    Revoked,
    Pending,
    Error,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From, Into)]
#[from(WalletProviderType)]
#[into(WalletProviderType)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum WalletProviderTypeRestEnum {
    ProcivisOne,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WalletUnitFilterQueryParamsRestDTO {
    /// Return only wallet units with a name starting with this string.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Filter by specific wallet unit UUIDs.
    #[param(rename = "ids[]", inline, nullable = false)]
    pub ids: Option<Vec<WalletUnitId>>,
    /// Return only wallet units with the specified status.
    #[param(rename = "status[]", inline, nullable = false)]
    pub status: Option<Vec<WalletUnitStatusRestEnum>>,
    /// Return only wallet units with the specified OS.
    #[param(rename = "os[]", inline, nullable = false)]
    pub os: Option<Vec<String>>,
    /// Return only wallet units with the specified wallet provider type.
    #[param(rename = "walletProviderType[]", inline, nullable = false)]
    pub wallet_provider_type: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From, Into)]
#[serde(rename_all = "camelCase")]
#[from(SortableWalletUnitColumn)]
#[into(SortableWalletUnitColumn)]
pub(crate) enum SortableWalletUnitColumnRest {
    CreatedDate,
    LastModified,
    Name,
    Status,
    Os,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(HolderRegisterWalletUnitRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HolderRegisterWalletUnitRequestRestDTO {
    pub organisation_id: OrganisationId,
    pub wallet_provider: WalletProviderRestDTO,
    pub key_id: KeyId,
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

#[derive(Clone, Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HolderAttestationsQueryParams {
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
