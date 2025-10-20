use one_core::model::wallet_unit::{WalletProviderType, WalletUnitOs, WalletUnitStatus};
use one_core::service::error::ServiceError;
use one_core::service::wallet_unit::dto::{
    HolderRefreshWalletUnitRequestDTO, HolderRegisterWalletUnitRequestDTO,
    HolderRegisterWalletUnitResponseDTO, HolderWalletUnitAttestationResponseDTO, WalletProviderDTO,
};
use one_dto_mapper::{From, Into, TryInto};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{KeyId, OrganisationId, WalletUnitAttestationId, WalletUnitId};
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::serialize::front_time;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, ToSchema, From, Into)]
#[from(WalletUnitOs)]
#[into(WalletUnitOs)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum WalletUnitOsRestEnum {
    Ios,
    Android,
    Web,
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

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T = HolderRegisterWalletUnitRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HolderRegisterWalletUnitRequestRestDTO {
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    #[try_into(infallible)]
    pub wallet_provider: WalletProviderRestDTO,
    #[try_into(infallible)]
    pub key_type: String,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into, From)]
#[into(WalletProviderDTO)]
#[from(WalletProviderDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WalletProviderRestDTO {
    pub url: String,
    pub r#type: WalletProviderTypeRestEnum,
    pub name: String,
    pub app_integrity_check_required: bool,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(HolderRegisterWalletUnitResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct HolderRegisterWalletUnitResponseRestDTO {
    pub id: WalletUnitId,
    pub key_id: KeyId,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T = HolderRefreshWalletUnitRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HolderRefreshWalletUnitRequestRestDTO {
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    #[try_into(infallible)]
    pub app_integrity_check_required: bool,
}

#[derive(Clone, Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HolderAttestationsQueryParams {
    #[param(nullable = false)]
    pub organisation_id: Option<OrganisationId>,
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
