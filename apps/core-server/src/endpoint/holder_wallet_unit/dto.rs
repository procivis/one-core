use one_core::service::error::ServiceError;
use one_core::service::wallet_unit::dto;
use one_dto_mapper::{From, Into, TryFrom, TryInto};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{HolderWalletUnitId, OrganisationId, WalletUnitId};
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::key::dto::KeyListItemResponseRestDTO;
use crate::endpoint::wallet_provider::dto::WalletUnitStatusRestEnum;
use crate::mapper::MapperError;
use crate::serialize::front_time;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T = dto::HolderRegisterWalletUnitRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HolderRegisterWalletUnitRequestRestDTO {
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Reference the `walletProvider` configuration of the Wallet Provider.
    #[try_into(infallible)]
    pub wallet_provider: WalletProviderRestDTO,
    #[try_into(infallible)]
    pub key_type: String,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into, From)]
#[into(dto::WalletProviderDTO)]
#[from(dto::WalletProviderDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WalletProviderRestDTO {
    pub url: String,
    pub r#type: WalletProviderTypeRestEnum,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From, Into)]
#[from(dto::WalletProviderType)]
#[into(dto::WalletProviderType)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum WalletProviderTypeRestEnum {
    ProcivisOne,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, TryFrom)]
#[try_from(T = dto::HolderWalletUnitResponseDTO, Error = MapperError)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HolderWalletUnitDetailRestDTO {
    #[try_from(infallible)]
    pub id: HolderWalletUnitId,
    #[serde(serialize_with = "front_time")]
    #[try_from(infallible)]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[try_from(infallible)]
    pub last_modified: OffsetDateTime,
    #[try_from(infallible)]
    pub provider_wallet_unit_id: WalletUnitId,
    #[try_from(infallible)]
    pub wallet_provider_url: String,
    #[try_from(infallible)]
    pub wallet_provider_type: WalletProviderTypeRestEnum,
    #[try_from(infallible)]
    pub wallet_provider_name: String,
    #[try_from(infallible)]
    pub status: WalletUnitStatusRestEnum,
    pub authentication_key: KeyListItemResponseRestDTO,
}
