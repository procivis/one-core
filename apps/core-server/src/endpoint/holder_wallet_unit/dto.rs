use one_core::service::error::ServiceError;
use one_core::service::wallet_unit::dto;
use one_dto_mapper::{From, Into, TryInto};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::OrganisationId;
use utoipa::ToSchema;

use crate::dto::mapper::fallback_organisation_id_from_session;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T = dto::HolderRegisterWalletUnitRequestDTO, Error = ServiceError)]
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
#[into(dto::WalletProviderDTO)]
#[from(dto::WalletProviderDTO)]
#[serde(rename_all = "camelCase")]
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
