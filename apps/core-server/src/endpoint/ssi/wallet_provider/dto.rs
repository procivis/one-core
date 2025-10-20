use one_core::service::wallet_provider::dto;
use one_dto_mapper::{From, Into, convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use serde_with::{OneOrMany, serde_as};
use shared_types::WalletUnitId;
use utoipa::ToSchema;

use crate::deserialize::one_or_many;
use crate::endpoint::ssi::dto::PublicKeyJwkRestDTO;
use crate::endpoint::wallet_unit::dto::WalletUnitOsRestEnum;

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::RefreshWalletUnitRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RefreshWalletUnitRequestRestDTO {
    pub proof: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(dto::RefreshWalletUnitResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RefreshWalletUnitResponseRestDTO {
    pub id: WalletUnitId,
    pub attestation: String,
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
    pub proof: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(dto::WalletUnitActivationResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WalletUnitActivationResponseRestDTO {
    pub attestation: String,
}
