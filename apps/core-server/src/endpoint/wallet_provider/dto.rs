use one_core::model::wallet_unit::SortableWalletUnitColumn;
use one_core::service::wallet_provider::dto;
use one_core::service::wallet_unit::dto::{WalletProviderType, WalletUnitOs, WalletUnitStatus};
use one_dto_mapper::{From, Into, convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{OrganisationId, WalletUnitId};
use standardized_types::jwk::PublicJwk;
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::ListQueryParamsRest;
use crate::serialize::{front_time, front_time_option};
pub(crate) type ListWalletUnitsQuery =
    ListQueryParamsRest<WalletUnitFilterQueryParamsRestDTO, SortableWalletUnitColumnRest>;

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::GetWalletUnitListResponseDTO)]
pub(crate) struct GetWalletUnitsResponseRestDTO {
    pub total_pages: u64,
    pub total_items: u64,
    #[from(with_fn = convert_inner)]
    pub values: Vec<WalletUnitResponseRestDTO>,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::GetWalletUnitResponseDTO)]
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
    pub os: WalletUnitOsRestEnum,
    pub status: WalletUnitStatusRestEnum,
    pub wallet_provider_type: WalletProviderTypeRestEnum,
    pub wallet_provider_name: String,
    #[from(with_fn = convert_inner)]
    pub authentication_key_jwk: Option<PublicJwk>,
}

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

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside ListWalletUnitsQuery
pub(crate) struct WalletUnitFilterQueryParamsRestDTO {
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[param(nullable = false)]
    pub organisation_id: Option<OrganisationId>,
    /// Return only wallet units with a name starting with this string.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Filter by specific wallet unit UUIDs.
    #[param(rename = "ids[]", inline, nullable = false)]
    pub ids: Option<Vec<WalletUnitId>>,
    /// Return only wallet units with the specified status.
    #[param(rename = "status[]", inline, nullable = false)]
    pub status: Option<Vec<WalletUnitStatusRestEnum>>,
    /// Return only wallet units with the specified operating systems.
    #[param(rename = "os[]", inline, nullable = false)]
    pub os: Option<Vec<WalletUnitOsRestEnum>>,
    /// Return only wallet units with the specified wallet provider types.
    #[param(rename = "walletProviderType[]", inline, nullable = false)]
    pub wallet_provider_type: Option<Vec<String>>,
    /// Return only the wallet unit with the specified attestation.
    #[param(rename = "attestation", inline, nullable = false)]
    pub attestation: Option<String>,
    /// Return only wallet units created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only wallet units created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_before: Option<OffsetDateTime>,
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
