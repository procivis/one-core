use one_dto_mapper::Into;
use serde::{Deserialize, Serialize};
use shared_types::WalletUnitId;
use strum::{AsRefStr, Display};
use time::OffsetDateTime;

use super::common::GetListResponse;
use super::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use super::list_query::ListQuery;
use crate::config;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletUnit {
    pub id: WalletUnitId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub last_issuance: OffsetDateTime,
    pub name: String,
    pub os: String,
    pub status: WalletUnitStatus,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,
    pub public_key: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletUnitStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Display, AsRefStr, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(config::core_config::WalletProviderType)]
pub enum WalletProviderType {
    ProcivisOne,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct WalletUnitRelations {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableWalletUnitColumn {
    CreatedDate,
    LastModified,
    Name,
    Status,
    Os,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalletUnitFilterValue {
    Name(StringMatch),
    Ids(Vec<WalletUnitId>),
    Status(Vec<WalletUnitStatus>),
    WalletProviderType(Vec<String>),
    Os(Vec<String>),
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
}

impl ListFilterValue for WalletUnitFilterValue {}

pub type WalletUnitListQuery = ListQuery<SortableWalletUnitColumn, WalletUnitFilterValue>;

pub type GetWalletUnitList = GetListResponse<WalletUnit>;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UpdateWalletUnitRequest {
    pub status: Option<WalletUnitStatus>,
}
