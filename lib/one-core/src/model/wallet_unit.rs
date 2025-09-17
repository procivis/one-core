use one_dto_mapper::{From, Into};
use serde::{Deserialize, Serialize};
use shared_types::WalletUnitId;
use strum::{AsRefStr, Display};
use time::OffsetDateTime;

use super::common::GetListResponse;
use super::list_query::ListQuery;
use crate::config;
use crate::model::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use crate::model::organisation::{Organisation, OrganisationRelations};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletUnit {
    pub id: WalletUnitId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub os: WalletUnitOs,
    pub status: WalletUnitStatus,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,
    pub public_key: Option<String>,
    pub last_issuance: Option<OffsetDateTime>,
    pub nonce: Option<String>,

    // Relations:
    pub organisation: Option<Organisation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(ascii_case_insensitive, serialize_all = "UPPERCASE")]
pub enum WalletUnitOs {
    Ios,
    Android,
    Web,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletUnitStatus {
    Pending,
    Active,
    Revoked,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Display, AsRefStr, Into, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(config::core_config::WalletProviderType)]
#[from(config::core_config::WalletProviderType)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum WalletProviderType {
    ProcivisOne,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct WalletUnitRelations {
    pub organisation: Option<OrganisationRelations>,
}

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
    Os(Vec<WalletUnitOs>),
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
}

impl ListFilterValue for WalletUnitFilterValue {}

pub type WalletUnitListQuery = ListQuery<SortableWalletUnitColumn, WalletUnitFilterValue>;

pub type GetWalletUnitList = GetListResponse<WalletUnit>;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UpdateWalletUnitRequest {
    pub status: Option<WalletUnitStatus>,
    pub last_issuance: Option<OffsetDateTime>,
    pub public_key: Option<String>,
}
