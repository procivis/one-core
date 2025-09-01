use one_core::model::wallet_unit::{WalletUnit, WalletUnitStatus as ModelWalletUnitStatus};
use one_dto_mapper::{From, Into};
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::Deserialize;
use shared_types::WalletUnitId;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Into)]
#[into(WalletUnit)]
#[sea_orm(table_name = "wallet_unit")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: WalletUnitId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub last_issuance: Option<OffsetDateTime>,
    pub name: String,
    pub os: String,
    pub status: WalletUnitStatus,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,
    pub public_key: String,
    pub nonce: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From, Deserialize)]
#[from(one_core::model::wallet_unit::WalletUnitStatus)]
#[into(one_core::model::wallet_unit::WalletUnitStatus)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum WalletUnitStatus {
    #[sea_orm(string_value = "ACTIVE")]
    Active,
    #[sea_orm(string_value = "REVOKED")]
    Revoked,
    #[sea_orm(string_value = "PENDING")]
    Pending,
    #[sea_orm(string_value = "ERROR")]
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From, Deserialize)]
#[from(one_core::model::wallet_unit::WalletProviderType)]
#[into(one_core::model::wallet_unit::WalletProviderType)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum WalletProviderType {
    #[sea_orm(string_value = "PROCIVIS_ONE")]
    ProcivisOne,
}

impl From<WalletUnit> for ActiveModel {
    fn from(wallet_unit: WalletUnit) -> Self {
        Self {
            id: Set(wallet_unit.id),
            created_date: Set(wallet_unit.created_date),
            last_modified: Set(wallet_unit.last_modified),
            last_issuance: Set(wallet_unit.last_issuance),
            name: Set(wallet_unit.name),
            os: Set(wallet_unit.os),
            status: Set(wallet_unit.status.into()),
            wallet_provider_type: Set(wallet_unit.wallet_provider_type.into()),
            wallet_provider_name: Set(wallet_unit.wallet_provider_name),
            public_key: Set(wallet_unit.public_key),
            nonce: Set(wallet_unit.nonce),
        }
    }
}
