use anyhow::anyhow;
use one_core::model::organisation::Organisation;
use one_core::model::wallet_unit::{WalletUnit, WalletUnitStatus as ModelWalletUnitStatus};
use one_core::repository::error::DataLayerError;
use one_dto_mapper::{From, Into};
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::Deserialize;
use shared_types::{OrganisationId, WalletUnitId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "wallet_unit")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: WalletUnitId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub last_issuance: Option<OffsetDateTime>,
    pub name: String,
    pub os: WalletUnitOs,
    pub status: WalletUnitStatus,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,
    pub authentication_key_jwk: Option<String>,
    pub nonce: Option<String>,
    pub organisation_id: OrganisationId,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::organisation::Entity",
        from = "Column::OrganisationId",
        to = "super::organisation::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Organisation,
    #[sea_orm(has_many = "super::wallet_unit_attested_key::Entity")]
    WalletUnitAttestedKey,
}
impl ActiveModelBehavior for ActiveModel {}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
}

impl Related<super::wallet_unit_attested_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::WalletUnitAttestedKey.def()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From, Deserialize)]
#[from(one_core::model::wallet_unit::WalletUnitOs)]
#[into(one_core::model::wallet_unit::WalletUnitOs)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum WalletUnitOs {
    #[sea_orm(string_value = "IOS")]
    Ios,
    #[sea_orm(string_value = "ANDROID")]
    Android,
    #[sea_orm(string_value = "WEB")]
    Web,
}

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

impl TryFrom<WalletUnit> for ActiveModel {
    type Error = DataLayerError;
    fn try_from(wallet_unit: WalletUnit) -> Result<Self, Self::Error> {
        let authentication_key_jwk = wallet_unit
            .authentication_key_jwk
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| DataLayerError::MappingError)?;
        Ok(Self {
            id: Set(wallet_unit.id),
            created_date: Set(wallet_unit.created_date),
            last_modified: Set(wallet_unit.last_modified),
            last_issuance: Set(wallet_unit.last_issuance),
            name: Set(wallet_unit.name),
            os: Set(wallet_unit.os.into()),
            status: Set(wallet_unit.status.into()),
            wallet_provider_type: Set(wallet_unit.wallet_provider_type.into()),
            wallet_provider_name: Set(wallet_unit.wallet_provider_name),
            authentication_key_jwk: Set(authentication_key_jwk),
            nonce: Set(wallet_unit.nonce),
            organisation_id: Set(wallet_unit
                .organisation
                .as_ref()
                .ok_or(DataLayerError::Db(anyhow!(
                    "Missing organisation for wallet unit {}",
                    wallet_unit.id
                )))?
                .id),
        })
    }
}
