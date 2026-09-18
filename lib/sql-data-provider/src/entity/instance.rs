use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use sea_orm::{
    ActiveModelBehavior, DeriveActiveEnum, DeriveEntityModel, DerivePrimaryKey, DeriveRelation,
    EntityTrait, EnumIter, PrimaryKeyTrait, Related, RelationDef, RelationTrait,
};
use serde::Deserialize;
use shared_types::{InstanceId, KeyId, ManagedInstanceId, OrganisationId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "instance")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: InstanceId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub status: InstanceStatus,
    pub provider_name: String,
    pub provider_type: WalletProviderType,
    pub provider_url: String,
    pub provider_instance_id: ManagedInstanceId,
    pub authentication_key_id: Option<KeyId>,
    pub organisation_id: OrganisationId,
    pub role: InstanceRole,
    pub nonce: Option<String>,
    pub user_nonce: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From, Deserialize)]
#[from(one_core::model::instance::WalletProviderType)]
#[into(one_core::model::instance::WalletProviderType)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum WalletProviderType {
    #[sea_orm(string_value = "PROCIVIS_ONE")]
    ProcivisOne,
}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From, Deserialize)]
#[from(one_core::model::instance::InstanceStatus)]
#[into(one_core::model::instance::InstanceStatus)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum InstanceStatus {
    #[sea_orm(string_value = "ACTIVE")]
    Active,
    #[sea_orm(string_value = "REVOKED")]
    Revoked,
    #[sea_orm(string_value = "PENDING")]
    Pending,
    #[sea_orm(string_value = "UNATTESTED")]
    Unattested,
    #[sea_orm(string_value = "ERROR")]
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From, Deserialize)]
#[from(one_core::model::instance::InstanceRole)]
#[into(one_core::model::instance::InstanceRole)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum InstanceRole {
    #[sea_orm(string_value = "WALLET")]
    Wallet,
    #[sea_orm(string_value = "VERIFIER")]
    Verifier,
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
    #[sea_orm(
        belongs_to = "super::key::Entity",
        from = "Column::AuthenticationKeyId",
        to = "super::key::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    AuthenticationKey,
}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
}

impl Related<super::key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AuthenticationKey.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
