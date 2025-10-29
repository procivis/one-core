use one_core::model::wallet_unit_attested_key::WalletUnitAttestedKey;
use one_core::repository::error::DataLayerError;
use sea_orm::{
    ActiveModelBehavior, DeriveEntityModel, DerivePrimaryKey, DeriveRelation, EntityTrait,
    EnumIter, PrimaryKeyTrait, Related, RelationDef, RelationTrait, Set,
};
use shared_types::{WalletUnitAttestedKeyId, WalletUnitId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::entity::wallet_unit_attested_key;
use crate::entity::wallet_unit_attested_key::Relation::{RevocationList, WalletUnit};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "wallet_unit_attested_key")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: WalletUnitAttestedKeyId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiration_date: OffsetDateTime,
    pub public_key_jwk: String,
    pub wallet_unit_id: WalletUnitId,
    pub revocation_list_id: Option<Uuid>,
    pub revocation_list_index: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::wallet_unit::Entity",
        from = "Column::WalletUnitId",
        to = "super::wallet_unit::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    WalletUnit,
    #[sea_orm(
        belongs_to = "super::revocation_list::Entity",
        from = "Column::RevocationListId",
        to = "super::revocation_list::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    RevocationList,
}

impl Related<super::wallet_unit::Entity> for Entity {
    fn to() -> RelationDef {
        WalletUnit.def()
    }
}

impl Related<super::revocation_list::Entity> for Entity {
    fn to() -> RelationDef {
        RevocationList.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
