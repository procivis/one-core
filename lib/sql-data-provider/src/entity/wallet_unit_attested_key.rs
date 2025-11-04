use one_core::model::wallet_unit_attested_key::WalletUnitAttestedKey;
use one_core::repository::error::DataLayerError;
use sea_orm::{
    ActiveModelBehavior, DeriveEntityModel, DerivePrimaryKey, DeriveRelation, EntityTrait,
    EnumIter, PrimaryKeyTrait, Related, RelationDef, RelationTrait, Set,
};
use shared_types::{WalletUnitAttestedKeyId, WalletUnitId};
use time::OffsetDateTime;

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
    pub revocation_list_entry_id: Option<String>,
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
        belongs_to = "super::revocation_list_entry::Entity",
        from = "Column::RevocationListEntryId",
        to = "super::revocation_list_entry::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    RevocationListEntry,
}

impl Related<super::wallet_unit::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::WalletUnit.def()
    }
}

impl Related<super::revocation_list_entry::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RevocationListEntry.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
