use sea_orm::{
    ActiveModelBehavior, DeriveEntityModel, DerivePrimaryKey, DeriveRelation, EntityTrait,
    EnumIter, PrimaryKeyTrait, Related, RelationDef, RelationTrait,
};
use shared_types::{
    HolderWalletUnitId, KeyId, OrganisationId, WalletUnitAttestationId, WalletUnitId,
};
use time::OffsetDateTime;

use crate::entity::wallet_unit::{WalletProviderType, WalletUnitStatus};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "holder_wallet_unit")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: HolderWalletUnitId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub status: WalletUnitStatus,
    pub wallet_provider_name: String,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_url: String,
    pub provider_wallet_unit_id: WalletUnitId,
    pub organisation_id: OrganisationId,
    pub authentication_key_id: KeyId,
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
