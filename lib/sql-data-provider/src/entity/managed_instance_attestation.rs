use sea_orm::{
    ActiveModelBehavior, DeriveEntityModel, DerivePrimaryKey, DeriveRelation, EntityTrait,
    EnumIter, PrimaryKeyTrait, Related, RelationDef, RelationTrait,
};
use shared_types::{ManagedInstanceAttestationId, ManagedInstanceId, RevocationListEntryId};
use time::OffsetDateTime;

use crate::entity::wallet_instance_attestation::AttestationType;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "managed_instance_attestation")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: ManagedInstanceAttestationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiration_date: OffsetDateTime,
    pub attestation_content_hash: Option<String>,
    pub managed_instance_id: ManagedInstanceId,
    pub revocation_list_entry_id: Option<RevocationListEntryId>,
    pub r#type: AttestationType,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::managed_instance::Entity",
        from = "Column::ManagedInstanceId",
        to = "super::managed_instance::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    ManagedInstance,
    #[sea_orm(
        belongs_to = "super::revocation_list_entry::Entity",
        from = "Column::RevocationListEntryId",
        to = "super::revocation_list_entry::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    RevocationListEntry,
}

impl Related<super::managed_instance::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ManagedInstance.def()
    }
}

impl Related<super::revocation_list_entry::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RevocationListEntry.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
