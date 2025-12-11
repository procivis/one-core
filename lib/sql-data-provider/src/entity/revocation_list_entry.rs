use one_core::model::revocation_list;
use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use shared_types::{CredentialId, DidId, IdentifierId, RevocationListId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "revocation_list_entry")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub created_date: OffsetDateTime,
    pub revocation_list_id: RevocationListId,
    pub index: u32,
    pub credential_id: Option<CredentialId>,
    pub r#type: RevocationListEntryType,
    pub status: RevocationListEntryStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum RevocationListEntryType {
    #[sea_orm(string_value = "CREDENTIAL")]
    Credential,
    #[sea_orm(string_value = "WUA")]
    WalletUnitAttestedKey,
    #[sea_orm(string_value = "SIGNATURE")]
    Signature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, From, Into)]
#[from(revocation_list::RevocationListEntryStatus)]
#[into(revocation_list::RevocationListEntryStatus)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum RevocationListEntryStatus {
    #[sea_orm(string_value = "ACTIVE")]
    Active,
    #[sea_orm(string_value = "SUSPENDED")]
    Suspended,
    #[sea_orm(string_value = "REVOKED")]
    Revoked,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::revocation_list::Entity",
        from = "Column::RevocationListId",
        to = "super::revocation_list::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    RevocationList,
    #[sea_orm(
        belongs_to = "super::credential::Entity",
        from = "Column::CredentialId",
        to = "super::credential::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Credential,
    #[sea_orm(has_one = "super::wallet_unit_attested_key::Entity")]
    WalletUnitAttestedKey,
}

impl Related<super::revocation_list::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RevocationList.def()
    }
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

impl Related<super::wallet_unit_attested_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::WalletUnitAttestedKey.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
