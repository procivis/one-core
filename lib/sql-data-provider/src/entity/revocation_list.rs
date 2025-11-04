use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use shared_types::{DidId, IdentifierId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "revocation_list")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    #[sea_orm(column_type = "Blob")]
    pub credentials: Vec<u8>,
    pub purpose: RevocationListPurpose,
    pub format: RevocationListFormat,
    pub r#type: String,

    pub issuer_identifier_id: IdentifierId,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::revocation_list_entry::Entity")]
    RevocationListEntry,
    #[sea_orm(
        belongs_to = "super::identifier::Entity",
        from = "Column::IssuerIdentifierId",
        to = "super::identifier::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Identifier,
}

impl Related<super::revocation_list_entry::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RevocationListEntry.def()
    }
}

impl Related<super::did::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Identifier.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(one_core::model::revocation_list::RevocationListPurpose)]
#[into(one_core::model::revocation_list::RevocationListPurpose)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum RevocationListPurpose {
    #[sea_orm(string_value = "REVOCATION")]
    Revocation,
    #[sea_orm(string_value = "SUSPENSION")]
    Suspension,
}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(one_core::model::revocation_list::StatusListCredentialFormat)]
#[into(one_core::model::revocation_list::StatusListCredentialFormat)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum RevocationListFormat {
    #[sea_orm(string_value = "JWT")]
    Jwt,
    #[sea_orm(string_value = "JSON_LD_CLASSIC")]
    JsonLdClassic,
}
