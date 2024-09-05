use dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use shared_types::DidId;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "revocation_list")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    #[sea_orm(column_type = "Binary(BlobSize::Blob(None))", nullable)]
    pub credentials: Vec<u8>,
    pub purpose: RevocationListPurpose,

    pub issuer_did_id: DidId,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::credential::Entity")]
    Credential,
    #[sea_orm(
        belongs_to = "super::did::Entity",
        from = "Column::IssuerDidId",
        to = "super::did::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Did,
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

impl Related<super::did::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Did.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(one_core::model::revocation_list::RevocationListPurpose)]
#[into(one_core::model::revocation_list::RevocationListPurpose)]
#[sea_orm(
    rs_type = "String",
    db_type = "Enum",
    enum_name = "revocation_list_purpose_enum"
)]
pub enum RevocationListPurpose {
    #[sea_orm(string_value = "REVOCATION")]
    Revocation,
    #[sea_orm(string_value = "SUSPENSION")]
    Suspension,
}
