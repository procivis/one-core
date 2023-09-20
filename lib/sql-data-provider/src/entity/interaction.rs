use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "interaction")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub host: Option<String>,
    #[sea_orm(column_type = "Binary(BlobSize::Blob(None))", nullable)]
    pub data: Option<Vec<u8>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::credential::Entity")]
    Credential,
    #[sea_orm(has_many = "super::proof::Entity")]
    Proof,
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

impl Related<super::proof::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Proof.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
