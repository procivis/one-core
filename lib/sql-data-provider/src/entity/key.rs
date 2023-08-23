use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "key")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub did_id: String,

    #[sea_orm(primary_key, auto_increment = false)]
    pub created_date: OffsetDateTime,

    pub last_modified: OffsetDateTime,

    pub public_key: String,
    pub private_key: String,
    pub storage_type: String,
    pub key_type: KeyType,

    pub credential_id: Option<String>,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::credential::Entity",
        from = "Column::CredentialId",
        to = "super::credential::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Credential,
    #[sea_orm(
        belongs_to = "super::did::Entity",
        from = "Column::DidId",
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

#[derive(Clone, Debug, Default, Eq, PartialEq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
pub enum KeyType {
    #[default]
    #[sea_orm(string_value = "RSA_4096")]
    Rsa4096,
    #[sea_orm(string_value = "ED25519")]
    Ed25519,
}
