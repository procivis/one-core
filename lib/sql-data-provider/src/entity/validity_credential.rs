use anyhow::Context;
use one_core::model;
use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::StringLen;
use sea_orm::prelude::{
    ActiveModelBehavior, DeriveEntityModel, DerivePrimaryKey, DeriveRelation, EntityTrait,
    EnumIter, PrimaryKeyTrait, Related, RelationDef, RelationTrait,
};
use sea_orm::DeriveActiveEnum;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "validity_credential")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub created_date: OffsetDateTime,
    #[sea_orm(column_type = "Blob")]
    pub credential: Vec<u8>,
    pub credential_id: String,
    pub r#type: ValidityCredentialType,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, From, Into)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
#[from("model::validity_credential::ValidityCredentialType")]
#[into("model::validity_credential::ValidityCredentialType")]
pub enum ValidityCredentialType {
    #[sea_orm(string_value = "LVVC")]
    Lvvc,
    #[sea_orm(string_value = "MDOC")]
    Mdoc,
}

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
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
