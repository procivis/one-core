use one_core::model::localized_text::{
    LocalizedTextEntityType as ModelEntityType, LocalizedTextField as ModelField,
};
use one_dto_mapper::{From, Into};
use sea_orm::prelude::*;
use sea_orm::{
    ActiveModelBehavior, DeriveActiveEnum, DeriveEntityModel, DerivePrimaryKey, EnumIter,
};
use shared_types::EntityId;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "localized_text")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub entity_id: EntityId,
    #[sea_orm(primary_key)]
    pub lang: String,
    #[sea_orm(primary_key)]
    pub field: LocalizedTextField,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub value: String,
    pub entity_type: LocalizedTextEntityType,
}

impl ActiveModelBehavior for ActiveModel {}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(ModelField)]
#[into(ModelField)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum LocalizedTextField {
    #[sea_orm(string_value = "NAME")]
    Name,
    #[sea_orm(string_value = "DESCRIPTION")]
    Description,
    #[sea_orm(string_value = "LOGO_ALT_TEXT")]
    LogoAltText,
}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(ModelEntityType)]
#[into(ModelEntityType)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum LocalizedTextEntityType {
    #[sea_orm(string_value = "CREDENTIAL_SCHEMA")]
    CredentialSchema,
    #[sea_orm(string_value = "CLAIM_SCHEMA")]
    ClaimSchema,
    #[sea_orm(string_value = "IDENTIFIER")]
    Identifier,
}
