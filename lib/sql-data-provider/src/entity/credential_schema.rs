use one_core::model;
use one_core::model::credential_schema::KeyStorageSecurity as ModelKeyStorageSecurity;
use one_dto_mapper::{From, Into, convert_inner};
use sea_orm::FromJsonQueryResult;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use shared_types::{CredentialSchemaId, OrganisationId};
use time::OffsetDateTime;

use crate::common::bool_from_int;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Deserialize)]
#[sea_orm(table_name = "credential_schema")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: CredentialSchemaId,
    pub deleted_at: Option<OffsetDateTime>,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub key_storage_security: Option<KeyStorageSecurity>,
    pub organisation_id: OrganisationId,
    #[sea_orm(column_type = "Text")]
    pub layout_type: LayoutType,
    #[sea_orm(column_type = "Json")]
    pub layout_properties: Option<LayoutProperties>,
    pub schema_id: String,
    pub imported_source_url: String,
    #[serde(deserialize_with = "bool_from_int")]
    pub allow_suspension: bool,
    #[serde(deserialize_with = "bool_from_int")]
    pub requires_app_attestation: bool,
}

#[derive(
    Copy, Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From, Deserialize,
)]
#[from(ModelKeyStorageSecurity)]
#[into(ModelKeyStorageSecurity)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyStorageSecurity {
    #[sea_orm(string_value = "HIGH")]
    High,
    #[sea_orm(string_value = "MODERATE")]
    Moderate,
    #[sea_orm(string_value = "ENHANCED_BASIC")]
    EnhancedBasic,
    #[sea_orm(string_value = "BASIC")]
    Basic,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, From, Into, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
#[from(model::credential_schema::LayoutType)]
#[into(model::credential_schema::LayoutType)]
pub enum LayoutType {
    #[sea_orm(string_value = "CARD")]
    Card,
    #[sea_orm(string_value = "DOCUMENT")]
    Document,
    #[sea_orm(string_value = "SINGLE_ATTRIBUTE")]
    SingleAttribute,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, FromJsonQueryResult, From, Into)]
#[from(model::credential_schema::LayoutProperties)]
#[into(model::credential_schema::LayoutProperties)]
pub struct LayoutProperties {
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub background: Option<BackgroundProperties>,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub logo: Option<LogoProperties>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub code: Option<CodeProperties>,
}

#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq, From, Into)]
#[from(model::credential_schema::BackgroundProperties)]
#[into(model::credential_schema::BackgroundProperties)]
pub struct BackgroundProperties {
    pub color: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq, From, Into)]
#[from(model::credential_schema::LogoProperties)]
#[into(model::credential_schema::LogoProperties)]
pub struct LogoProperties {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq, From, Into)]
#[from(model::credential_schema::CodeProperties)]
#[into(model::credential_schema::CodeProperties)]
pub struct CodeProperties {
    pub attribute: String,
    pub r#type: CodeTypeEnum,
}

#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq, From, Into)]
#[from(model::credential_schema::CodeTypeEnum)]
#[into(model::credential_schema::CodeTypeEnum)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CodeTypeEnum {
    Barcode,
    Mrz,
    QrCode,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::credential::Entity")]
    Credential,
    #[sea_orm(has_many = "super::claim_schema::Entity")]
    ClaimSchema,
    #[sea_orm(
        belongs_to = "super::organisation::Entity",
        from = "Column::OrganisationId",
        to = "super::organisation::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Organisation,
    #[sea_orm(has_many = "super::proof_input_schema::Entity")]
    ProofInputSchema,
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

impl Related<super::claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ClaimSchema.def()
    }
}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
}

impl Related<super::proof_input_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofInputSchema.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
