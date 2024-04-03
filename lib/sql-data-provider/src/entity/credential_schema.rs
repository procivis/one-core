use dto_mapper::{convert_inner, From, Into};
use one_core::model::{
    self, credential_schema::WalletStorageTypeEnum as ModelWalletStorageTypeEnum,
};
use sea_orm::{entity::prelude::*, FromJsonQueryResult};
use serde::{Deserialize, Serialize};
use shared_types::OrganisationId;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "credential_schema")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub deleted_at: Option<OffsetDateTime>,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub wallet_storage_type: Option<WalletStorageType>,
    pub organisation_id: OrganisationId,
    #[sea_orm(column_type = "Text")]
    pub layout_type: LayoutType,
    #[sea_orm(column_type = "Json")]
    pub layout_properties: Option<LayoutProperties>,
    pub schema_type: CredentialSchemaType,
    pub schema_id: String,
}

#[derive(Debug, Clone, EnumIter, DeriveActiveEnum, From, Into, PartialEq, Eq)]
#[sea_orm(rs_type = "String", db_type = "String(Some(1))")]
#[from(model::credential_schema::CredentialSchemaType)]
#[into(model::credential_schema::CredentialSchemaType)]
pub enum CredentialSchemaType {
    #[sea_orm(string_value = "ProcivisOneSchema2024")]
    ProcivisOneSchema2024,

    #[sea_orm(string_value = "FallbackSchema2024")]
    FallbackSchema2024,
}

#[derive(
    Copy, Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From, Deserialize,
)]
#[from(ModelWalletStorageTypeEnum)]
#[into(ModelWalletStorageTypeEnum)]
#[sea_orm(
    rs_type = "String",
    db_type = "Enum",
    enum_name = "wallet_storage_type"
)]
#[serde(rename_all = "UPPERCASE")]
pub enum WalletStorageType {
    #[sea_orm(string_value = "HARDWARE")]
    Hardware,
    #[sea_orm(string_value = "SOFTWARE")]
    Software,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, From, Into)]
#[sea_orm(
    rs_type = "String",
    db_type = "Enum",
    enum_name = "credential_schema_layout_type_enum"
)]
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
    #[sea_orm(has_many = "super::credential_schema_claim_schema::Entity")]
    CredentialSchemaClaimSchema,
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

impl Related<super::credential_schema_claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialSchemaClaimSchema.def()
    }
}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
}

impl Related<super::claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        super::credential_schema_claim_schema::Relation::ClaimSchema.def()
    }
    fn via() -> Option<RelationDef> {
        Some(
            super::credential_schema_claim_schema::Relation::CredentialSchema
                .def()
                .rev(),
        )
    }
}

impl Related<super::proof_input_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofInputSchema.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
