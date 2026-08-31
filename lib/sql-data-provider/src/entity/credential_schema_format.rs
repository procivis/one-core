use sea_orm::entity::prelude::*;
use serde::Deserialize;
use shared_types::{CredentialFormat, CredentialSchemaFormatId, CredentialSchemaId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Deserialize)]
#[sea_orm(table_name = "credential_schema_format")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: CredentialSchemaFormatId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub credential_schema_id: CredentialSchemaId,
    pub format: CredentialFormat,
    pub ecosystem_schema_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::credential_schema::Entity",
        from = "Column::CredentialSchemaId",
        to = "super::credential_schema::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    CredentialSchema,
    #[sea_orm(has_many = "super::credential_schema_format_claim_schema::Entity")]
    CredentialSchemaFormatClaimSchema,
}

impl Related<super::credential_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialSchema.def()
    }
}

impl Related<super::credential_schema_format_claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialSchemaFormatClaimSchema.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
