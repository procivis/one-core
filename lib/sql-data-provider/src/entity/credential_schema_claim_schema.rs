use sea_orm::entity::prelude::*;
use serde::Deserialize;
use shared_types::ClaimSchemaId;

use crate::common::bool_from_int;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Deserialize)]
#[sea_orm(table_name = "credential_schema_claim_schema")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub claim_schema_id: ClaimSchemaId,

    pub credential_schema_id: String,
    #[serde(deserialize_with = "bool_from_int")]
    pub required: bool,
    pub order: u32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::claim_schema::Entity",
        from = "Column::ClaimSchemaId",
        to = "super::claim_schema::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    ClaimSchema,
    #[sea_orm(
        belongs_to = "super::credential_schema::Entity",
        from = "Column::CredentialSchemaId",
        to = "super::credential_schema::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    CredentialSchema,
}

impl Related<super::claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ClaimSchema.def()
    }
}

impl Related<super::credential_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialSchema.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
