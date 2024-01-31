use std::str::FromStr;

use dto_mapper::TryInto;
use one_core::{model::claim_schema::ClaimSchema, repository::error::DataLayerError};
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, TryInto)]
#[try_into(T = ClaimSchema, Error = DataLayerError)]
#[sea_orm(table_name = "claim_schema")]
pub struct Model {
    #[try_into(with_fn_ref = "uuid::Uuid::from_str")]
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[try_into(infallible)]
    pub key: String,

    #[try_into(infallible)]
    pub created_date: OffsetDateTime,
    #[try_into(infallible)]
    pub last_modified: OffsetDateTime,
    #[try_into(infallible, rename = "data_type")]
    pub datatype: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::claim::Entity")]
    Claim,
    #[sea_orm(has_one = "super::credential_schema_claim_schema::Entity")]
    CredentialSchemaClaimSchema,
    #[sea_orm(has_many = "super::proof_schema_claim_schema::Entity")]
    ProofSchemaClaimSchema,
}

impl Related<super::claim::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Claim.def()
    }
}

impl Related<super::credential_schema_claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialSchemaClaimSchema.def()
    }
}

impl Related<super::proof_schema_claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofSchemaClaimSchema.def()
    }
}

impl Related<super::credential_schema::Entity> for Entity {
    fn to() -> RelationDef {
        super::credential_schema_claim_schema::Relation::CredentialSchema.def()
    }
    fn via() -> Option<RelationDef> {
        Some(
            super::credential_schema_claim_schema::Relation::ClaimSchema
                .def()
                .rev(),
        )
    }
}

impl Related<super::proof_schema::Entity> for Entity {
    fn to() -> RelationDef {
        super::proof_schema_claim_schema::Relation::ProofSchema.def()
    }
    fn via() -> Option<RelationDef> {
        Some(
            super::proof_schema_claim_schema::Relation::ClaimSchema
                .def()
                .rev(),
        )
    }
}

impl ActiveModelBehavior for ActiveModel {}
