use std::str::FromStr;

use one_core::model::claim_schema::ClaimSchema;
use one_core::repository::error::DataLayerError;
use one_dto_mapper::Into;
use sea_orm::entity::prelude::*;
use serde::Deserialize;
use shared_types::ClaimSchemaId;
use time::OffsetDateTime;

use crate::common::bool_from_int;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Into, Deserialize)]
#[into(ClaimSchema)]
#[sea_orm(table_name = "claim_schema")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: ClaimSchemaId,
    pub key: String,

    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    #[into(rename = "data_type")]
    pub datatype: String,
    #[serde(deserialize_with = "bool_from_int")]
    pub array: bool,
    #[serde(deserialize_with = "bool_from_int")]
    pub metadata: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::claim::Entity")]
    Claim,
    #[sea_orm(has_one = "super::credential_schema_claim_schema::Entity")]
    CredentialSchemaClaimSchema,
    #[sea_orm(has_many = "super::proof_input_claim_schema::Entity")]
    ProofInputClaimSchema,
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

impl Related<super::proof_input_claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofInputClaimSchema.def()
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

impl Related<super::proof_input_schema::Entity> for Entity {
    fn to() -> RelationDef {
        super::proof_input_claim_schema::Relation::ProofInputSchema.def()
    }
    fn via() -> Option<RelationDef> {
        Some(
            super::proof_input_claim_schema::Relation::ClaimSchema
                .def()
                .rev(),
        )
    }
}

impl ActiveModelBehavior for ActiveModel {}
