use sea_orm::entity::prelude::*;
use serde::Deserialize;
use shared_types::{ClaimId, ClaimSchemaId, CredentialId};
use time::OffsetDateTime;

use crate::common::opt_hex;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Deserialize)]
#[sea_orm(table_name = "claim")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: ClaimId,

    pub claim_schema_id: ClaimSchemaId,
    pub credential_id: CredentialId,

    #[serde(deserialize_with = "opt_hex")]
    #[sea_orm(column_type = "Blob")]
    pub value: Option<Vec<u8>>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub path: String,
}

impl ActiveModelBehavior for ActiveModel {}

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
        belongs_to = "super::credential::Entity",
        from = "Column::CredentialId",
        to = "super::credential::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Credential,
    #[sea_orm(has_one = "super::proof_claim::Entity")]
    ProofClaim,
}

impl Related<super::claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ClaimSchema.def()
    }
}

impl Related<super::proof_claim::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofClaim.def()
    }
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

impl Related<super::proof::Entity> for Entity {
    fn to() -> RelationDef {
        super::proof_claim::Relation::Proof.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::proof_claim::Relation::Claim.def().rev())
    }
}
