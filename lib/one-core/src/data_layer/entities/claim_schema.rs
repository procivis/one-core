use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "claim_schema")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: Datatype,
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

#[derive(Clone, Debug, Default, Eq, PartialEq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
pub enum Datatype {
    #[default]
    #[sea_orm(string_value = "STRING")]
    String,
    #[sea_orm(string_value = "DATE")]
    Date,
    #[sea_orm(string_value = "NUMBER")]
    Number,
}
