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

    pub credential_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::credential_schema::Entity",
        from = "Column::CredentialId",
        to = "super::credential_schema::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    CredentialSchema,
}

impl Related<super::credential_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialSchema.def()
    }
}

impl Related<super::proof_schema::Entity> for Entity {
    fn to() -> RelationDef {
        super::proof_schema_claim::Relation::ProofSchema.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::proof_schema_claim::Relation::ClaimSchema.def().rev())
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
