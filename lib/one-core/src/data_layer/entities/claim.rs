use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "claim")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub claim_schema_id: String,

    #[sea_orm(primary_key, auto_increment = false)]
    pub credential_id: String,

    // #[sea_orm(primary_key, auto_increment = false)]
    // pub proof_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub value: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
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
    // #[sea_orm(
    //     belongs_to = "super::proof::Entity",
    //     from = "Column::ProofId",
    //     to = "super::proof::Column::Id",
    //     on_update = "Restrict",
    //     on_delete = "Restrict"
    // )]
    // Proof,
}

impl Related<super::claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ClaimSchema.def()
    }
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

// impl Related<super::proof::Entity> for Entity {
//     fn to() -> RelationDef {
//         Relation::Proof.def()
//     }
// }
