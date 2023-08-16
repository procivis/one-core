//! `SeaORM` Entity. Generated by sea-orm-codegen 0.12.0-rc.3

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "credential_claim")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub claim_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub credential_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::claim::Entity",
        from = "Column::ClaimId",
        to = "super::claim::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Claim,
    #[sea_orm(
        belongs_to = "super::credential::Entity",
        from = "Column::CredentialId",
        to = "super::credential::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Credential,
}

impl Related<super::claim::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Claim.def()
    }
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
