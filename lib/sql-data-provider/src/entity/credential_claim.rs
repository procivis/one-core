use sea_orm::entity::prelude::*;
use shared_types::{ClaimId, CredentialId};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "credential_claim")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub credential_id: CredentialId,
    #[sea_orm(primary_key, auto_increment = false)]
    pub claim_id: ClaimId,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::credential::Entity",
        from = "Column::CredentialId",
        to = "super::credential::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Credential,
    #[sea_orm(
        belongs_to = "super::claim::Entity",
        from = "Column::ClaimId",
        to = "super::claim::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Claim,
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

impl Related<super::claim::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Claim.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
