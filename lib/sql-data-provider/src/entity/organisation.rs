use std::str::FromStr;

use dto_mapper::Into;
use one_core::model::organisation::Organisation;
use one_core::repository::error::DataLayerError;
use sea_orm::entity::prelude::*;
use shared_types::OrganisationId;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Into)]
#[into(Organisation)]
#[sea_orm(table_name = "organisation")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::credential_schema::Entity")]
    CredentialSchema,
    #[sea_orm(has_many = "super::did::Entity")]
    Did,
    #[sea_orm(has_many = "super::proof_schema::Entity")]
    ProofSchema,
}

impl Related<super::credential_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialSchema.def()
    }
}

impl Related<super::did::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Did.def()
    }
}

impl Related<super::proof_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofSchema.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
