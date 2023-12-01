use std::str::FromStr;

use dto_mapper::TryInto;
use one_core::{model::organisation::Organisation, repository::error::DataLayerError};
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, TryInto)]
#[try_into(T = Organisation, Error = DataLayerError)]
#[sea_orm(table_name = "organisation")]
pub struct Model {
    #[try_into(with_fn_ref = "uuid::Uuid::from_str")]
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[try_into(infallible)]
    pub created_date: OffsetDateTime,
    #[try_into(infallible)]
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
