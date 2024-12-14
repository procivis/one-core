use sea_orm::entity::prelude::*;
use shared_types::ProofId;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "proof")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: ProofId,

    pub requested_date: Option<OffsetDateTime>,
    pub completed_date: Option<OffsetDateTime>,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
