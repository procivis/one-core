use sea_orm::entity::prelude::*;
use shared_types::{InteractionId, NonceId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "used_nonce")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: NonceId,
    pub created_date: OffsetDateTime,
    pub interaction_id: InteractionId,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::interaction::Entity",
        from = "Column::InteractionId",
        to = "super::interaction::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Interaction,
}

impl Related<super::interaction::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Interaction.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
