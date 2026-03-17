use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use shared_types::{TrustCollectionId, TrustListSubscriberId, TrustListSubscriptionId};
use time::OffsetDateTime;

use crate::entity::trust_list_publication::TrustRoleEnum;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "trust_list_subscription")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: TrustListSubscriptionId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
    #[sea_orm(column_name = "type")]
    pub r#type: TrustListSubscriberId,
    pub reference: String,
    pub role: TrustRoleEnum,
    pub state: TrustListSubscriptionState,

    pub trust_collection_id: TrustCollectionId,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::trust_collection::Entity",
        from = "Column::TrustCollectionId",
        to = "super::trust_collection::Column::Id"
    )]
    TrustCollection,
}

impl Related<super::trust_collection::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::TrustCollection.def()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(one_core::model::trust_list_subscription::TrustListSubscriptionState)]
#[into(one_core::model::trust_list_subscription::TrustListSubscriptionState)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum TrustListSubscriptionState {
    #[sea_orm(string_value = "ACTIVE")]
    Active,
    #[sea_orm(string_value = "ERROR")]
    Error,
}
