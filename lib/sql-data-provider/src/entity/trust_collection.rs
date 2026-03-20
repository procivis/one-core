use sea_orm::entity::prelude::*;
use shared_types::{OrganisationId, TrustCollectionId};
use time::OffsetDateTime;
use url::Url;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "trust_collection")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: TrustCollectionId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub remote_trust_collection_url: Option<String>,
    pub deactivated_at: Option<OffsetDateTime>,

    pub organisation_id: OrganisationId,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::organisation::Entity",
        from = "Column::OrganisationId",
        to = "super::organisation::Column::Id"
    )]
    Organisation,
    #[sea_orm(has_many = "super::trust_list_subscription::Entity")]
    TrustListSubscription,
}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
}

impl Related<super::trust_list_subscription::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::TrustListSubscription.def()
    }
}
