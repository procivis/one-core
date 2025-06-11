use one_core::model::trust_entity::TrustEntity;
use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use shared_types::{DidId, OrganisationId, TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "trust_entity")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: TrustEntityId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
    #[sea_orm(column_type = "Text")]
    pub name: String,
    #[sea_orm(column_type = "Blob", nullable)]
    pub logo: Option<Vec<u8>>,
    #[sea_orm(column_type = "Text", nullable)]
    pub website: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub terms_url: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub state: TrustEntityState,
    pub r#type: TrustEntityType,
    #[sea_orm(column_type = "Blob", nullable)]
    pub content: Option<Vec<u8>>,
    pub entity_key: String,
    pub trust_anchor_id: TrustAnchorId,
    #[sea_orm(nullable)]
    pub organisation_id: Option<OrganisationId>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::organisation::Entity",
        from = "Column::OrganisationId",
        to = "super::organisation::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Organisation,
    #[sea_orm(
        belongs_to = "super::trust_anchor::Entity",
        from = "Column::TrustAnchorId",
        to = "super::trust_anchor::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    TrustAnchor,
}

impl Related<super::trust_anchor::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::TrustAnchor.def()
    }
}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, From, Into)]
#[into(one_core::model::trust_entity::TrustEntityRole)]
#[from(one_core::model::trust_entity::TrustEntityRole)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum TrustEntityRole {
    #[sea_orm(string_value = "ISSUER")]
    Issuer,
    #[sea_orm(string_value = "VERIFIER")]
    Verifier,
    #[sea_orm(string_value = "BOTH")]
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, From, Into)]
#[into(one_core::model::trust_entity::TrustEntityState)]
#[from(one_core::model::trust_entity::TrustEntityState)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum TrustEntityState {
    #[sea_orm(string_value = "ACTIVE")]
    Active,
    #[sea_orm(string_value = "REMOVED")]
    Removed,
    #[sea_orm(string_value = "WITHDRAWN")]
    Withdrawn,
    #[sea_orm(string_value = "REMOVED_AND_WITHDRAWN")]
    RemovedAndWithdrawn,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, From, Into)]
#[into(one_core::model::trust_entity::TrustEntityType)]
#[from(one_core::model::trust_entity::TrustEntityType)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum TrustEntityType {
    #[sea_orm(string_value = "DID")]
    Did,
}
