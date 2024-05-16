use dto_mapper::{From, Into};
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
    pub entity_id: String,
    pub name: String,
    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub trust_anchor_id: TrustAnchorId,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
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

impl ActiveModelBehavior for ActiveModel {}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum)]
#[sea_orm(
    rs_type = "String",
    db_type = "Enum",
    enum_name = "trust_entity_role_enum"
)]
pub enum TrustEntityRole {
    #[sea_orm(string_value = "ISSUER")]
    Issuer,
    #[sea_orm(string_value = "VERIFIER")]
    Verifier,
    #[sea_orm(string_value = "BOTH")]
    Both,
}
