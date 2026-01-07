use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use shared_types::{InteractionId, NonceId, OrganisationId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "interaction")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: InteractionId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    #[sea_orm(column_type = "Blob")]
    pub data: Option<Vec<u8>>,
    pub organisation_id: OrganisationId,
    pub nonce_id: Option<NonceId>,
    pub interaction_type: InteractionType,
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::credential::Entity")]
    Credential,
    #[sea_orm(has_many = "super::proof::Entity")]
    Proof,
    #[sea_orm(
        belongs_to = "super::organisation::Entity",
        from = "Column::OrganisationId",
        to = "super::organisation::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Organisation,
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

impl Related<super::proof::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Proof.def()
    }
}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, From, Into)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
#[from(one_core::model::interaction::InteractionType)]
#[into(one_core::model::interaction::InteractionType)]
pub enum InteractionType {
    #[sea_orm(string_value = "ISSUANCE")]
    Issuance,
    #[sea_orm(string_value = "VERIFICATION")]
    Verification,
}
