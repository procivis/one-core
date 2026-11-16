use std::str::FromStr;

use one_core::model::organisation::OrganisationConfiguration;
use one_dto_mapper::{From, Into};
use sea_orm::FromJsonQueryResult;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{
    EcosystemId, IdentifierId, OrganisationId, VerifierProviderId, WalletProviderId,
};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "organisation")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
    pub wallet_provider: Option<WalletProviderId>,
    pub wallet_provider_issuer: Option<IdentifierId>,
    pub parent_organisation: Option<OrganisationId>,
    #[sea_orm(column_type = "Json")]
    pub configuration: Option<Configuration>,
    pub verifier_provider: Option<VerifierProviderId>,
    pub verifier_provider_issuer: Option<IdentifierId>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, FromJsonQueryResult)]
pub struct Configuration {
    pub selected_ecosystems: Option<Vec<EcosystemId>>,
    pub enforce_ecosystem_as_issuer: Option<bool>,
    pub enforce_ecosystem_as_holder: Option<bool>,
    pub enforce_ecosystem_as_verifier: Option<bool>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::credential_schema::Entity")]
    CredentialSchema,
    #[sea_orm(has_many = "super::did::Entity")]
    Did,
    #[sea_orm(has_many = "super::proof_schema::Entity")]
    ProofSchema,
    #[sea_orm(has_many = "super::interaction::Entity")]
    Interaction,
    #[sea_orm(
        belongs_to = "Entity",
        from = "Column::Id",
        to = "Column::ParentOrganisation",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    ChildOrganisation,
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

impl Related<super::interaction::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Interaction.def()
    }
}

impl Related<Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ChildOrganisation.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
