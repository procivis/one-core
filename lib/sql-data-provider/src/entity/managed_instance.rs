use one_dto_mapper::{From, Into};
use sea_orm::FromJsonQueryResult;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use shared_types::{ManagedInstanceId, OrganisationId, RevocationListEntryId};
use time::OffsetDateTime;

use crate::entity::instance::{InstanceRole, InstanceStatus};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "managed_instance")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: ManagedInstanceId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub last_issuance: Option<OffsetDateTime>,
    pub name: String,
    pub os: ManagedInstanceOs,
    pub status: InstanceStatus,
    pub provider: String,
    pub authentication_key_jwk: Option<String>,
    pub nonce: Option<String>,
    pub user_nonce: Option<String>,
    pub user_sub: Option<String>,
    pub organisation_id: OrganisationId,
    pub role: InstanceRole,
    pub verifier_csr: Option<String>,
    #[sea_orm(column_type = "Json")]
    pub verifier_signature_ids: Option<VerifierSignatures>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, FromJsonQueryResult)]
pub struct VerifierSignatures {
    pub signatures: Vec<RevocationListEntryId>,
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
    #[sea_orm(has_many = "super::managed_instance_attestation::Entity")]
    ManagedInstanceAttestation,
}
impl ActiveModelBehavior for ActiveModel {}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
}

impl Related<super::managed_instance_attestation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ManagedInstanceAttestation.def()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From, Deserialize)]
#[from(one_core::model::managed_instance::ManagedInstanceOs)]
#[into(one_core::model::managed_instance::ManagedInstanceOs)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum ManagedInstanceOs {
    #[sea_orm(string_value = "IOS")]
    Ios,
    #[sea_orm(string_value = "ANDROID")]
    Android,
    #[sea_orm(string_value = "WEB")]
    Web,
}
