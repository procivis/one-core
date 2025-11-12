use one_core::model::credential::{
    CredentialRole as ModelCredentialRole, CredentialStateEnum as ModelCredentialStateEnum,
};
use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use shared_types::{
    BlobId, CertificateId, CredentialId, CredentialSchemaId, DidId, IdentifierId, KeyId,
};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "credential")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: CredentialId,

    pub credential_schema_id: CredentialSchemaId,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    pub issuance_date: Option<OffsetDateTime>,
    pub deleted_at: Option<OffsetDateTime>,

    pub protocol: String,
    pub redirect_uri: Option<String>,

    pub role: CredentialRole,

    pub issuer_identifier_id: Option<IdentifierId>,
    pub issuer_certificate_id: Option<CertificateId>,
    pub key_id: Option<KeyId>,

    pub holder_identifier_id: Option<IdentifierId>,

    pub interaction_id: Option<String>,

    pub suspend_end_date: Option<OffsetDateTime>,

    pub state: CredentialState,

    pub profile: Option<String>,

    pub credential_blob_id: Option<BlobId>,
    pub wallet_unit_attestation_blob_id: Option<BlobId>,
    pub wallet_app_attestation_blob_id: Option<BlobId>,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::claim::Entity")]
    Claim,
    #[sea_orm(
        belongs_to = "super::credential_schema::Entity",
        from = "Column::CredentialSchemaId",
        to = "super::credential_schema::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    CredentialSchema,
    #[sea_orm(
        belongs_to = "super::identifier::Entity",
        from = "Column::IssuerIdentifierId",
        to = "super::identifier::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    IssuerIdentifier,
    #[sea_orm(
        belongs_to = "super::certificate::Entity",
        from = "Column::IssuerCertificateId",
        to = "super::certificate::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    IssuerCertificate,
    #[sea_orm(
        belongs_to = "super::identifier::Entity",
        from = "Column::HolderIdentifierId",
        to = "super::identifier::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    HolderIdentifier,
    #[sea_orm(
        belongs_to = "super::interaction::Entity",
        from = "Column::InteractionId",
        to = "super::interaction::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Interaction,
    #[sea_orm(
        belongs_to = "super::key::Entity",
        from = "Column::KeyId",
        to = "super::key::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Key,
}

impl Related<super::claim::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Claim.def()
    }
}

impl Related<super::credential_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialSchema.def()
    }
}

impl Related<super::interaction::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Interaction.def()
    }
}

impl Related<super::key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Key.def()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(ModelCredentialRole)]
#[into(ModelCredentialRole)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum CredentialRole {
    #[sea_orm(string_value = "HOLDER")]
    Holder,
    #[sea_orm(string_value = "ISSUER")]
    Issuer,
    #[sea_orm(string_value = "VERIFIER")]
    Verifier,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(ModelCredentialStateEnum)]
#[into(ModelCredentialStateEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum CredentialState {
    #[sea_orm(string_value = "CREATED")]
    Created,
    #[sea_orm(string_value = "PENDING")]
    Pending,
    #[sea_orm(string_value = "OFFERED")]
    Offered,
    #[sea_orm(string_value = "ACCEPTED")]
    Accepted,
    #[sea_orm(string_value = "REJECTED")]
    Rejected,
    #[sea_orm(string_value = "REVOKED")]
    Revoked,
    #[sea_orm(string_value = "SUSPENDED")]
    Suspended,
    #[sea_orm(string_value = "ERROR")]
    Error,
}
