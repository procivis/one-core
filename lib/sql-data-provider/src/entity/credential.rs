use one_core::model::credential::{
    CredentialRole as ModelCredentialRole, CredentialStateEnum as ModelCredentialStateEnum,
    CredentialType as ModelCredentialType,
};
use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use shared_types::{
    BlobId, CertificateId, CredentialId, CredentialSchemaFormatId, CredentialSchemaId, DidId,
    EcosystemId, IdentifierId, InteractionId, KeyId, OrganisationId,
};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "credential")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: CredentialId,

    pub credential_schema_id: CredentialSchemaId,
    /// Copy of `credential_schema.organisation_id`, indexed for the list queries (ONE-11287).
    pub organisation_id: OrganisationId,
    pub format: Option<CredentialSchemaFormatId>,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    pub issuance_date: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub deleted_at: Option<OffsetDateTime>,
    pub consumed_at: Option<OffsetDateTime>,

    pub protocol: String,
    pub redirect_uri: Option<String>,

    pub role: CredentialRole,
    pub r#type: CredentialType,

    pub issuer_identifier_id: Option<IdentifierId>,
    pub issuer_certificate_id: Option<CertificateId>,
    pub key_id: Option<KeyId>,

    pub holder_identifier_id: Option<IdentifierId>,

    pub interaction_id: Option<InteractionId>,

    pub suspend_end_date: Option<OffsetDateTime>,

    pub state: CredentialState,

    pub profile: Option<String>,

    pub parent_id: Option<CredentialId>,
    pub credential_blob_id: Option<BlobId>,
    pub wallet_key_attestation_blob_id: Option<BlobId>,
    pub wallet_instance_attestation_blob_id: Option<BlobId>,

    pub webhook_url: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub embedded_disclosure_policy: Option<String>,
    pub subscriber_information: Option<String>,
    pub ecosystem: Option<EcosystemId>,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::credential_claim::Entity")]
    CredentialClaim,
    #[sea_orm(
        belongs_to = "super::credential_schema::Entity",
        from = "Column::CredentialSchemaId",
        to = "super::credential_schema::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    CredentialSchema,
    #[sea_orm(
        belongs_to = "super::credential_schema_format::Entity",
        from = "Column::Format",
        to = "super::credential_schema_format::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    CredentialSchemaFormat,
    #[sea_orm(
        belongs_to = "super::organisation::Entity",
        from = "Column::OrganisationId",
        to = "super::organisation::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Organisation,
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
        super::credential_claim::Relation::Claim.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::credential_claim::Relation::Credential.def().rev())
    }
}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
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
#[from(ModelCredentialType)]
#[into(ModelCredentialType)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum CredentialType {
    #[sea_orm(string_value = "SINGLE")]
    Single,
    #[sea_orm(string_value = "BATCH_PARENT")]
    BatchParent,
    #[sea_orm(string_value = "BATCH_ITEM")]
    BatchItem,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum)]
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
    #[sea_orm(string_value = "INTERACTION_EXPIRED")]
    InteractionExpired,
    #[sea_orm(string_value = "EXPIRED")]
    Expired,
    #[sea_orm(string_value = "EXPIRING")]
    Expiring,
}

impl From<ModelCredentialStateEnum> for CredentialState {
    fn from(value: ModelCredentialStateEnum) -> Self {
        match value {
            ModelCredentialStateEnum::Created => Self::Created,
            ModelCredentialStateEnum::Pending => Self::Pending,
            ModelCredentialStateEnum::Offered => Self::Offered,
            ModelCredentialStateEnum::Accepted => Self::Accepted,
            ModelCredentialStateEnum::Rejected => Self::Rejected,
            ModelCredentialStateEnum::Revoked => Self::Revoked,
            ModelCredentialStateEnum::Suspended { .. } => Self::Suspended,
            ModelCredentialStateEnum::Error => Self::Error,
            ModelCredentialStateEnum::InteractionExpired => Self::InteractionExpired,
            ModelCredentialStateEnum::Expiring => Self::Expiring,
            ModelCredentialStateEnum::Expired => Self::Expired,
        }
    }
}

impl CredentialState {
    pub(crate) fn to_model(
        self,
        suspend_end_date: Option<OffsetDateTime>,
    ) -> ModelCredentialStateEnum {
        match self {
            Self::Created => ModelCredentialStateEnum::Created,
            Self::Pending => ModelCredentialStateEnum::Pending,
            Self::Offered => ModelCredentialStateEnum::Offered,
            Self::Accepted => ModelCredentialStateEnum::Accepted,
            Self::Rejected => ModelCredentialStateEnum::Rejected,
            Self::Revoked => ModelCredentialStateEnum::Revoked,
            Self::Suspended => ModelCredentialStateEnum::Suspended { suspend_end_date },
            Self::Error => ModelCredentialStateEnum::Error,
            Self::InteractionExpired => ModelCredentialStateEnum::InteractionExpired,
            Self::Expiring => ModelCredentialStateEnum::Expiring,
            Self::Expired => ModelCredentialStateEnum::Expired,
        }
    }
}
