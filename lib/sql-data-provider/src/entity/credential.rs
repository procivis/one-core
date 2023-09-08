use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "credential")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,

    pub credential_schema_id: String,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    pub issuance_date: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,

    pub transport: String,

    #[sea_orm(column_type = "Binary(BlobSize::Blob(None))")]
    pub credential: Vec<u8>,

    pub issuer_did_id: String,
    pub holder_did_id: Option<String>,
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
    #[sea_orm(has_many = "super::credential_state::Entity")]
    CredentialState,
    #[sea_orm(
        belongs_to = "super::did::Entity",
        from = "Column::IssuerDidId",
        to = "super::did::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    IssuerDid,
    #[sea_orm(
        belongs_to = "super::did::Entity",
        from = "Column::HolderDidId",
        to = "super::did::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    HolderDidId,
    #[sea_orm(has_many = "super::key::Entity")]
    Key,
}

impl Related<super::credential_claim::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialClaim.def()
    }
}

impl Related<super::credential_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialSchema.def()
    }
}

impl Related<super::credential_state::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialState.def()
    }
}

impl Related<super::key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Key.def()
    }
}

impl Related<super::did::Entity> for Entity {
    fn to() -> RelationDef {
        super::key::Relation::Did.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::key::Relation::Credential.def().rev())
    }
}
