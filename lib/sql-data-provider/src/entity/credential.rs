use dto_mapper::{From, Into};
use one_core::model::credential::CredentialRole as ModelCredentialRole;
use sea_orm::entity::prelude::*;
use shared_types::{CredentialId, DidId, KeyId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "credential")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: CredentialId,

    pub credential_schema_id: String,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    pub issuance_date: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,

    #[sea_orm(column_name = "transport")]
    pub exchange: String,
    pub redirect_uri: Option<String>,

    #[sea_orm(column_type = "Binary(BlobSize::Long)")]
    pub credential: Vec<u8>,

    pub role: CredentialRole,

    pub issuer_did_id: Option<DidId>,
    pub holder_did_id: Option<DidId>,
    pub interaction_id: Option<String>,
    pub revocation_list_id: Option<String>,
    pub key_id: Option<KeyId>,
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
    #[sea_orm(
        belongs_to = "super::revocation_list::Entity",
        from = "Column::RevocationListId",
        to = "super::revocation_list::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    RevocationList,
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

impl Related<super::credential_state::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialState.def()
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

impl Related<super::revocation_list::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RevocationList.def()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(ModelCredentialRole)]
#[into(ModelCredentialRole)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
pub enum CredentialRole {
    #[sea_orm(string_value = "HOLDER")]
    Holder,
    #[sea_orm(string_value = "ISSUER")]
    Issuer,
    #[sea_orm(string_value = "VERIFIER")]
    Verifier,
}
