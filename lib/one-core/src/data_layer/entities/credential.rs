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

    pub transport: Transport,
    pub credential: Vec<u8>,

    pub did_id: Option<String>,
    pub receiver_did_id: Option<String>,
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
        from = "Column::DidId",
        to = "super::did::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    IssuerDid,
    #[sea_orm(
        belongs_to = "super::did::Entity",
        from = "Column::ReceiverDidId",
        to = "super::did::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    HolderDid,
    #[sea_orm(has_many = "super::key::Entity")]
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

#[derive(Clone, Debug, Default, Eq, PartialEq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
pub enum Transport {
    #[default]
    #[sea_orm(string_value = "PROCIVIS_TEMPORARY")]
    ProcivisTemporary,
    #[sea_orm(string_value = "OPENID4VC")]
    OpenId4Vc,
}
