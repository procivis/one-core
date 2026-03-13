use one_core::model::trust_list_publication::TrustListPublicationRoleEnum;
use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use serde::Deserialize;
use shared_types::{
    CertificateId, IdentifierId, KeyId, OrganisationId, TrustListPublicationId,
    TrustListPublisherId,
};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "trust_list_publication")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: TrustListPublicationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    #[sea_orm(column_type = "Text")]
    pub name: String,
    pub role: TrustRoleEnum,
    #[sea_orm(column_name = "type")]
    pub r#type: TrustListPublisherId,
    #[sea_orm(column_type = "Blob")]
    pub metadata: Vec<u8>,
    #[sea_orm(column_name = "deactivated_at")]
    pub deleted_at: Option<OffsetDateTime>,
    #[sea_orm(column_type = "Blob")]
    pub content: Vec<u8>,
    pub sequence_number: u32,
    pub organisation_id: OrganisationId,
    pub identifier_id: IdentifierId,
    #[sea_orm(nullable)]
    pub key_id: Option<KeyId>,
    #[sea_orm(nullable)]
    pub certificate_id: Option<CertificateId>,
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
        belongs_to = "super::identifier::Entity",
        from = "Column::IdentifierId",
        to = "super::identifier::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Identifier,
    #[sea_orm(
        belongs_to = "super::key::Entity",
        from = "Column::KeyId",
        to = "super::key::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Key,
    #[sea_orm(
        belongs_to = "super::certificate::Entity",
        from = "Column::CertificateId",
        to = "super::certificate::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Certificate,
}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
}

impl Related<super::identifier::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Identifier.def()
    }
}

impl Related<super::key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Key.def()
    }
}

impl Related<super::certificate::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Certificate.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, From, Into, Deserialize)]
#[into(TrustListPublicationRoleEnum)]
#[from(TrustListPublicationRoleEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum TrustRoleEnum {
    #[sea_orm(string_value = "PID_PROVIDER")]
    PidProvider,
    #[sea_orm(string_value = "WALLET_PROVIDER")]
    WalletProvider,
    #[sea_orm(string_value = "WRP_AC_PROVIDER")]
    WrpAcProvider,
    #[sea_orm(string_value = "PUB_EEA_PROVIDER")]
    PubEeaProvider,
    #[sea_orm(string_value = "QEAA_PROVIDER")]
    QeaaProvider,
    #[sea_orm(string_value = "QESRC_PROVIDER")]
    QesrcProvider,
    #[sea_orm(string_value = "WRP_RC_PROVIDER")]
    WrpRcProvider,
    #[sea_orm(string_value = "NATIONAL_REGISTRY_REGISTRAR")]
    NationalRegistryRegistrar,
    #[sea_orm(string_value = "ISSUER")]
    Issuer,
    #[sea_orm(string_value = "VERIFIER")]
    Verifier,
}
