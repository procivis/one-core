use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use shared_types::{CertificateId, DidId, IdentifierId, RevocationListId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "revocation_list")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: RevocationListId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    #[sea_orm(column_type = "Blob")]
    pub formatted_list: Vec<u8>,
    pub purpose: RevocationListPurpose,
    pub format: RevocationListFormat,
    pub r#type: RevocationListType,

    pub issuer_identifier_id: IdentifierId,
    pub issuer_certificate_id: Option<CertificateId>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::revocation_list_entry::Entity")]
    RevocationListEntry,
    #[sea_orm(
        belongs_to = "super::identifier::Entity",
        from = "Column::IssuerIdentifierId",
        to = "super::identifier::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Identifier,
    #[sea_orm(
        belongs_to = "super::certificate::Entity",
        from = "Column::IssuerCertificateId",
        to = "super::certificate::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Certificate,
}

impl Related<super::revocation_list_entry::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RevocationListEntry.def()
    }
}

impl Related<super::identifier::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Identifier.def()
    }
}

impl Related<super::certificate::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Certificate.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(one_core::model::revocation_list::RevocationListPurpose)]
#[into(one_core::model::revocation_list::RevocationListPurpose)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum RevocationListPurpose {
    #[sea_orm(string_value = "REVOCATION")]
    Revocation,
    #[sea_orm(string_value = "SUSPENSION")]
    Suspension,
    #[sea_orm(string_value = "REVOCATION_AND_SUSPENSION")]
    RevocationAndSuspension,
}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(one_core::model::revocation_list::StatusListCredentialFormat)]
#[into(one_core::model::revocation_list::StatusListCredentialFormat)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum RevocationListFormat {
    #[sea_orm(string_value = "JWT")]
    Jwt,
    #[sea_orm(string_value = "JSON_LD_CLASSIC")]
    JsonLdClassic,
    #[sea_orm(string_value = "X509_CRL")]
    X509Crl,
}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(one_core::model::revocation_list::StatusListType)]
#[into(one_core::model::revocation_list::StatusListType)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum RevocationListType {
    #[sea_orm(string_value = "BITSTRINGSTATUSLIST")]
    BitstringStatusList,
    #[sea_orm(string_value = "TOKENSTATUSLIST")]
    TokenStatusList,
    #[sea_orm(string_value = "CRL")]
    Crl,
}
