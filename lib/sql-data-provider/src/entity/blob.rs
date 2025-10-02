use one_core::model;
use one_core::model::certificate::CertificateState as ModelCertificateState;
use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use shared_types::{BlobId, CertificateId, IdentifierId, KeyId, OrganisationId};
use time::OffsetDateTime;

use crate::entity::did::DidType;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "blob_storage")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: BlobId,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    #[sea_orm(column_type = "Blob")]
    pub value: Vec<u8>,
    #[sea_orm(column_name = "type")]
    pub r#type: BlobType,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(model::blob::BlobType)]
#[into(model::blob::BlobType)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum BlobType {
    #[sea_orm(string_value = "CREDENTIAL")]
    Credential,
    #[sea_orm(string_value = "PROOF")]
    Proof,
    #[sea_orm(string_value = "WALLET_UNIT_ATTESTATION")]
    WalletUnitAttestation,
}
