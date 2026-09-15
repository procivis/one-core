use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use shared_types::{InstanceId, KeyId, WalletInstanceAttestationId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "wallet_instance_attestation")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: WalletInstanceAttestationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiration_date: OffsetDateTime,
    #[sea_orm(column_type = "Blob")]
    pub attestation: Vec<u8>,
    pub revocation_list_url: Option<String>,
    pub revocation_list_index: Option<i64>,
    pub instance_id: InstanceId,
    pub attested_key_id: KeyId,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::instance::Entity",
        from = "Column::InstanceId",
        to = "super::instance::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Instance,
    #[sea_orm(
        belongs_to = "super::key::Entity",
        from = "Column::AttestedKeyId",
        to = "super::key::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    AttestedKey,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(one_core::model::wallet_instance_attestation::AttestationType)]
#[into(one_core::model::wallet_instance_attestation::AttestationType)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum AttestationType {
    #[sea_orm(string_value = "WIA")]
    WalletInstanceAttestation,
    #[sea_orm(string_value = "KA")]
    KeyAttestation,
}
