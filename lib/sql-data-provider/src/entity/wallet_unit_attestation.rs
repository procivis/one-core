use one_core::model::key::KeyRelations;
use one_core::model::organisation::OrganisationRelations;
use one_core::model::wallet_unit::{WalletUnit, WalletUnitStatus as ModelWalletUnitStatus};
use one_core::model::wallet_unit_attestation::WalletUnitAttestation;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use shared_types::{KeyId, OrganisationId, WalletUnitAttestationId, WalletUnitId};
use time::OffsetDateTime;

use crate::entity::wallet_unit::{WalletProviderType, WalletUnitStatus};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "wallet_unit")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: WalletUnitAttestationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiration_date: OffsetDateTime,
    pub status: WalletUnitStatus,
    #[sea_orm(column_type = "Blob")]
    pub attestation: Vec<u8>,
    pub wallet_unit_id: WalletUnitId,
    pub wallet_provider_url: String,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,
    pub organisation_id: Option<OrganisationId>,
    pub key_id: Option<KeyId>,
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
        belongs_to = "super::key::Entity",
        from = "Column::KeyId",
        to = "super::key::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Key,
}

impl ActiveModelBehavior for ActiveModel {}

impl From<WalletUnitAttestation> for ActiveModel {
    fn from(wallet_unit_attestation: WalletUnitAttestation) -> Self {
        Self {
            id: Set(wallet_unit_attestation.id),
            created_date: Set(wallet_unit_attestation.created_date),
            last_modified: Set(wallet_unit_attestation.last_modified),
            expiration_date: Set(wallet_unit_attestation.expiration_date),
            status: Set(wallet_unit_attestation.status.into()),
            attestation: Set(wallet_unit_attestation.attestation.into_bytes()),
            wallet_unit_id: Set(wallet_unit_attestation.wallet_unit_id),
            wallet_provider_url: Set(wallet_unit_attestation.wallet_provider_url),
            wallet_provider_type: Set(wallet_unit_attestation.wallet_provider_type.into()),
            wallet_provider_name: Set(wallet_unit_attestation.wallet_provider_name),
            organisation_id: Set(wallet_unit_attestation.organisation.map(|o| o.id)),
            key_id: Set(wallet_unit_attestation.key.map(|k| k.id)),
        }
    }
}

impl From<Model> for WalletUnitAttestation {
    fn from(value: Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            expiration_date: value.expiration_date,
            status: value.status.into(),
            attestation: String::from_utf8_lossy(&value.attestation).to_string(),
            wallet_unit_id: value.wallet_unit_id,
            wallet_provider_url: value.wallet_provider_url,
            wallet_provider_type: value.wallet_provider_type.into(),
            wallet_provider_name: value.wallet_provider_name,
            organisation: None,
            key: None,
        }
    }
}
