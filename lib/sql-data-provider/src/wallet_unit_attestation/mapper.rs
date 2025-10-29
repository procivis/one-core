use one_core::model::wallet_unit_attestation::WalletUnitAttestation;
use one_core::repository::error::DataLayerError;
use sea_orm::Set;

use crate::entity::wallet_unit_attestation::{ActiveModel, Model};

impl TryFrom<WalletUnitAttestation> for ActiveModel {
    type Error = DataLayerError;
    fn try_from(wallet_unit_attestation: WalletUnitAttestation) -> Result<Self, Self::Error> {
        let attested_key_id = wallet_unit_attestation
            .attested_key
            .ok_or(DataLayerError::MappingError)?
            .id;
        Ok(Self {
            id: Set(wallet_unit_attestation.id),
            created_date: Set(wallet_unit_attestation.created_date),
            last_modified: Set(wallet_unit_attestation.last_modified),
            expiration_date: Set(wallet_unit_attestation.expiration_date),
            attestation: Set(wallet_unit_attestation.attestation.into_bytes()),
            revocation_list_url: Set(wallet_unit_attestation.revocation_list_url),
            revocation_list_index: Set(wallet_unit_attestation.revocation_list_index),
            holder_wallet_unit_id: Set(wallet_unit_attestation.holder_wallet_unit_id),
            attested_key_id: Set(attested_key_id),
        })
    }
}

impl From<Model> for WalletUnitAttestation {
    fn from(value: Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            expiration_date: value.expiration_date,
            attestation: String::from_utf8_lossy(&value.attestation).to_string(),
            holder_wallet_unit_id: value.holder_wallet_unit_id,
            revocation_list_url: value.revocation_list_url,
            revocation_list_index: value.revocation_list_index,
            attested_key: None,
        }
    }
}
