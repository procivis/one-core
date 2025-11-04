use one_core::model::wallet_unit_attested_key::{
    WalletUnitAttestedKey, WalletUnitAttestedKeyUpsertRequest,
};
use one_core::repository::error::DataLayerError;
use sea_orm::Set;
use time::OffsetDateTime;

use crate::entity::wallet_unit_attested_key::{ActiveModel, Model};

impl TryFrom<Model> for WalletUnitAttestedKey {
    type Error = DataLayerError;

    fn try_from(value: Model) -> Result<Self, DataLayerError> {
        Ok(Self {
            id: value.id,
            wallet_unit_id: value.wallet_unit_id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            expiration_date: value.expiration_date,
            public_key_jwk: serde_json::from_str(&value.public_key_jwk)
                .map_err(|_| DataLayerError::MappingError)?,
            revocation: None,
        })
    }
}

impl TryFrom<WalletUnitAttestedKey> for ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: WalletUnitAttestedKey) -> Result<Self, DataLayerError> {
        Ok(Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            expiration_date: Set(value.expiration_date),
            public_key_jwk: Set(serde_json::to_string(&value.public_key_jwk)
                .map_err(|_| DataLayerError::MappingError)?),
            wallet_unit_id: Set(value.wallet_unit_id),
            revocation_list_entry_id: Set(None),
        })
    }
}

impl TryFrom<WalletUnitAttestedKeyUpsertRequest> for ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: WalletUnitAttestedKeyUpsertRequest) -> Result<Self, DataLayerError> {
        let now = OffsetDateTime::now_utc();
        Ok(Self {
            id: Set(value.id),
            created_date: Set(now),
            last_modified: Set(now),
            expiration_date: Set(value.expiration_date),
            public_key_jwk: Set(serde_json::to_string(&value.public_key_jwk)
                .map_err(|_| DataLayerError::MappingError)?),
            wallet_unit_id: Set(value.wallet_unit_id),
            revocation_list_entry_id: Set(None),
        })
    }
}
