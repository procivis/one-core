use one_core::model::revocation_list::RevocationList;
use one_core::model::wallet_unit_attested_key::{
    WalletUnitAttestedKey, WalletUnitAttestedKeyUpsertRequest,
};
use one_core::repository::error::DataLayerError;
use sea_orm::Set;
use time::OffsetDateTime;

use crate::entity::wallet_unit_attested_key::{ActiveModel, Model};

pub(super) fn model_to_attested_key(
    model: Model,
    revocation_lists: &[RevocationList],
) -> Result<WalletUnitAttestedKey, DataLayerError> {
    let revocation_list = if let Some(revocation_list_id) = model.revocation_list_id {
        let revocation_list = revocation_lists
            .iter()
            .find(|revocation_list| revocation_list.id == revocation_list_id)
            .cloned()
            .ok_or(DataLayerError::MissingRequiredRelation {
                relation: "wallet_unit_attested_key-revocation_list",
                id: revocation_list_id.to_string(),
            })?;
        Some(revocation_list)
    } else {
        None
    };
    let mut attested_key = WalletUnitAttestedKey::try_from(model)?;
    attested_key.revocation_list = revocation_list;
    Ok(attested_key)
}

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
            revocation_list_index: value.revocation_list_index,
            revocation_list: None,
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
            revocation_list_id: Set(value.revocation_list.map(|list| list.id)),
            revocation_list_index: Set(value.revocation_list_index),
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
            revocation_list_id: Set(value.revocation_list.map(|list| list.id)),
            revocation_list_index: Set(value.revocation_list_index),
        })
    }
}
