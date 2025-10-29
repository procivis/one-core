use one_core::model::holder_wallet_unit::HolderWalletUnit;
use one_core::model::wallet_unit::{WalletProviderType, WalletUnitStatus};
use one_core::repository::error::DataLayerError;
use sea_orm::Set;

use crate::entity::holder_wallet_unit::{ActiveModel, Model};

impl From<Model> for HolderWalletUnit {
    fn from(value: Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            wallet_provider_type: WalletProviderType::from(value.wallet_provider_type),
            wallet_provider_name: value.wallet_provider_name,
            wallet_provider_url: value.wallet_provider_url,
            provider_wallet_unit_id: value.provider_wallet_unit_id,
            status: WalletUnitStatus::from(value.status),
            organisation: None,
            authentication_key: None,
            wallet_unit_attestations: None,
        }
    }
}

impl TryFrom<HolderWalletUnit> for ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: HolderWalletUnit) -> Result<Self, DataLayerError> {
        Ok(Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            status: Set(value.status.into()),
            wallet_provider_name: Set(value.wallet_provider_name),
            wallet_provider_type: Set(value.wallet_provider_type.into()),
            wallet_provider_url: Set(value.wallet_provider_url),
            provider_wallet_unit_id: Set(value.provider_wallet_unit_id),
            organisation_id: Set(value.organisation.ok_or(DataLayerError::MappingError)?.id),
            authentication_key_id: Set(value
                .authentication_key
                .ok_or(DataLayerError::MappingError)?
                .id),
        })
    }
}
