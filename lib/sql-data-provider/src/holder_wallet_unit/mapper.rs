use one_core::model::holder_wallet_unit::{CreateHolderWalletUnitRequest, HolderWalletUnit};
use one_core::model::wallet_unit::{WalletProviderType, WalletUnitStatus};
use sea_orm::Set;
use time::OffsetDateTime;

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

impl From<CreateHolderWalletUnitRequest> for ActiveModel {
    fn from(value: CreateHolderWalletUnitRequest) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: Set(value.id),
            created_date: Set(now),
            last_modified: Set(now),
            status: Set(value.status.into()),
            wallet_provider_name: Set(value.wallet_provider_name),
            wallet_provider_type: Set(value.wallet_provider_type.into()),
            wallet_provider_url: Set(value.wallet_provider_url),
            provider_wallet_unit_id: Set(value.provider_wallet_unit_id),
            organisation_id: Set(value.organisation.id),
            authentication_key_id: Set(value.authentication_key.id),
        }
    }
}
