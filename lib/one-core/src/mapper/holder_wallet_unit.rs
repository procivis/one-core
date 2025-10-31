use crate::model::holder_wallet_unit::{CreateHolderWalletUnitRequest, HolderWalletUnit};
use crate::service::error::ServiceError;

impl TryFrom<HolderWalletUnit> for CreateHolderWalletUnitRequest {
    type Error = ServiceError;

    fn try_from(value: HolderWalletUnit) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            wallet_provider_type: value.wallet_provider_type,
            wallet_provider_name: value.wallet_provider_name,
            wallet_provider_url: value.wallet_provider_url,
            provider_wallet_unit_id: value.provider_wallet_unit_id,
            status: value.status,
            organisation: value.organisation.ok_or(ServiceError::MappingError(
                "Missing organisation".to_string(),
            ))?,
            authentication_key: value.authentication_key.ok_or(ServiceError::MappingError(
                "Missing authentication key".to_string(),
            ))?,
        })
    }
}
