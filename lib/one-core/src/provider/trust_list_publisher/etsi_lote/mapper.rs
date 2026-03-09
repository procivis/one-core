use standardized_types::etsi_119_602::LoTEType;

use super::dto::{AddEntryParams, CreateTrustListParams};
use crate::model::trust_list_publication::TrustRoleEnum;
use crate::provider::trust_list_publisher::error::TrustListPublisherError;

impl TryFrom<&TrustRoleEnum> for LoTEType {
    type Error = TrustListPublisherError;

    fn try_from(role: &TrustRoleEnum) -> Result<Self, Self::Error> {
        match role {
            TrustRoleEnum::PidProvider => Ok(Self::EuPidProvidersList),
            TrustRoleEnum::WalletProvider => Ok(Self::EuWalletProvidersList),
            TrustRoleEnum::WrpAcProvider => Ok(Self::EuWrpAcProvidersList),
            TrustRoleEnum::WrpRcProvider => Ok(Self::EuWrpRcProvidersList),
            TrustRoleEnum::PubEeaProvider => Ok(Self::EuPubEaaProvidersList),
            TrustRoleEnum::NationalRegistryRegistrar => Ok(Self::EuRegistrarsAndRegistersList),
            other => Err(TrustListPublisherError::UnsupportedRole(format!(
                "no ETSI LoTE type for role: {other:?}"
            ))),
        }
    }
}

impl TryFrom<serde_json::Value> for AddEntryParams {
    type Error = TrustListPublisherError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map_err(TrustListPublisherError::InvalidParams)
    }
}

impl TryFrom<serde_json::Value> for CreateTrustListParams {
    type Error = TrustListPublisherError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map_err(TrustListPublisherError::InvalidParams)
    }
}
