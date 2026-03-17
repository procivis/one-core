use standardized_types::etsi_119_602::LoTEType;

use super::dto::{AddEntryParams, CreateTrustListParams};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::provider::trust_list_publisher::error::TrustListPublisherError;

impl TryFrom<&TrustListRoleEnum> for LoTEType {
    type Error = TrustListPublisherError;

    fn try_from(role: &TrustListRoleEnum) -> Result<Self, Self::Error> {
        match role {
            TrustListRoleEnum::PidProvider => Ok(Self::EuPidProvidersList),
            TrustListRoleEnum::WalletProvider => Ok(Self::EuWalletProvidersList),
            TrustListRoleEnum::WrpAcProvider => Ok(Self::EuWrpAcProvidersList),
            TrustListRoleEnum::WrpRcProvider => Ok(Self::EuWrpRcProvidersList),
            TrustListRoleEnum::PubEeaProvider => Ok(Self::EuPubEaaProvidersList),
            TrustListRoleEnum::NationalRegistryRegistrar => Ok(Self::EuRegistrarsAndRegistersList),
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
