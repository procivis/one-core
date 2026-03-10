use standardized_types::etsi_119_602::LoTEType;

use super::dto::{AddEntryParams, CreateTrustListParams};
use crate::model::trust_list_publication::TrustListPublicationRoleEnum;
use crate::provider::trust_list_publisher::error::TrustListPublisherError;

impl TryFrom<&TrustListPublicationRoleEnum> for LoTEType {
    type Error = TrustListPublisherError;

    fn try_from(role: &TrustListPublicationRoleEnum) -> Result<Self, Self::Error> {
        match role {
            TrustListPublicationRoleEnum::PidProvider => Ok(Self::EuPidProvidersList),
            TrustListPublicationRoleEnum::WalletProvider => Ok(Self::EuWalletProvidersList),
            TrustListPublicationRoleEnum::WrpAcProvider => Ok(Self::EuWrpAcProvidersList),
            TrustListPublicationRoleEnum::WrpRcProvider => Ok(Self::EuWrpRcProvidersList),
            TrustListPublicationRoleEnum::PubEeaProvider => Ok(Self::EuPubEaaProvidersList),
            TrustListPublicationRoleEnum::NationalRegistryRegistrar => {
                Ok(Self::EuRegistrarsAndRegistersList)
            }
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
