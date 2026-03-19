use standardized_types::etsi_119_602::LoTEType;

use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::trust_list_role::TrustListRoleEnum;

impl TryFrom<LoTEType> for TrustListRoleEnum {
    type Error = LoTEMappingError;

    fn try_from(value: LoTEType) -> Result<Self, Self::Error> {
        match value {
            LoTEType::EuPidProvidersList => Ok(TrustListRoleEnum::PidProvider),
            LoTEType::EuWalletProvidersList => Ok(TrustListRoleEnum::WalletProvider),
            LoTEType::EuWrpAcProvidersList => Ok(TrustListRoleEnum::WrpAcProvider),
            LoTEType::EuWrpRcProvidersList => Ok(TrustListRoleEnum::WrpRcProvider),
            LoTEType::EuPubEaaProvidersList => Ok(TrustListRoleEnum::PubEeaProvider),
            LoTEType::EuRegistrarsAndRegistersList => {
                Ok(TrustListRoleEnum::NationalRegistryRegistrar)
            }
            LoTEType::Other(r#type) => Err(LoTEMappingError::UnsupportedLoTEType(r#type)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoTEMappingError {
    #[error("Unsupported LoTE type: `{0}`")]
    UnsupportedLoTEType(String),
    #[error("Unsupported role: `{0}`")]
    UnsupportedRole(String),
}

impl ErrorCodeMixin for LoTEMappingError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::UnsupportedLoTEType(_) => ErrorCode::BR_0047,
            Self::UnsupportedRole(_) => ErrorCode::BR_0386,
        }
    }
}

impl TryFrom<&TrustListRoleEnum> for LoTEType {
    type Error = LoTEMappingError;

    fn try_from(role: &TrustListRoleEnum) -> Result<Self, Self::Error> {
        match role {
            TrustListRoleEnum::PidProvider => Ok(Self::EuPidProvidersList),
            TrustListRoleEnum::WalletProvider => Ok(Self::EuWalletProvidersList),
            TrustListRoleEnum::WrpAcProvider => Ok(Self::EuWrpAcProvidersList),
            TrustListRoleEnum::WrpRcProvider => Ok(Self::EuWrpRcProvidersList),
            TrustListRoleEnum::PubEeaProvider => Ok(Self::EuPubEaaProvidersList),
            TrustListRoleEnum::NationalRegistryRegistrar => Ok(Self::EuRegistrarsAndRegistersList),
            other => Err(LoTEMappingError::UnsupportedRole(format!(
                "no ETSI LoTE type for role: {other:?}"
            ))),
        }
    }
}
