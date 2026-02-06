use one_core::service::error::{BusinessLogicError, ServiceError};
use one_core::service::wallet_provider::dto::{
    IssueWalletUnitAttestationRequestDTO, IssueWalletUnitAttestationResponseDTO,
};
use one_dto_mapper::convert_inner;

use super::dto::{
    IssueWalletUnitAttestationRequestRestDTO, IssueWalletUnitAttestationResponseRestDTO,
};

impl TryFrom<IssueWalletUnitAttestationRequestRestDTO> for IssueWalletUnitAttestationRequestDTO {
    type Error = ServiceError;

    fn try_from(value: IssueWalletUnitAttestationRequestRestDTO) -> Result<Self, Self::Error> {
        // ONE-8735: backward compatible handling of input
        let wia = match (value.waa, value.wia) {
            (waa, wia) if waa.is_empty() => wia,
            (waa, wia) if wia.is_empty() => {
                tracing::warn!("Using deprecated `waa` request");
                waa
            }
            _ => {
                return Err(BusinessLogicError::GeneralInputValidationError.into());
            }
        };

        Ok(Self {
            wia: convert_inner(wia),
            wua: convert_inner(value.wua),
        })
    }
}

impl From<IssueWalletUnitAttestationResponseDTO> for IssueWalletUnitAttestationResponseRestDTO {
    fn from(value: IssueWalletUnitAttestationResponseDTO) -> Self {
        Self {
            // ONE-8735: duplicit data for backward compatibility
            waa: value.wia.clone(),
            wia: value.wia,
            wua: value.wua,
        }
    }
}
