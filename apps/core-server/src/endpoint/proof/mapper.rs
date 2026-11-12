use one_core::provider::verification_protocol::dto::{
    ApplicableCredentialOrFailureHintEnum, PresentationDefinitionTransactionDataDTO,
};
use one_core::service::common_dto::TrustInformationDetailResponseDTO;
use one_core::service::error::ServiceError;
use one_core::service::proof::dto::{
    ProofTransactionDataResponseDTO, ShareProofResponseDTO, ShareProofResponseData,
    TransactionDataResponseDTO,
};
use one_dto_mapper::{convert_inner, try_convert_inner};

use super::dto::{
    ApplicableCredentialOrFailureHintRestEnum, PresentationDefinitionTransactionDataRestDTO,
    ProofTransactionDataResponseRestDTO, ProofTrustInformationDetailResponseRestDTO,
    ShareProofResponseRestDTO, TransactionDataResponseRestDTO,
};
use crate::dto::common::trust_detail::TrustInformationDetailResponseRestEnum;
use crate::mapper::MapperError;

impl TryFrom<ApplicableCredentialOrFailureHintEnum> for ApplicableCredentialOrFailureHintRestEnum {
    type Error = MapperError;

    fn try_from(value: ApplicableCredentialOrFailureHintEnum) -> Result<Self, Self::Error> {
        Ok(match value {
            ApplicableCredentialOrFailureHintEnum::ApplicableCredentials {
                applicable_credentials,
                purpose,
            } => Self::ApplicableCredentials {
                applicable_credentials: try_convert_inner(applicable_credentials)?,
                purpose,
            },
            ApplicableCredentialOrFailureHintEnum::FailureHint { failure_hint } => {
                Self::FailureHint {
                    failure_hint: Box::new((*failure_hint).into()),
                }
            }
        })
    }
}

impl From<PresentationDefinitionTransactionDataDTO>
    for PresentationDefinitionTransactionDataRestDTO
{
    fn from(value: PresentationDefinitionTransactionDataDTO) -> Self {
        let PresentationDefinitionTransactionDataDTO {
            id,
            r#type,
            credential_query_ids,
            ..
        } = value;
        Self {
            id,
            r#type: r#type.to_string(),
            credential_query_ids,
        }
    }
}

impl From<ProofTransactionDataResponseDTO> for ProofTransactionDataResponseRestDTO {
    fn from(value: ProofTransactionDataResponseDTO) -> Self {
        let ProofTransactionDataResponseDTO {
            id,
            r#type,
            credential_query_ids,
            transaction_data_display,
            raw_transaction_data,
            ..
        } = value;
        Self {
            id,
            r#type: r#type.to_string(),
            credential_query_ids,
            transaction_data_display: convert_inner(transaction_data_display),
            raw_transaction_data,
        }
    }
}

impl From<TransactionDataResponseDTO> for TransactionDataResponseRestDTO {
    fn from(value: TransactionDataResponseDTO) -> Self {
        let TransactionDataResponseDTO {
            r#type,
            credential_schema_ids,
            data,
            ..
        } = value;
        Self {
            r#type: r#type.to_string(),
            credential_schema_ids,
            data,
        }
    }
}

impl From<TrustInformationDetailResponseDTO> for ProofTrustInformationDetailResponseRestDTO {
    fn from(value: TrustInformationDetailResponseDTO) -> Self {
        let verifier = convert_inner(value.verifier);

        let eudi_ecosystem =
            if let Some(TrustInformationDetailResponseRestEnum::Eudi(eudi_verifier)) = &verifier {
                Some(eudi_verifier.to_owned())
            } else {
                None
            };

        Self {
            #[expect(deprecated)]
            eudi_ecosystem,
            ecosystem: value.ecosystem,
            verifier,
            ecosystem_errors: value.ecosystem_outcomes.into(),
        }
    }
}

impl TryFrom<ShareProofResponseDTO> for ShareProofResponseRestDTO {
    type Error = ServiceError;

    fn try_from(value: ShareProofResponseDTO) -> Result<Self, Self::Error> {
        let mut result = Self {
            url: None,
            request_json: None,
            expires_at: value.expires_at,
        };

        match value.data {
            ShareProofResponseData::Url(url) => {
                result.url = Some(url);
            }
            ShareProofResponseData::DcApi(request) => {
                result.request_json = Some(
                    serde_json::to_string(&request)
                        .map_err(|e| ServiceError::MappingError(e.to_string()))?,
                );
            }
        };

        Ok(result)
    }
}
