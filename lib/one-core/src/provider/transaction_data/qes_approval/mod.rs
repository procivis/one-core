use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use indexmap::IndexMap;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::{Hasher, get_hasher};
use proc_macros::Provider;
use serde::Deserialize;
use shared_types::TransactionDataType;
use standardized_types::csc::transaction_data::{
    QES_APPROVAL_KB_JWT_CLAIM, QES_APPROVAL_MDOC_ELEMENT, QES_APPROVAL_MDOC_NAMESPACE,
    QES_APPROVAL_TRANSACTION_DATA_TYPE, QesApprovalRequest,
    QesApprovalTransactionData as QesApprovalEntry,
};
use standardized_types::iana;
use standardized_types::openid4vp::dcql::CredentialQueryId;

use super::error::TransactionDataError;
use super::processed_transaction_data::ProcessedTransactionData;
use super::{
    TransactionData, TransactionDataAuthorization, TransactionDataCapabilities,
    TransactionDataDisplayParams, TransactionDataMetadata, TransactionDataParams,
    decode_transaction_data,
};
use crate::config::core_config::FormatType;
use crate::provider::presentation_formatter::model::PresentedTransactionData;
use crate::provider::provider_directory::InitializationError;

#[cfg(test)]
mod test;

#[derive(Provider)]
pub struct QesApprovalTransactionData {
    config_id: TransactionDataType,
    params: TransactionDataParams,
}

impl QesApprovalTransactionData {
    pub fn new(
        config_id: TransactionDataType,
        params: serde_json::Value,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        Ok(Self { config_id, params })
    }

    fn validate_entry(&self, entry: &QesApprovalEntry) -> Result<(), TransactionDataError> {
        if entry.credential_ids.is_empty() {
            return Err(TransactionDataError::InvalidTransactionData(
                "credential_ids must not be empty".to_string(),
            ));
        }

        if entry.extension.credential_id.is_none() && entry.extension.signature_qualifier.is_none()
        {
            return Err(TransactionDataError::InvalidTransactionData(
                "at least one of credentialID and signatureQualifier must be present".to_string(),
            ));
        }

        get_hasher(entry.extension.hash_algorithm.into())?;

        Ok(())
    }

    fn evidence(
        &self,
        transaction_data: &str,
        format: FormatType,
    ) -> Result<ProcessedTransactionData, TransactionDataError> {
        let entry: QesApprovalEntry = decode_transaction_data(transaction_data)?;

        match format {
            // data model bindings section 7.2.1.2: hash the base64url-encoded
            // transaction data as received, using the hashAlgorithmOID algorithm
            FormatType::SdJwtVc => {
                let qes_approval = get_hasher(entry.extension.hash_algorithm.into())?
                    .hash_base64(transaction_data.as_bytes())?;

                Ok(ProcessedTransactionData::KbJwtClaims(
                    serde_json::Map::from_iter([(
                        QES_APPROVAL_KB_JWT_CLAIM.to_string(),
                        qes_approval.into(),
                    )]),
                ))
            }
            // data model bindings section 7.2.1.1: the mdoc encoding pins SHA-256
            // regardless of the requested hashAlgorithmOID, hashed over the
            // base64url-decoded transaction data and represented as a raw byte string
            FormatType::Mdoc => {
                let decoded = Base64UrlSafeNoPadding::decode_to_vec(transaction_data, None)?;
                let digest = SHA256.hash(&decoded)?;

                Ok(ProcessedTransactionData::DeviceSignedElements(
                    IndexMap::from([(
                        QES_APPROVAL_MDOC_NAMESPACE.to_string(),
                        IndexMap::from([(
                            QES_APPROVAL_MDOC_ELEMENT.to_string(),
                            ciborium::Value::Bytes(digest),
                        )]),
                    )]),
                ))
            }
            other => Err(TransactionDataError::UnsupportedCredentialFormat(other)),
        }
    }
}

#[async_trait]
impl TransactionData for QesApprovalTransactionData {
    fn prepare_transaction_data(
        &self,
        credential_ids: Vec<CredentialQueryId>,
        data: Option<serde_json::Value>,
    ) -> Result<String, TransactionDataError> {
        let entry = QesApprovalEntry {
            r#type: QES_APPROVAL_TRANSACTION_DATA_TYPE.to_string(),
            credential_ids: credential_ids.iter().map(ToString::to_string).collect(),
            // the field belongs to the OpenID4VP `transaction_data_hashes` profile,
            // which this type does not use: consent is expressed through the CSC claim
            transaction_data_hashes_alg: None,
            extension: QesApprovalRequest::deserialize(&data.unwrap_or_default())?,
        };

        self.validate_entry(&entry)?;

        Ok(Base64UrlSafeNoPadding::encode_to_string(
            serde_json::to_vec(&entry)?,
        )?)
    }

    fn validate_transaction_data(
        &self,
        transaction_data: &str,
    ) -> Result<TransactionDataMetadata, TransactionDataError> {
        let entry: QesApprovalEntry = decode_transaction_data(transaction_data)?;
        self.validate_entry(&entry)?;

        Ok(TransactionDataMetadata {
            credential_ids: entry.credential_ids.into_iter().map(Into::into).collect(),
        })
    }

    async fn process_transaction_data(
        &self,
        transaction_data: &str,
        format: FormatType,
        // the CSC claim pins the algorithm through `hashAlgorithmOID`, so the one the
        // OpenID4VP profile agreed for the credential does not apply
        _hash_algorithm: iana::HashAlgorithm,
    ) -> Result<ProcessedTransactionData, TransactionDataError> {
        self.evidence(transaction_data, format)
    }

    // processing has no side effects for this type, the expected evidence can simply
    // be recomputed and compared
    async fn verify_transaction_data(
        &self,
        transaction_data: &str,
        format: FormatType,
        presented: &PresentedTransactionData,
    ) -> Result<TransactionDataAuthorization, TransactionDataError> {
        let expected = self.evidence(transaction_data, format)?;

        let authorized = match (&expected, presented) {
            (
                ProcessedTransactionData::KbJwtClaims(expected),
                PresentedTransactionData::KbJwtClaims(presented),
            ) => expected
                .iter()
                .all(|(claim, value)| presented.get(claim) == Some(value)),
            (
                ProcessedTransactionData::DeviceSignedElements(expected),
                PresentedTransactionData::DeviceSignedElements(presented),
            ) => expected.iter().all(|(namespace, elements)| {
                presented.get(namespace).is_some_and(|presented| {
                    elements
                        .iter()
                        .all(|(element, value)| presented.get(element) == Some(value))
                })
            }),
            _ => false,
        };

        Ok(if authorized {
            TransactionDataAuthorization::Authorized
        } else {
            TransactionDataAuthorization::NotAuthorized
        })
    }

    fn get_capabilities(&self) -> TransactionDataCapabilities {
        TransactionDataCapabilities {
            transaction_data_types: vec![QES_APPROVAL_TRANSACTION_DATA_TYPE.to_string()],
            formats: vec![FormatType::SdJwtVc, FormatType::Mdoc],
            features: vec![],
        }
    }

    fn config_name(&self) -> &TransactionDataType {
        &self.config_id
    }

    fn display_params(&self) -> &TransactionDataDisplayParams {
        &self.params.transaction_data_display_params
    }
}
