use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use itertools::Itertools;
use one_crypto::get_hasher;
use proc_macros::Provider;
use serde::Deserialize;
use serde_json::json;
use serde_with::{DurationSeconds, serde_as};
use shared_types::TransactionDataType;
use standardized_types::eudi_ts12::{Payload, TransactionData as ScaEntry, TransactionType};
use standardized_types::iana;
use standardized_types::openid4vp::dcql::CredentialQueryId;
use standardized_types::openid4vp::{TRANSACTION_DATA_HASHES, TRANSACTION_DATA_HASHES_ALG};
use time::Duration;

use super::error::TransactionDataError;
use super::processed_transaction_data::ProcessedTransactionData;
use super::{
    Features, TransactionData, TransactionDataAuthorization, TransactionDataCapabilities,
    TransactionDataDisplayParams, TransactionDataMetadata, decode_transaction_data,
};
use crate::config::core_config::FormatType;
use crate::provider::presentation_formatter::model::PresentedTransactionData;
use crate::provider::provider_directory::InitializationError;

mod model;
#[cfg(test)]
mod test;

use model::TransactionTypeExt;

#[serde_as]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Params {
    transaction_data_display_params: TransactionDataDisplayParams,
    #[serde_as(as = "DurationSeconds<i64>")]
    leeway_seconds: Duration,
}

#[derive(Provider)]
pub struct ScaTransactionData {
    config_id: TransactionDataType,
    transaction_type: TransactionType,
    params: Params,
}

impl ScaTransactionData {
    pub fn new(
        config_id: TransactionDataType,
        transaction_type: TransactionType,
        params: serde_json::Value,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        Ok(Self {
            config_id,
            transaction_type,
            params,
        })
    }

    /// Hash of the entry as received, base64url-encoded, per OpenID4VP section 8.4
    fn hash(
        &self,
        transaction_data: &str,
        algorithm: iana::HashAlgorithm,
    ) -> Result<String, TransactionDataError> {
        Ok(get_hasher(algorithm)?.hash_base64_url(transaction_data.as_bytes())?)
    }

    fn validate_entry(&self, entry: &ScaEntry) -> Result<(), TransactionDataError> {
        if entry.credential_ids.is_empty() {
            return Err(TransactionDataError::InvalidTransactionData(
                "credential_ids must not be empty".to_string(),
            ));
        }

        self.transaction_type
            .validate_payload(&entry.extension.payload, self.params.leeway_seconds)?;

        // an entry that offers only algorithms we cannot compute can never be answered
        let offered = entry
            .transaction_data_hashes_alg
            .as_deref()
            .unwrap_or(&[iana::HashAlgorithm::Sha256]);
        if !offered
            .iter()
            .any(|algorithm| get_hasher(*algorithm).is_ok())
        {
            return Err(TransactionDataError::UnsupportedHashAlgorithm(
                offered.iter().join(", "),
            ));
        }

        Ok(())
    }
}

#[async_trait]
impl TransactionData for ScaTransactionData {
    fn prepare_transaction_data(
        &self,
        credential_ids: Vec<CredentialQueryId>,
        data: Option<serde_json::Value>,
    ) -> Result<String, TransactionDataError> {
        let entry = ScaEntry {
            r#type: self.transaction_type.to_string(),
            credential_ids: credential_ids.iter().map(ToString::to_string).collect(),
            // required by TS12 section 4.2
            transaction_data_hashes_alg: Some(vec![iana::HashAlgorithm::Sha256]),
            extension: Payload {
                payload: self
                    .transaction_type
                    .payload_from_request(data.unwrap_or_default())?,
            },
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
        let entry: ScaEntry = decode_transaction_data(transaction_data)?;
        self.validate_entry(&entry)?;

        Ok(TransactionDataMetadata {
            credential_ids: entry.credential_ids.into_iter().map(Into::into).collect(),
        })
    }

    async fn process_transaction_data(
        &self,
        transaction_data: &str,
        // formats outside the capabilities are rejected by the `CapabilityChecked` decorator
        _format: FormatType,
        hash_algorithm: iana::HashAlgorithm,
    ) -> Result<ProcessedTransactionData, TransactionDataError> {
        Ok(ProcessedTransactionData::KbJwtClaims(
            serde_json::Map::from_iter([
                (
                    TRANSACTION_DATA_HASHES.to_string(),
                    json!([self.hash(transaction_data, hash_algorithm)?]),
                ),
                (
                    TRANSACTION_DATA_HASHES_ALG.to_string(),
                    hash_algorithm.to_string().into(),
                ),
            ]),
        ))
    }

    async fn verify_transaction_data(
        &self,
        transaction_data: &str,
        // formats outside the capabilities are rejected by the `CapabilityChecked` decorator
        _format: FormatType,
        presented: &PresentedTransactionData,
    ) -> Result<TransactionDataAuthorization, TransactionDataError> {
        let PresentedTransactionData::KbJwtClaims(presented) = presented else {
            return Ok(TransactionDataAuthorization::NotAuthorized);
        };

        let request: ScaEntry = decode_transaction_data(transaction_data)?;

        // evidence that does not follow the rules of OpenID4VP appendix B.3.3.1 is
        // unauthorized, rather than an error
        let offered = request
            .transaction_data_hashes_alg
            .as_deref()
            .unwrap_or(&[iana::HashAlgorithm::Sha256]);
        let algorithm = match presented.get(TRANSACTION_DATA_HASHES_ALG) {
            // the hash function must be one of the values the request named
            Some(algorithm) => {
                let Some(algorithm) = algorithm
                    .as_str()
                    .and_then(|algorithm| algorithm.parse().ok())
                    .filter(|algorithm| offered.contains(algorithm))
                else {
                    return Ok(TransactionDataAuthorization::NotAuthorized);
                };
                algorithm
            }
            // the request named no algorithms, so the hash function must be `sha-256`
            None if request.transaction_data_hashes_alg.is_none() => iana::HashAlgorithm::Sha256,
            // the claim is required when the request named algorithms
            None => return Ok(TransactionDataAuthorization::NotAuthorized),
        };

        // the claim covers every entry the credential authorizes, including this one
        let expected = self.hash(transaction_data, algorithm)?;
        let authorized = presented
            .get(TRANSACTION_DATA_HASHES)
            .and_then(|hashes| hashes.as_array())
            .is_some_and(|hashes| {
                hashes
                    .iter()
                    .any(|hash| hash.as_str() == Some(expected.as_str()))
            });

        Ok(if authorized {
            TransactionDataAuthorization::Authorized
        } else {
            TransactionDataAuthorization::NotAuthorized
        })
    }

    fn get_capabilities(&self) -> TransactionDataCapabilities {
        TransactionDataCapabilities {
            transaction_data_types: vec![self.transaction_type.to_string()],
            // TS12 defines no mdoc encoding for the SCA transaction data types
            formats: vec![FormatType::SdJwtVc],
            // the hashes of all entries share one claim, so a single credential can
            // authorize any number of them
            features: vec![Features::SupportsMultipleTxDataPerPresentation],
        }
    }

    fn config_name(&self) -> &TransactionDataType {
        &self.config_id
    }

    fn display_params(&self) -> &TransactionDataDisplayParams {
        &self.params.transaction_data_display_params
    }
}
