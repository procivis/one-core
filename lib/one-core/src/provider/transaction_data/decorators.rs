use std::fmt::Display;
use std::sync::Arc;

use async_trait::async_trait;
use shared_types::TransactionDataType;
use standardized_types::openid4vp::dcql::CredentialQueryId;
use standardized_types::{iana, openid4vp};

use crate::config::core_config::FormatType;
use crate::provider::Provider;
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::presentation_formatter::model::PresentedTransactionData;
use crate::provider::provider_directory::WithDisabledDecorator;
use crate::provider::transaction_data::error::TransactionDataError;
use crate::provider::transaction_data::processed_transaction_data::ProcessedTransactionData;
use crate::provider::transaction_data::{
    TransactionData, TransactionDataAuthorization, TransactionDataCapabilities,
    TransactionDataDisplayParams, TransactionDataDisplayValue, TransactionDataMetadata,
    decode_transaction_data,
};

impl WithDisabledDecorator for dyn TransactionData {
    fn decorate(self: Arc<dyn TransactionData>) -> Arc<dyn TransactionData> {
        Arc::new(DisabledProvider::new(self))
    }
}

#[async_trait]
impl<T: Provider + TransactionData + Display + ?Sized> TransactionData for DisabledProvider<T> {
    fn prepare_transaction_data(
        &self,
        _credential_ids: Vec<CredentialQueryId>,
        _data: Option<serde_json::Value>,
    ) -> Result<String, TransactionDataError> {
        self.disabled_error()
    }

    fn validate_transaction_data(
        &self,
        _transaction_data: &str,
    ) -> Result<TransactionDataMetadata, TransactionDataError> {
        self.disabled_error()
    }

    async fn process_transaction_data(
        &self,
        _transaction_data: &str,
        _format: FormatType,
        _hash_algorithm: iana::HashAlgorithm,
    ) -> Result<ProcessedTransactionData, TransactionDataError> {
        self.disabled_error()
    }

    async fn verify_transaction_data(
        &self,
        _transaction_data: &str,
        _format: FormatType,
        _presented: &PresentedTransactionData,
    ) -> Result<TransactionDataAuthorization, TransactionDataError> {
        self.disabled_error()
    }

    fn get_capabilities(&self) -> TransactionDataCapabilities {
        self.inner().get_capabilities()
    }

    fn config_name(&self) -> &TransactionDataType {
        self.inner().config_name()
    }

    fn display_params(&self) -> &TransactionDataDisplayParams {
        self.inner().display_params()
    }

    fn get_display_data(
        &self,
        transaction_data: &str,
    ) -> Result<Vec<TransactionDataDisplayValue>, TransactionDataError> {
        self.inner().get_display_data(transaction_data)
    }
}

/// Rejects transaction data of unsupported types
pub(super) struct CapabilityChecked(pub Arc<dyn TransactionData>);

impl CapabilityChecked {
    fn check_supported(&self, transaction_data: &str) -> Result<(), TransactionDataError> {
        let entry: openid4vp::TransactionData = decode_transaction_data(transaction_data)?;

        if !self
            .0
            .get_capabilities()
            .transaction_data_types
            .contains(&entry.r#type)
        {
            return Err(TransactionDataError::UnsupportedType(entry.r#type));
        }

        Ok(())
    }
}

impl Provider for CapabilityChecked {
    fn capabilities(&self) -> Option<serde_json::Value> {
        self.0.capabilities()
    }
}

#[async_trait]
impl TransactionData for CapabilityChecked {
    fn prepare_transaction_data(
        &self,
        credential_ids: Vec<CredentialQueryId>,
        data: Option<serde_json::Value>,
    ) -> Result<String, TransactionDataError> {
        self.0.prepare_transaction_data(credential_ids, data)
    }

    fn validate_transaction_data(
        &self,
        transaction_data: &str,
    ) -> Result<TransactionDataMetadata, TransactionDataError> {
        self.check_supported(transaction_data)?;
        self.0.validate_transaction_data(transaction_data)
    }

    async fn process_transaction_data(
        &self,
        transaction_data: &str,
        format: FormatType,
        hash_algorithm: iana::HashAlgorithm,
    ) -> Result<ProcessedTransactionData, TransactionDataError> {
        self.check_supported(transaction_data)?;

        if !self.0.get_capabilities().formats.contains(&format) {
            return Err(TransactionDataError::UnsupportedCredentialFormat(format));
        }

        self.0
            .process_transaction_data(transaction_data, format, hash_algorithm)
            .await
    }

    async fn verify_transaction_data(
        &self,
        transaction_data: &str,
        format: FormatType,
        presented: &PresentedTransactionData,
    ) -> Result<TransactionDataAuthorization, TransactionDataError> {
        self.check_supported(transaction_data)?;

        if !self.0.get_capabilities().formats.contains(&format) {
            return Err(TransactionDataError::UnsupportedCredentialFormat(format));
        }

        self.0
            .verify_transaction_data(transaction_data, format, presented)
            .await
    }

    fn get_capabilities(&self) -> TransactionDataCapabilities {
        self.0.get_capabilities()
    }

    fn config_name(&self) -> &TransactionDataType {
        self.0.config_name()
    }

    fn display_params(&self) -> &TransactionDataDisplayParams {
        self.0.display_params()
    }

    fn get_display_data(
        &self,
        transaction_data: &str,
    ) -> Result<Vec<TransactionDataDisplayValue>, TransactionDataError> {
        self.check_supported(transaction_data)?;
        self.0.get_display_data(transaction_data)
    }
}

#[cfg(test)]
mod test {
    use std::assert_matches;

    use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
    use serde_json::json;

    use super::*;
    use crate::provider::transaction_data::MockTransactionData;

    fn capabilities() -> TransactionDataCapabilities {
        TransactionDataCapabilities {
            transaction_data_types: vec!["https://example.com/type".to_string()],
            formats: vec![FormatType::SdJwtVc],
            features: vec![],
        }
    }

    fn encode(transaction_data: serde_json::Value) -> String {
        Base64UrlSafeNoPadding::encode_to_string(serde_json::to_vec(&transaction_data).unwrap())
            .unwrap()
    }

    #[test]
    fn capability_checked_delegates_supported_types() {
        let mut inner = MockTransactionData::new();
        inner.expect_get_capabilities().return_once(capabilities);
        inner.expect_validate_transaction_data().return_once(|_| {
            Ok(TransactionDataMetadata {
                credential_ids: vec!["cred1".into()],
            })
        });

        CapabilityChecked(Arc::new(inner))
            .validate_transaction_data(&encode(
                json!({ "type": "https://example.com/type", "credential_ids": ["cred1"] }),
            ))
            .unwrap();
    }

    #[tokio::test]
    async fn capability_checked_rejects_unsupported_formats() {
        let mut inner = MockTransactionData::new();
        inner.expect_get_capabilities().returning(capabilities);

        let result = CapabilityChecked(Arc::new(inner))
            .process_transaction_data(
                &encode(json!({ "type": "https://example.com/type", "credential_ids": ["cred1"] })),
                FormatType::Mdoc,
                iana::HashAlgorithm::Sha256,
            )
            .await;

        assert_matches!(
            result,
            Err(TransactionDataError::UnsupportedCredentialFormat(_))
        );
    }

    #[test]
    fn capability_checked_rejects_unsupported_types() {
        let mut inner = MockTransactionData::new();
        inner.expect_get_capabilities().return_once(capabilities);

        let result = CapabilityChecked(Arc::new(inner)).validate_transaction_data(&encode(
            json!({ "type": "https://example.com/other", "credential_ids": ["cred1"] }),
        ));

        assert_matches!(result, Err(TransactionDataError::UnsupportedType(_)));
    }
}
