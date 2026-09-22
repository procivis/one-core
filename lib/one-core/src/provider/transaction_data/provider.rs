use std::sync::Arc;

use shared_types::TransactionDataType;
use standardized_types::eudi_ts12::TransactionType;
use standardized_types::openid4vp;

use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, Fields, TransactionDataProviderType};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::provider::provider_directory::ProviderDirectory;
use crate::provider::transaction_data::decorators::CapabilityChecked;
use crate::provider::transaction_data::error::TransactionDataError;
use crate::provider::transaction_data::qes_approval::QesApprovalTransactionData;
use crate::provider::transaction_data::sca::ScaTransactionData;
use crate::provider::transaction_data::{TransactionData, decode_transaction_data};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait TransactionDataProvider: Send + Sync {
    /// Resolves the provider from the `type` field of a base64url-encoded
    /// OpenID4VP `transaction_data` entry
    fn get_transaction_data(
        &self,
        transaction_data: &str,
    ) -> Result<(TransactionDataType, Arc<dyn TransactionData>), NestedError>;

    /// Resolves the provider by its config name
    fn get_transaction_data_by_name(
        &self,
        name: &TransactionDataType,
    ) -> Result<Arc<dyn TransactionData>, NestedError>;
}

impl TransactionDataProvider
    for ProviderDirectory<
        TransactionDataType,
        Fields<TransactionDataProviderType>,
        dyn TransactionData,
    >
{
    fn get_transaction_data(
        &self,
        // base64url-encoded transaction data
        transaction_data: &str,
    ) -> Result<(TransactionDataType, Arc<dyn TransactionData>), NestedError> {
        let entry: openid4vp::TransactionData =
            decode_transaction_data(transaction_data).error_while("decoding transaction data")?;

        let (name, provider) = self
            .iter()
            .find(|(_, provider)| {
                provider
                    .get_capabilities()
                    .transaction_data_types
                    .contains(&entry.r#type)
            })
            .ok_or(TransactionDataError::UnsupportedType(entry.r#type.clone()))
            .error_while("resolving transaction data provider")?;

        Ok((name.clone(), provider.clone()))
    }

    fn get_transaction_data_by_name(
        &self,
        name: &TransactionDataType,
    ) -> Result<Arc<dyn TransactionData>, NestedError> {
        self.provider(name)
    }
}

pub(crate) fn transaction_data_provider_from_config(
    config: &mut CoreConfig,
) -> Result<Arc<dyn TransactionDataProvider>, ConfigValidationError> {
    let directory = ProviderDirectory::initialize(
        config.transaction_data_provider.iter_mut(),
        |name: &TransactionDataType, fields: &Fields<TransactionDataProviderType>| {
            let provider: Arc<dyn TransactionData> = match fields.r#type {
                TransactionDataProviderType::QesApproval => Arc::new(
                    QesApprovalTransactionData::new(name.clone(), fields.merge_fields())?,
                ),
                TransactionDataProviderType::ScaLoginRiskTransaction => {
                    Arc::new(ScaTransactionData::new(
                        name.clone(),
                        TransactionType::LoginRiskTransaction,
                        fields.merge_fields(),
                    )?)
                }
                TransactionDataProviderType::ScaPaymentConfirmation => {
                    Arc::new(ScaTransactionData::new(
                        name.clone(),
                        TransactionType::Payment,
                        fields.merge_fields(),
                    )?)
                }
                TransactionDataProviderType::ScaAccountAccess => Arc::new(ScaTransactionData::new(
                    name.clone(),
                    TransactionType::AccountAccess,
                    fields.merge_fields(),
                )?),
                TransactionDataProviderType::ScaEmandate => Arc::new(ScaTransactionData::new(
                    name.clone(),
                    TransactionType::Emandate,
                    fields.merge_fields(),
                )?),
            };
            let provider: Arc<dyn TransactionData> = Arc::new(CapabilityChecked(provider));

            Ok(provider)
        },
    )
    .error_while("initializing transaction data provider")?;

    Ok(Arc::new(directory))
}
