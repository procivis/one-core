use std::sync::Arc;

use one_dto_mapper::convert_inner;
use serde_json::{Value, json};
use shared_types::{HolderWalletUnitId, VerifierInstanceId};

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::holder_wallet_unit::HolderWalletUnitRelations;
use crate::model::list_filter::ListFilterValue;
use crate::model::organisation::OrganisationRelations;
use crate::model::trust_collection::{TrustCollectionFilterValue, TrustCollectionListQuery};
use crate::model::verifier_instance::VerifierInstanceRelations;
use crate::proto::trust_collection::TrustCollectionManager;
use crate::proto::trust_list_subscription_sync::TrustListSubscriptionSync;
use crate::proto::verifier_provider_client::VerifierProviderClient;
use crate::proto::wallet_provider_client::WalletProviderClient;
use crate::provider::task::Task;
use crate::provider::task::trust_collection_sync::dto::Params;
use crate::repository::holder_wallet_unit_repository::HolderWalletUnitRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::verifier_instance_repository::VerifierInstanceRepository;
use crate::service::error::ServiceError;

mod dto;
#[cfg(test)]
mod test;

pub(crate) struct TrustCollectionSyncTask {
    wallet_unit_repository: Arc<dyn HolderWalletUnitRepository>,
    wallet_unit_client: Arc<dyn WalletProviderClient>,
    verifier_instance_repository: Arc<dyn VerifierInstanceRepository>,
    verifier_client: Arc<dyn VerifierProviderClient>,
    trust_collection_sync: Arc<dyn TrustCollectionManager>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    subscription_sync: Arc<dyn TrustListSubscriptionSync>,
}

#[derive(Debug, thiserror::Error)]
pub enum TrustCollectionSyncError {
    #[error("No task params supplied")]
    MissingParams,
    #[error("Invalid task params: {0}")]
    InvalidParams(#[from] serde_json::Error),
    #[error("Wallet unit not found: {0}")]
    WalletUnitNotFound(HolderWalletUnitId),
    #[error("Verifier instance not found: {0}")]
    VerifierInstanceNotFound(VerifierInstanceId),
    #[error("Mapping error: {0}")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for TrustCollectionSyncError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingParams => ErrorCode::BR_0404,
            Self::InvalidParams(_) => ErrorCode::BR_0405,
            Self::WalletUnitNotFound(_) => ErrorCode::BR_0259,
            Self::VerifierInstanceNotFound(_) => ErrorCode::BR_0406,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested_error) => nested_error.error_code(),
        }
    }
}

#[async_trait::async_trait]
impl Task for TrustCollectionSyncTask {
    async fn run(&self, params: Option<Value>) -> Result<Value, ServiceError> {
        let result = self
            .run_internal(params)
            .await
            .error_while("syncing trust collections")?;
        Ok(result)
    }
}

impl TrustCollectionSyncTask {
    pub fn new(
        wallet_unit_repository: Arc<dyn HolderWalletUnitRepository>,
        wallet_unit_client: Arc<dyn WalletProviderClient>,
        verifier_instance_repository: Arc<dyn VerifierInstanceRepository>,
        verifier_client: Arc<dyn VerifierProviderClient>,
        trust_collection_sync: Arc<dyn TrustCollectionManager>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        subscription_sync: Arc<dyn TrustListSubscriptionSync>,
    ) -> Self {
        Self {
            wallet_unit_repository,
            wallet_unit_client,
            verifier_instance_repository,
            verifier_client,
            trust_collection_sync,
            trust_collection_repository,
            subscription_sync,
        }
    }
    async fn run_internal(&self, params: Option<Value>) -> Result<Value, TrustCollectionSyncError> {
        let Some(params) = params else {
            return Err(TrustCollectionSyncError::MissingParams);
        };

        let params: Params = serde_json::from_value(params)?;
        let (organisation_id, url, remote_trust_collections) = match params {
            Params::HolderWalletUnitId(id) => {
                let holder_wallet_unit = self
                    .wallet_unit_repository
                    .get_holder_wallet_unit(
                        &id,
                        &HolderWalletUnitRelations {
                            organisation: Some(OrganisationRelations::default()),
                            ..Default::default()
                        },
                    )
                    .await
                    .error_while("loading wallet unit")?
                    .ok_or(TrustCollectionSyncError::WalletUnitNotFound(id))?;
                let metadata_url = format!(
                    "{}/ssi/wallet-provider/v1/{}",
                    holder_wallet_unit.wallet_provider_url, holder_wallet_unit.wallet_provider_name
                );
                let metadata = self
                    .wallet_unit_client
                    .get_wallet_provider_metadata(&metadata_url)
                    .await
                    .error_while("getting wallet provider metadata")?;
                let org_id = holder_wallet_unit
                    .organisation
                    .ok_or(TrustCollectionSyncError::MappingError(
                        "Missing organisation".to_string(),
                    ))?
                    .id;
                (
                    org_id,
                    holder_wallet_unit.wallet_provider_url,
                    convert_inner(metadata.trust_collections),
                )
            }
            Params::VerifierInstanceId(id) => {
                let verifier_instance = self
                    .verifier_instance_repository
                    .get(
                        &id,
                        &VerifierInstanceRelations {
                            organisation: Some(OrganisationRelations::default()),
                        },
                    )
                    .await
                    .error_while("loading verifier instance")?
                    .ok_or(TrustCollectionSyncError::VerifierInstanceNotFound(id))?;
                let metadata_url = format!(
                    "{}/ssi/verifier-provider/v1/{}",
                    verifier_instance.provider_url, verifier_instance.provider_name
                );
                let metadata = self
                    .verifier_client
                    .get_verifier_provider_metadata(&metadata_url)
                    .await
                    .error_while("getting verifier provider metadata")?;
                let org_id = verifier_instance
                    .organisation
                    .ok_or(TrustCollectionSyncError::MappingError(
                        "Missing organisation".to_string(),
                    ))?
                    .id;
                (
                    org_id,
                    verifier_instance.provider_url,
                    convert_inner(metadata.trust_collections),
                )
            }
        };

        let synced_collections = self
            .trust_collection_sync
            .sync_remote_trust_collections(&url, remote_trust_collections, organisation_id)
            .await
            .error_while("creating empty trust collections")?;

        let collections = self
            .trust_collection_repository
            .list(TrustCollectionListQuery {
                filtering: Some(
                    TrustCollectionFilterValue::OrganisationId(organisation_id).condition()
                        & TrustCollectionFilterValue::Ids(synced_collections)
                        & TrustCollectionFilterValue::Remote(true)
                        // Empty collections are not enabled and hence should not be synced
                        // (which fills in the trust list subscriptions)
                        & TrustCollectionFilterValue::Empty(false),
                ),
                ..Default::default()
            })
            .await
            .error_while("listing trust collections")?;

        for collection in &collections.values {
            self.subscription_sync
                .sync_subscriptions(collection)
                .await
                .error_while("syncing subscriptions")?;
        }

        Ok(json!({
            "trustCollectionIds": collections.values.iter().map(|c| c.id).collect::<Vec<_>>(),
        }))
    }
}
