use std::collections::HashSet;
use std::sync::Arc;

use InstanceFilterValue::Status;
use serde_json::{Value, json};
use shared_types::{EcosystemId, InstanceId, OrganisationId, TrustCollectionId};

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::instance::{
    Instance, InstanceFilterValue, InstanceListQuery, InstanceRole, InstanceStatus,
};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::model::trust_collection::{TrustCollectionFilterValue, TrustCollectionListQuery};
use crate::proto::trust_collection::TrustCollectionManager;
use crate::proto::trust_collection::dto::RemoteTrustCollectionInfoDTO;
use crate::proto::trust_collection::legacy_selection::legacy_deselected_collections;
use crate::proto::trust_list_subscription_sync::TrustListSubscriptionSync;
use crate::proto::verifier_provider_client::VerifierProviderClient;
use crate::proto::wallet_provider_client::WalletProviderClient;
use crate::proto::wallet_provider_client::dto::MetadataTarget;
use crate::provider::task::Task;
use crate::repository::instance_repository::InstanceRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::service::error::ServiceError;
use crate::service::instance::service::provider_metadata_url;
use crate::service::managed_instance::ecosystem_metadata::remote_trust_collections;

#[cfg(test)]
mod test;

pub(crate) struct EcosystemSyncTask {
    instance_repository: Arc<dyn InstanceRepository>,
    wallet_unit_client: Arc<dyn WalletProviderClient>,
    verifier_client: Arc<dyn VerifierProviderClient>,
    trust_collection_manager: Arc<dyn TrustCollectionManager>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    subscription_sync: Arc<dyn TrustListSubscriptionSync>,
}

#[derive(Debug, thiserror::Error)]
pub enum EcosystemSyncError {
    #[error("Invalid task params: {0}")]
    InvalidParams(#[from] serde_json::Error),
    #[error("Wallet unit not found: {0}")]
    WalletUnitNotFound(InstanceId),
    #[error("Mapping error: {0}")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for EcosystemSyncError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidParams(_) => ErrorCode::BR_0405,
            Self::WalletUnitNotFound(_) => ErrorCode::BR_0259,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested_error) => nested_error.error_code(),
        }
    }
}

#[async_trait::async_trait]
impl Task for EcosystemSyncTask {
    async fn run(&self, _params: Option<Value>) -> Result<Value, ServiceError> {
        let result = self
            .run_internal()
            .await
            .error_while("syncing ecosystems")?;
        Ok(result)
    }
}

/// The trust collections a provider advertises for an organisation, together with
/// the ecosystems that organisation has selected.
struct RemoteCollectionData {
    organisation_id: OrganisationId,
    selected_ecosystems: Vec<EcosystemId>,
    provider_url: String,
    remote_collections: Vec<RemoteTrustCollectionInfoDTO>,
}

impl EcosystemSyncTask {
    pub fn new(
        instance_repository: Arc<dyn InstanceRepository>,
        wallet_unit_client: Arc<dyn WalletProviderClient>,
        verifier_client: Arc<dyn VerifierProviderClient>,
        trust_collection_manager: Arc<dyn TrustCollectionManager>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        subscription_sync: Arc<dyn TrustListSubscriptionSync>,
    ) -> Self {
        Self {
            instance_repository,
            wallet_unit_client,
            verifier_client,
            trust_collection_manager,
            trust_collection_repository,
            subscription_sync,
        }
    }
    async fn run_internal(&self) -> Result<Value, EcosystemSyncError> {
        let synced_collections_count = self.sync_instance_collections().await?;
        Ok(json!({
            "syncedTrustCollectionsCount": synced_collections_count,
        }))
    }

    async fn sync_instance_collections(&self) -> Result<usize, EcosystemSyncError> {
        let mut count = 0;
        let mut page = 0;
        loop {
            let mut data_to_sync = vec![];
            let instances = self
                .instance_repository
                .list(InstanceListQuery {
                    pagination: Some(ListPagination {
                        page,
                        page_size: 1000,
                    }),
                    filtering: Some(
                        Status(InstanceStatus::Active).condition()
                            | Status(InstanceStatus::Unattested),
                    ),
                    ..Default::default()
                })
                .await
                .error_while("listing holder wallet instances")?;
            if instances.values.is_empty() {
                break;
            }
            for instance in instances.values {
                let data = self.fetch_data_for_instance(instance).await?;
                data_to_sync.push(data);
            }
            count += self.sync_collections(data_to_sync).await?;
            page += 1;
        }
        Ok(count)
    }

    async fn sync_collections(
        &self,
        data_to_sync: Vec<RemoteCollectionData>,
    ) -> Result<usize, EcosystemSyncError> {
        let mut count = 0;
        for RemoteCollectionData {
            organisation_id,
            selected_ecosystems,
            provider_url,
            remote_collections,
        } in data_to_sync
        {
            // TODO (ONE-10972): remove together with the deprecated per-collection selection API.
            // Read before syncing, so that collections created by this run - which have
            // no subscriptions yet and would make their ecosystem look mixed - cannot be
            // mistaken for a deselection.
            let legacy_deselected = if selected_ecosystems.is_empty() {
                HashSet::new()
            } else {
                self.legacy_deselected_collections(organisation_id).await?
            };

            // All advertised collections are mirrored locally so that the organisation can
            // select their ecosystem later on, only the selected ones are subscribed to.
            let synced_collections = self
                .trust_collection_manager
                .sync_remote_trust_collections(&provider_url, remote_collections, organisation_id)
                .await
                .error_while("syncing trust collections")?;

            if selected_ecosystems.is_empty() {
                continue;
            }

            let collections = self
                .trust_collection_repository
                .list(TrustCollectionListQuery {
                    filtering: Some(
                        TrustCollectionFilterValue::OrganisationId {
                            id: organisation_id,
                            // Parent organisation must not be modified, hence not synced
                            include_inherited_collections: false,
                        }
                        .condition()
                            & TrustCollectionFilterValue::Ids(synced_collections)
                            & TrustCollectionFilterValue::Remote(true)
                            // Collections of an ecosystem the organisation did not select
                            // are not enabled and hence should not be synced (which fills
                            // in the trust list subscriptions)
                            & TrustCollectionFilterValue::Ecosystems(selected_ecosystems),
                    ),
                    ..Default::default()
                })
                .await
                .error_while("listing trust collections")?;

            let to_sync = collections
                .values
                .iter()
                // TODO (ONE-10972): remove together with the deprecated
                // per-collection selection API.
                .filter(|collection| !legacy_deselected.contains(&collection.id));

            for collection in to_sync {
                self.subscription_sync
                    .sync_subscriptions(collection)
                    .await
                    .error_while("syncing subscriptions")?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// TODO (ONE-10972): remove together with the deprecated per-collection selection API.
    ///
    /// Collections an organisation excluded through the deprecated per-collection
    /// selection, which the ecosystem selection must not silently re-subscribe.
    async fn legacy_deselected_collections(
        &self,
        organisation_id: OrganisationId,
    ) -> Result<HashSet<TrustCollectionId>, EcosystemSyncError> {
        let organisation_collections = TrustCollectionFilterValue::OrganisationId {
            id: organisation_id,
            include_inherited_collections: false,
        };

        let collections = self
            .trust_collection_repository
            .list(TrustCollectionListQuery {
                filtering: Some(organisation_collections.clone().condition()),
                ..Default::default()
            })
            .await
            .error_while("listing trust collections")?;

        let subscribed = self
            .trust_collection_repository
            .list(TrustCollectionListQuery {
                filtering: Some(
                    organisation_collections.condition() & TrustCollectionFilterValue::Empty(false),
                ),
                ..Default::default()
            })
            .await
            .error_while("listing subscribed trust collections")?
            .values
            .into_iter()
            .map(|collection| collection.id)
            .collect();

        Ok(legacy_deselected_collections(
            &collections.values,
            &subscribed,
        ))
    }

    async fn fetch_data_for_instance(
        &self,
        instance: Instance,
    ) -> Result<RemoteCollectionData, EcosystemSyncError> {
        let metadata_url = provider_metadata_url(
            &instance.provider_url,
            &instance.provider_name,
            instance.role,
        );
        let remote_collections = match instance.role {
            InstanceRole::Wallet => {
                let metadata = self
                    .wallet_unit_client
                    .get_wallet_provider_metadata(MetadataTarget {
                        r#type: instance.provider_type,
                        metadata_url,
                    })
                    .await
                    .error_while("getting wallet provider metadata")?;
                remote_trust_collections(&metadata.ecosystems)
            }
            InstanceRole::Verifier => {
                let metadata = self
                    .verifier_client
                    .get_verifier_provider_metadata(&metadata_url)
                    .await
                    .error_while("getting verifier provider metadata")?;
                remote_trust_collections(&metadata.ecosystems)
            }
        };
        let organisation = instance
            .organisation
            .as_ref()
            .await
            .error_while("getting organisation of holder wallet instance")?;
        Ok(RemoteCollectionData {
            organisation_id: organisation.id,
            selected_ecosystems: organisation.configuration.selected_ecosystems.to_owned(),
            provider_url: instance.provider_url,
            remote_collections,
        })
    }
}
