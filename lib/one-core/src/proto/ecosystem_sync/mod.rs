//! Synchronisation of the entities an organisation's wallet and/or verifier provider
//! advertises for the ecosystems that organisation selected.
//!
//! Used both by the periodic `ECOSYSTEM_SYNC` task and by the organisation service, which
//! runs a sync as soon as an ecosystem is enabled instead of waiting for the next task run.

use std::collections::HashSet;
use std::sync::Arc;

use shared_types::{EcosystemId, OrganisationId, TrustCollectionId};

use crate::error::{ContextWithErrorCode, NestedError};
use crate::model::instance::{Instance, InstanceRole};
use crate::model::list_filter::ListFilterValue;
use crate::model::organisation::Organisation;
use crate::model::trust_collection::{TrustCollectionFilterValue, TrustCollectionListQuery};
use crate::proto::schema_import::SchemaImporter;
use crate::proto::trust_collection::TrustCollectionManager;
use crate::proto::trust_collection::legacy_selection::legacy_deselected_collections;
use crate::proto::trust_list_subscription_sync::TrustListSubscriptionSync;
use crate::proto::verifier_provider_client::VerifierProviderClient;
use crate::proto::wallet_provider_client::WalletProviderClient;
use crate::proto::wallet_provider_client::dto::MetadataTarget;
use crate::repository::instance_repository::InstanceRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::service::instance::service::provider_metadata_url;
use crate::service::managed_instance::dto::EcosystemMetadataDTO;
use crate::service::managed_instance::ecosystem_metadata::remote_trust_collections;

#[cfg(test)]
mod test;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait EcosystemSync: Send + Sync {
    /// Syncs the ecosystems advertised to a single instance, on behalf of the organisation
    /// owning it.
    ///
    /// Returns the number of trust collections whose subscriptions were synced.
    async fn sync_instance(&self, instance: &Instance) -> Result<usize, NestedError>;

    /// Syncs the ecosystems advertised to an organisation by both its wallet and its
    /// verifier instance, if it has any.
    ///
    /// Returns the number of trust collections whose subscriptions were synced.
    async fn sync_organisation(&self, organisation: &Organisation) -> Result<usize, NestedError>;
}

pub(crate) struct EcosystemSyncProto {
    instance_repository: Arc<dyn InstanceRepository>,
    wallet_provider_client: Arc<dyn WalletProviderClient>,
    verifier_provider_client: Arc<dyn VerifierProviderClient>,
    trust_collection_manager: Arc<dyn TrustCollectionManager>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    subscription_sync: Arc<dyn TrustListSubscriptionSync>,
    schema_importer: Arc<dyn SchemaImporter>,
}

impl EcosystemSyncProto {
    pub(crate) fn new(
        instance_repository: Arc<dyn InstanceRepository>,
        wallet_provider_client: Arc<dyn WalletProviderClient>,
        verifier_provider_client: Arc<dyn VerifierProviderClient>,
        trust_collection_manager: Arc<dyn TrustCollectionManager>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        subscription_sync: Arc<dyn TrustListSubscriptionSync>,
        schema_importer: Arc<dyn SchemaImporter>,
    ) -> Self {
        Self {
            instance_repository,
            wallet_provider_client,
            verifier_provider_client,
            trust_collection_manager,
            trust_collection_repository,
            subscription_sync,
            schema_importer,
        }
    }

    /// Reads the ecosystems the provider backing `instance` advertises to it.
    async fn fetch_remote_ecosystems(
        &self,
        instance: &Instance,
    ) -> Result<Vec<EcosystemMetadataDTO>, NestedError> {
        let metadata_url = provider_metadata_url(
            &instance.provider_url,
            &instance.provider_name,
            instance.role,
        );
        match instance.role {
            InstanceRole::Wallet => Ok(self
                .wallet_provider_client
                .get_wallet_provider_metadata(MetadataTarget {
                    r#type: instance.provider_type,
                    metadata_url,
                })
                .await
                .error_while("getting wallet provider metadata")?
                .ecosystems),
            InstanceRole::Verifier => Ok(self
                .verifier_provider_client
                .get_verifier_provider_metadata(&metadata_url)
                .await
                .error_while("getting verifier provider metadata")?
                .ecosystems),
        }
    }

    /// Pulls in everything the provider backing `instance` advertises for the ecosystems
    /// the owning organisation selected: their trust collections, which are mirrored and
    /// subscribed to, and their credential and proof schemas, which are imported.
    async fn sync(
        &self,
        instance: &Instance,
        organisation: &Organisation,
    ) -> Result<usize, NestedError> {
        let remote_ecosystems = self.fetch_remote_ecosystems(instance).await?;
        let selected_ecosystems = &organisation.configuration.selected_ecosystems;

        // TODO (ONE-10972): remove together with the deprecated per-collection selection API.
        // Read before syncing, so that collections created by this run - which have
        // no subscriptions yet and would make their ecosystem look mixed - cannot be
        // mistaken for a deselection.
        let legacy_deselected = if selected_ecosystems.is_empty() {
            HashSet::new()
        } else {
            self.legacy_deselected_collections(organisation.id).await?
        };

        // All advertised collections are mirrored locally so that the organisation can
        // select their ecosystem later on, only the selected ones are subscribed to.
        let synced_collections = self
            .trust_collection_manager
            .sync_remote_trust_collections(
                &instance.provider_url,
                remote_trust_collections(&remote_ecosystems),
                organisation.id,
            )
            .await
            .error_while("syncing trust collections")?;

        self.import_schemas(&remote_ecosystems, organisation, selected_ecosystems)
            .await;

        if selected_ecosystems.is_empty() {
            return Ok(0);
        }

        let collections = self
            .trust_collection_repository
            .list(TrustCollectionListQuery {
                include_count: false,
                filtering: Some(
                    TrustCollectionFilterValue::OrganisationId {
                        id: organisation.id,
                        // Parent organisation must not be modified, hence not synced
                        include_inherited_collections: false,
                    }
                    .condition()
                        & TrustCollectionFilterValue::Ids(synced_collections)
                        & TrustCollectionFilterValue::Remote(true)
                        // Collections of an ecosystem the organisation did not select
                        // are not enabled and hence should not be synced (which fills
                        // in the trust list subscriptions)
                        & TrustCollectionFilterValue::Ecosystems(selected_ecosystems.to_owned()),
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

        let mut count = 0;
        for collection in to_sync {
            match self.subscription_sync.sync_subscriptions(collection).await {
                Ok(()) => count += 1,
                Err(error) => tracing::warn!(
                    "Failed syncing subscriptions of trust collection {}: {error}",
                    collection.id,
                ),
            }
        }

        Ok(count)
    }

    /// Imports the credential and proof schemas the provider publishes for the given
    /// ecosystems. Schemas already imported, as well as those failing to import, are only
    /// logged - a sync repeatedly covering the same ecosystem must not fail over them.
    async fn import_schemas(
        &self,
        remote_ecosystems: &[EcosystemMetadataDTO],
        organisation: &Organisation,
        selected_ecosystems: &[EcosystemId],
    ) {
        let to_import = remote_ecosystems
            .iter()
            .filter(|ecosystem| selected_ecosystems.contains(&ecosystem.name));

        for ecosystem in to_import {
            self.schema_importer
                .import_schemas(
                    &ecosystem.credential_schemas,
                    &ecosystem.proof_schemas,
                    organisation,
                )
                .await;
        }
    }

    /// TODO (ONE-10972): remove together with the deprecated per-collection selection API.
    ///
    /// Collections an organisation excluded through the deprecated per-collection
    /// selection, which the ecosystem selection must not silently re-subscribe.
    async fn legacy_deselected_collections(
        &self,
        organisation_id: OrganisationId,
    ) -> Result<HashSet<TrustCollectionId>, NestedError> {
        let organisation_collections = TrustCollectionFilterValue::OrganisationId {
            id: organisation_id,
            include_inherited_collections: false,
        };

        let collections = self
            .trust_collection_repository
            .list(TrustCollectionListQuery {
                include_count: false,
                filtering: Some(organisation_collections.clone().condition()),
                ..Default::default()
            })
            .await
            .error_while("listing trust collections")?;

        let subscribed = self
            .trust_collection_repository
            .list(TrustCollectionListQuery {
                include_count: false,
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
}

#[async_trait::async_trait]
impl EcosystemSync for EcosystemSyncProto {
    async fn sync_instance(&self, instance: &Instance) -> Result<usize, NestedError> {
        let organisation = instance
            .organisation
            .as_ref()
            .await
            .error_while("getting organisation of instance")?;

        self.sync(instance, &organisation).await
    }

    async fn sync_organisation(&self, organisation: &Organisation) -> Result<usize, NestedError> {
        let mut count = 0;
        for role in [InstanceRole::Wallet, InstanceRole::Verifier] {
            let Some(instance) = self
                .instance_repository
                .get_by_role(role, organisation.id)
                .await
                .error_while("getting instance of organisation")?
            else {
                continue;
            };

            count += self.sync(&instance, organisation).await?;
        }

        Ok(count)
    }
}
