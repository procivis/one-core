use std::sync::Arc;

use futures::FutureExt;
use shared_types::{OrganisationId, TrustCollectionId};
use url::Url;
use uuid::Uuid;

use super::dto::RemoteTrustCollectionInfoDTO;
use super::{Error, TrustCollectionManager};
use crate::error::ContextWithErrorCode;
use crate::model::list_filter::ListFilterValue;
use crate::model::relation::Related;
use crate::model::trust_collection::{
    GetTrustCollectionList, TrustCollection, TrustCollectionFilterValue, TrustCollectionListQuery,
};
use crate::proto::transaction_manager::TransactionManager;
use crate::repository::error::DataLayerError;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;

pub(crate) struct TrustCollectionManagerImpl {
    repository: Arc<dyn TrustCollectionRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    tx_manager: Arc<dyn TransactionManager>,
}

impl TrustCollectionManagerImpl {
    pub(crate) fn new(
        repository: Arc<dyn TrustCollectionRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        tx_manager: Arc<dyn TransactionManager>,
    ) -> Self {
        Self {
            repository,
            organisation_repository,
            tx_manager,
        }
    }
}

#[async_trait::async_trait]
impl TrustCollectionManager for TrustCollectionManagerImpl {
    async fn create_empty_trust_collections(
        &self,
        provider_metadata_url: &str,
        collections: Vec<RemoteTrustCollectionInfoDTO>,
        organisation_id: OrganisationId,
    ) -> Result<Vec<TrustCollectionId>, Error> {
        let provider_url = Url::parse(provider_metadata_url)?;
        let now = crate::clock::now_utc();

        let mut collection_ids = vec![];
        self.tx_manager
            .tx(async {
                for collection in collections {
                    let trust_collection_url =
                        get_trust_collection_url(provider_url.clone(), collection.id)?;

                    let result = self.repository
                        .create(TrustCollection {
                            ecosystem: collection.ecosystem.clone(),
                            id: Uuid::new_v4().into(),
                            name: collection.name.clone(),
                            created_date: now,
                            last_modified: now,
                            deactivated_at: None,
                            remote_trust_collection_url: Some(trust_collection_url),
                            organisation: Related::new(organisation_id, self.organisation_repository.clone()),
                        })
                        .await;
                    match result {
                        Ok(id) => {
                            collection_ids.push(id);
                        }
                        Err(DataLayerError::AlreadyExists(_)) => {
                            tracing::info!("Skipping trust collection with name `{}`: already exists", collection.name);
                            continue;
                        }
                        Err(err) => return Err(err)
                            .error_while(format!(
                                "creating trust collection with name `{}` in organisation {organisation_id}",
                                collection.name,
                            )).map_err(Into::into),
                    }
                }

                Ok::<_, Error>(())
            }
            .boxed())
            .await
            .error_while("creating trust collections")??;

        Ok(collection_ids)
    }

    async fn sync_remote_trust_collections(
        &self,
        provider_url: &str,
        remote_collections: Vec<RemoteTrustCollectionInfoDTO>,
        organisation_id: OrganisationId,
    ) -> Result<Vec<TrustCollectionId>, Error> {
        self.tx_manager
            .tx(async {
                let existing_collections: GetTrustCollectionList = self
                    .repository
                    .list(TrustCollectionListQuery {
                        include_count: false,
                        filtering: Some(
                            TrustCollectionFilterValue::OrganisationId {
                                id: organisation_id,
                                include_inherited_collections: false,
                            }
                            .condition(),
                        ),
                        ..Default::default()
                    })
                    .await
                    .error_while("listing existing trust collections")?;
                let (to_keep, to_delete): (Vec<_>, Vec<_>) =
                    existing_collections.values.iter().partition(|existing| {
                        remote_collections.iter().any(|remote| {
                            existing.name == remote.name
                                || existing.remote_trust_collection_url.is_none()
                        })
                    });
                for collection_to_delete in to_delete {
                    self.repository
                        .delete(collection_to_delete.id)
                        .await
                        .error_while("deleting trust collection")?;
                }
                let to_create = remote_collections
                    .into_iter()
                    .filter(|remote| {
                        !existing_collections
                            .values
                            .iter()
                            .any(|existing| existing.name == remote.name)
                    })
                    .collect();
                let mut created = self
                    .create_empty_trust_collections(provider_url, to_create, organisation_id)
                    .await?;
                created.extend(
                    to_keep
                        .iter()
                        // do not return local collections
                        .filter(|c| c.remote_trust_collection_url.is_some())
                        .map(|c| c.id),
                );
                Ok(created)
            }
            .boxed())
            .await
            .error_while("syncing trust collections")?
    }
}

fn get_trust_collection_url(
    mut provider_url: Url,
    remote_collection_id: TrustCollectionId,
) -> Result<Url, Error> {
    {
        let mut path = provider_url
            .path_segments_mut()
            .map_err(|_| Error::InvalidUrl)?;

        path.clear()
            .push("ssi")
            .push("trust-collection")
            .push("v1")
            .push(remote_collection_id.to_string().as_str());
    }

    Ok(provider_url)
}
