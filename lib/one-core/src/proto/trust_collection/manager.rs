use std::sync::Arc;

use futures::FutureExt;
use shared_types::{OrganisationId, TrustCollectionId};
use url::Url;
use uuid::Uuid;

use super::dto::RemoteTrustCollectionInfoDTO;
use super::{Error, TrustCollectionManager};
use crate::error::ContextWithErrorCode;
use crate::model::list_filter::ListFilterValue;
use crate::model::trust_collection::{
    GetTrustCollectionList, TrustCollection, TrustCollectionFilterValue, TrustCollectionListQuery,
};
use crate::proto::transaction_manager::TransactionManager;
use crate::repository::trust_collection_repository::TrustCollectionRepository;

pub(crate) struct TrustCollectionManagerImpl {
    repository: Arc<dyn TrustCollectionRepository>,
    tx_manager: Arc<dyn TransactionManager>,
}

impl TrustCollectionManagerImpl {
    pub(crate) fn new(
        repository: Arc<dyn TrustCollectionRepository>,
        tx_manager: Arc<dyn TransactionManager>,
    ) -> Self {
        Self {
            repository,
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

        let mut result = vec![];
        self.tx_manager
            .tx(async {
                for collection in collections {
                    let trust_collection_url =
                        get_trust_collection_url(provider_url.clone(), collection.id)?;

                    result.push(
                        self.repository
                            .create(TrustCollection {
                                id: Uuid::new_v4().into(),
                                name: collection.name,
                                created_date: now,
                                last_modified: now,
                                deactivated_at: None,
                                remote_trust_collection_url: Some(trust_collection_url),
                                organisation_id,
                                organisation: None,
                            })
                            .await
                            .error_while("creating trust collection")?,
                    );
                }

                Ok::<_, Error>(())
            }
            .boxed())
            .await
            .error_while("creating trust collections")??;

        Ok(result)
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
                        filtering: Some(
                            TrustCollectionFilterValue::OrganisationId(organisation_id).condition()
                                & TrustCollectionFilterValue::Remote(true),
                        ),
                        ..Default::default()
                    })
                    .await
                    .error_while("listing existing trust collections")?;
                let (to_keep, to_delete): (Vec<_>, Vec<_>) =
                    existing_collections.values.iter().partition(|existing| {
                        remote_collections
                            .iter()
                            .any(|remote| existing.name == remote.name)
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
                created.extend(to_keep.iter().map(|c| c.id));
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
