use std::collections::HashMap;

use one_dto_mapper::convert_inner;
use shared_types::{KeyId, OrganisationId, TrustCollectionId};
use time::OffsetDateTime;

use super::dto::{HolderWalletUnitResponseDTO, TrustCollectionInfoDTO};
use super::error::HolderWalletUnitError;
use crate::error::ContextWithErrorCode;
use crate::model::holder_wallet_unit::HolderWalletUnit;
use crate::model::key::Key;
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::model::organisation::Organisation;
use crate::model::trust_collection::{TrustCollectionFilterValue, TrustCollectionListQuery};
use crate::model::trust_list_subscription::{
    TrustListSubscriptionFilterValue, TrustListSubscriptionListQuery, TrustListSubscriptionState,
};
use crate::proto::trust_collection::dto::RemoteTrustCollectionInfoDTO;
use crate::proto::trust_list_subscription_sync::TrustListSubscriptionSync;
use crate::provider::key_storage::model::StorageGeneratedKey;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use crate::service::wallet_provider::dto::ProviderTrustCollectionDTO;

pub(super) fn key_from_generated_key(
    key_id: KeyId,
    key_storage_id: &str,
    key_type: &str,
    organisation: Organisation,
    generated_key: StorageGeneratedKey,
) -> Key {
    let now = OffsetDateTime::now_utc();

    Key {
        id: key_id,
        created_date: now,
        last_modified: now,
        public_key: generated_key.public_key,
        name: format!("Wallet unit key {key_id}"),
        key_reference: generated_key.key_reference,
        storage_type: key_storage_id.to_string(),
        key_type: key_type.to_string(),
        organisation: Some(organisation),
    }
}

impl From<HolderWalletUnit> for HolderWalletUnitResponseDTO {
    fn from(value: HolderWalletUnit) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            provider_wallet_unit_id: value.provider_wallet_unit_id,
            wallet_provider_url: value.wallet_provider_url,
            wallet_provider_type: value.wallet_provider_type,
            wallet_provider_name: value.wallet_provider_name,
            status: value.status,
            authentication_key: convert_inner(value.authentication_key),
        }
    }
}

impl From<ProviderTrustCollectionDTO> for RemoteTrustCollectionInfoDTO {
    fn from(value: ProviderTrustCollectionDTO) -> Self {
        Self {
            id: value.id,
            name: value.name,
        }
    }
}

pub(crate) async fn prepare_trust_collection_info(
    trust_collection_repository: &dyn TrustCollectionRepository,
    trust_subscription_repository: &dyn TrustListSubscriptionRepository,
    provider_metadata_trust_collections: Vec<ProviderTrustCollectionDTO>,
    organisation_id: OrganisationId,
) -> Result<Vec<TrustCollectionInfoDTO>, HolderWalletUnitError> {
    let local_trust_collections = trust_collection_repository
        .list(TrustCollectionListQuery {
            filtering: Some(
                TrustCollectionFilterValue::OrganisationId(organisation_id).condition(),
            ),
            ..Default::default()
        })
        .await
        .error_while("getting local trust collections")?
        .values;

    if provider_metadata_trust_collections.len() != local_trust_collections.len() {
        return Err(HolderWalletUnitError::TrustCollectionsNotInSync);
    }

    let mut local_id_to_metadata = HashMap::<TrustCollectionId, ProviderTrustCollectionDTO>::new();
    for metadata_collection in provider_metadata_trust_collections {
        let local_collection = local_trust_collections
            .iter()
            .find(|lc| lc.name == metadata_collection.name)
            .ok_or(HolderWalletUnitError::TrustCollectionsNotInSync)?;

        local_id_to_metadata.insert(local_collection.id, metadata_collection);
    }

    let mut result = vec![];
    for (id, metadata) in local_id_to_metadata {
        let subscriptions = trust_subscription_repository
            .list(TrustListSubscriptionListQuery {
                filtering: Some(
                    TrustListSubscriptionFilterValue::TrustCollectionId(id).condition()
                        & TrustListSubscriptionFilterValue::State(vec![
                            TrustListSubscriptionState::Active,
                        ]),
                ),
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: 1,
                }),
                ..Default::default()
            })
            .await
            .error_while("listing subscriptions")?;

        result.push(TrustCollectionInfoDTO {
            selected: subscriptions.total_items > 0,
            collection: ProviderTrustCollectionDTO { id, ..metadata },
        });
    }

    Ok(result)
}

pub(crate) async fn set_active_trust_collections(
    trust_collections: Vec<TrustCollectionId>,
    organisation_id: OrganisationId,
    trust_collection_repository: &dyn TrustCollectionRepository,
    trust_subscription_repository: &dyn TrustListSubscriptionRepository,
    trust_list_subscription_sync: &dyn TrustListSubscriptionSync,
) -> Result<(), HolderWalletUnitError> {
    let all_trust_collections = trust_collection_repository
        .list(TrustCollectionListQuery {
            filtering: Some(
                TrustCollectionFilterValue::OrganisationId(organisation_id).condition(),
            ),
            ..Default::default()
        })
        .await
        .error_while("getting trust collections")?
        .values;

    let collections_to_remove = all_trust_collections
        .iter()
        .filter(|c| !trust_collections.contains(&c.id))
        .map(|c| c.id);

    let mut subscriptions_to_remove = vec![];
    for collection_id in collections_to_remove {
        subscriptions_to_remove.extend(
            trust_subscription_repository
                .list(TrustListSubscriptionListQuery {
                    filtering: Some(
                        TrustListSubscriptionFilterValue::TrustCollectionId(collection_id)
                            .condition(),
                    ),
                    ..Default::default()
                })
                .await
                .error_while("listing subscriptions")?
                .values
                .into_iter()
                .map(|s| s.id)
                .collect::<Vec<_>>(),
        );
    }

    trust_subscription_repository
        .delete_many(subscriptions_to_remove)
        .await
        .error_while("deleting subscriptions")?;

    for requested in trust_collections {
        let collection = all_trust_collections
            .iter()
            .find(|c| c.id == requested)
            .ok_or(HolderWalletUnitError::MissingTrustCollection(requested))?;

        trust_list_subscription_sync
            .sync_subscriptions(collection)
            .await
            .error_while("syncing trust collection")?;
    }

    Ok(())
}
