use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use shared_types::{OrganisationId, TrustCollectionId};
use uuid::Uuid;

use crate::error::ContextWithErrorCode;
use crate::model::identifier::Identifier;
use crate::model::instance::InstanceRole;
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, ValueComparison,
};
use crate::model::list_query::ListPagination;
use crate::model::organisation::{
    Organisation, OrganisationFilterValue, UpdateOrganisationRequest,
};
use crate::model::relation::Related;
use crate::model::trust_collection::{
    TrustCollection, TrustCollectionFilterValue, TrustCollectionListQuery,
};
use crate::model::trust_list_subscription::{
    TrustListSubscriptionFilterValue, TrustListSubscriptionListQuery, TrustListSubscriptionState,
};
use crate::proto::trust_list_subscription_sync::TrustListSubscriptionSync;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use crate::service::managed_instance::dto::ProviderTrustCollectionDTO;
use crate::service::organisation::dto::{
    CreateOrganisationRequestDTO, GetOrganisationDetailsResponseDTO,
    GetOrganisationListItemResponseDTO, InstanceDetailResponseDTO, OrganisationFilterParamsDTO,
    TrustCollectionInfoDTO, UpsertOrganisationRequestDTO, VerifierProviderDetailResponseDTO,
    WalletProviderDetailResponseDTO,
};
use crate::service::organisation::error::OrganisationServiceError;

pub(super) fn request_to_model(
    request: CreateOrganisationRequestDTO,
    organisation_repository: &Arc<dyn OrganisationRepository>,
) -> Organisation {
    let now = crate::clock::now_utc();
    let id = request.id.unwrap_or(Uuid::new_v4().into());
    Organisation {
        id,
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        wallet_provider: None,
        wallet_provider_issuer: None,
        parent_organisation: request.parent_organisation.map(|organisation_id| {
            Related::new(organisation_id, organisation_repository.to_owned())
        }),
        verifier_provider: None,
        verifier_provider_issuer: None,
        configuration: Default::default(),
    }
}

impl From<UpsertOrganisationRequestDTO> for CreateOrganisationRequestDTO {
    fn from(request: UpsertOrganisationRequestDTO) -> Self {
        Self {
            id: Some(request.id),
            parent_organisation: request.parent_organisation.flatten(),
        }
    }
}

impl From<UpsertOrganisationRequestDTO> for UpdateOrganisationRequest {
    fn from(request: UpsertOrganisationRequestDTO) -> Self {
        Self {
            parent_organisation: request.parent_organisation,
            deactivate: request.deactivate,
            wallet_provider: request.wallet_provider,
            wallet_provider_issuer: request.wallet_provider_issuer,
            verifier_provider: request.verifier_provider,
            verifier_provider_issuer: request.verifier_provider_issuer,
            // Configuration is merged with the existing value (partial update) in the
            // service, which has access to the organisation's current state.
            configuration: None,
        }
    }
}

pub(super) fn detail_from_model(
    organisation: Organisation,
    wallet_provider_issuer: Option<Identifier>,
    verifier_provider_issuer: Option<Identifier>,
    wallet_instance: Option<InstanceDetailResponseDTO>,
    verifier_instance: Option<InstanceDetailResponseDTO>,
) -> GetOrganisationDetailsResponseDTO {
    GetOrganisationDetailsResponseDTO {
        id: organisation.id,
        created_date: organisation.created_date,
        last_modified: organisation.last_modified,
        deactivated_at: organisation.deactivated_at,
        configuration: Some(organisation.configuration.into()),
        wallet_provider: map_to_wallet_provider(
            organisation.wallet_provider,
            wallet_provider_issuer,
        ),
        verifier_provider: map_to_verifier_provider(
            organisation.verifier_provider,
            verifier_provider_issuer,
        ),
        parent_organisation: organisation
            .parent_organisation
            .map(|parent_organisation| parent_organisation.id()),
        wallet_instance,
        verifier_instance,
    }
}

pub(super) fn list_item_from_model(
    organisation: Organisation,
    wallet_provider_issuer: Option<Identifier>,
    verifier_provider_issuer: Option<Identifier>,
) -> GetOrganisationListItemResponseDTO {
    GetOrganisationListItemResponseDTO {
        id: organisation.id,
        created_date: organisation.created_date,
        last_modified: organisation.last_modified,
        deactivated_at: organisation.deactivated_at,
        wallet_provider: map_to_wallet_provider(
            organisation.wallet_provider,
            wallet_provider_issuer,
        ),
        verifier_provider: map_to_verifier_provider(
            organisation.verifier_provider,
            verifier_provider_issuer,
        ),
        parent_organisation: organisation
            .parent_organisation
            .map(|parent_organisation| parent_organisation.id()),
    }
}

fn map_to_wallet_provider(
    provider_name: Option<String>,
    wallet_provider_issuer: Option<Identifier>,
) -> Option<WalletProviderDetailResponseDTO> {
    if provider_name.is_some() || wallet_provider_issuer.is_some() {
        Some(WalletProviderDetailResponseDTO {
            provider_name,
            issuer: wallet_provider_issuer.map(Into::into),
        })
    } else {
        None
    }
}

fn map_to_verifier_provider(
    provider_name: Option<String>,
    verifier_provider_issuer: Option<Identifier>,
) -> Option<VerifierProviderDetailResponseDTO> {
    if provider_name.is_some() || verifier_provider_issuer.is_some() {
        Some(VerifierProviderDetailResponseDTO {
            provider_name,
            issuer: verifier_provider_issuer.map(Into::into),
        })
    } else {
        None
    }
}

impl From<OrganisationFilterParamsDTO> for ListFilterCondition<OrganisationFilterValue> {
    fn from(filter: OrganisationFilterParamsDTO) -> Self {
        let created_date_after = filter.created_date_after.map(|date| {
            OrganisationFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = filter.created_date_before.map(|date| {
            OrganisationFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = filter.last_modified_after.map(|date| {
            OrganisationFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = filter.last_modified_before.map(|date| {
            OrganisationFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let has_parent_organisation = filter
            .has_parent_organisation
            .map(OrganisationFilterValue::HasParentOrganisation);
        let parent_organisations = filter
            .parent_organisations
            .map(OrganisationFilterValue::ParentOrganisations);

        ListFilterCondition::<OrganisationFilterValue>::default()
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
            & has_parent_organisation
            & parent_organisations
    }
}

/// Resolves a provider-supplied trust collection name to the local `TrustCollection` record
/// it corresponds to. Local collection names aren't guaranteed unique, so `matched_local_ids`
/// tracks rows already claimed by an earlier call in the same batch: this guarantees that
/// when two remote entries share a name (e.g. one from the wallet provider, one from the
/// verifier provider), each is attributed to a distinct local row instead of both colliding
/// onto the first match (which would silently misattribute or drop the second one).
///
/// Returns `Ok(None)` when a same-named local collection exists but isn't remote-linked
/// (a local collection takes precedence over a remote one with the same name, so it isn't
/// shown as a selection option), and errors if no local collection matches the name at all.
pub(super) fn match_local_trust_collection<'a>(
    local_trust_collections: &'a [TrustCollection],
    matched_local_ids: &mut HashSet<TrustCollectionId>,
    name: &str,
) -> Result<Option<&'a TrustCollection>, OrganisationServiceError> {
    let local_collection = local_trust_collections
        .iter()
        .find(|collection| collection.name == name && !matched_local_ids.contains(&collection.id))
        .ok_or(OrganisationServiceError::TrustCollectionsNotInSync)?;

    if local_collection.remote_trust_collection_url.is_none() {
        return Ok(None);
    }

    matched_local_ids.insert(local_collection.id);
    Ok(Some(local_collection))
}

/// Groups an organisation's remote-provider trust collections by the local id they resolve
/// to, recording every provider role that exposes each one (a collection not tied to any
/// remote provider, or unmatched by `match_local_trust_collection`, simply has no entry).
pub(super) fn group_remote_trust_collections_by_local_id(
    local_trust_collections: &[TrustCollection],
    remote_trust_collections: Vec<(InstanceRole, ProviderTrustCollectionDTO)>,
) -> Result<HashMap<TrustCollectionId, Vec<InstanceRole>>, OrganisationServiceError> {
    let mut matched_local_ids = HashSet::new();
    let mut roles_by_local_id = HashMap::<TrustCollectionId, Vec<InstanceRole>>::new();
    for (role, metadata) in remote_trust_collections {
        let Some(local) = match_local_trust_collection(
            local_trust_collections,
            &mut matched_local_ids,
            &metadata.name,
        )?
        else {
            continue;
        };

        let roles = roles_by_local_id.entry(local.id).or_default();
        if !roles.contains(&role) {
            roles.push(role);
        }
    }

    Ok(roles_by_local_id)
}

pub(super) async fn prepare_trust_collection_info(
    trust_collection_repository: &dyn TrustCollectionRepository,
    trust_subscription_repository: &dyn TrustListSubscriptionRepository,
    provider_metadata_trust_collections: Vec<ProviderTrustCollectionDTO>,
    organisation_id: OrganisationId,
) -> Result<Vec<TrustCollectionInfoDTO>, OrganisationServiceError> {
    let local_trust_collections = trust_collection_repository
        .list(TrustCollectionListQuery {
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
        .error_while("getting local trust collections")?
        .values;

    let mut matched_local_ids = HashSet::new();
    let mut local_id_to_metadata = HashMap::<TrustCollectionId, ProviderTrustCollectionDTO>::new();
    for metadata_collection in provider_metadata_trust_collections {
        let Some(local_collection) = match_local_trust_collection(
            &local_trust_collections,
            &mut matched_local_ids,
            &metadata_collection.name,
        )?
        else {
            continue;
        };

        local_id_to_metadata.insert(local_collection.id, metadata_collection);
    }

    let mut collections_with_subscription_state = vec![];
    for (id, metadata) in local_id_to_metadata {
        let subscriptions = trust_subscription_repository
            .list(TrustListSubscriptionListQuery {
                filtering: Some(
                    TrustListSubscriptionFilterValue::TrustCollectionId(vec![id]).condition()
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

        collections_with_subscription_state.push((id, metadata, subscriptions.total_items > 0));
    }

    // When no collection has an active subscription yet, the user has not made a selection;
    // in that case the provider-configured `defaultSelected` flag determines the selection.
    let any_subscription_exists = collections_with_subscription_state
        .iter()
        .any(|(_, _, has_subscription)| *has_subscription);

    Ok(collections_with_subscription_state
        .into_iter()
        .map(|(id, metadata, has_subscription)| {
            let selected = if any_subscription_exists {
                has_subscription
            } else {
                metadata.default_selected.unwrap_or(false)
            };
            TrustCollectionInfoDTO {
                selected,
                collection: ProviderTrustCollectionDTO { id, ..metadata },
            }
        })
        .collect())
}

pub(super) async fn set_active_trust_collections(
    trust_collections: Vec<TrustCollectionId>,
    organisation_id: OrganisationId,
    trust_collection_repository: &dyn TrustCollectionRepository,
    trust_subscription_repository: &dyn TrustListSubscriptionRepository,
    trust_list_subscription_sync: &dyn TrustListSubscriptionSync,
) -> Result<(), OrganisationServiceError> {
    let all_trust_collections = trust_collection_repository
        .list(TrustCollectionListQuery {
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
                        TrustListSubscriptionFilterValue::TrustCollectionId(vec![collection_id])
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
            .ok_or(OrganisationServiceError::MissingTrustCollection(requested))?;

        trust_list_subscription_sync
            .sync_subscriptions(collection)
            .await
            .error_while("syncing trust collection")?;
    }

    Ok(())
}
