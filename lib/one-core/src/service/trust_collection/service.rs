use std::sync::Arc;

use shared_types::{TrustCollectionId, TrustListSubscriberId, TrustListSubscriptionId};
use tracing::info;

use super::TrustCollectionService;
use super::dto::{
    CreateTrustCollectionRequestDTO, CreateTrustListSubscriptionRequestDTO,
    GetTrustCollectionListResponseDTO, GetTrustCollectionResponseDTO,
    GetTrustListSubscriptionListResponseDTO, TrustCollectionFilterParamsDTO,
    TrustCollectionPublicResponseDTO, TrustListSubscriptionFilterParamsDTO,
};
use super::error::TrustCollectionServiceError;
use super::mapper::{
    get_public_dto, map_create_trust_collection_request, map_create_trust_list_subscription_request,
};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::list_response_into;
use crate::model::list_filter::ListFilterValue;
use crate::model::trust_collection::{SortableTrustCollectionColumn, TrustCollection};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{
    SortableTrustListSubscriptionColumn, TrustListSubscription, TrustListSubscriptionFilterValue,
    TrustListSubscriptionListQuery, TrustListSubscriptionState,
};
use crate::provider::trust_list_subscriber::{
    TrustListSubscriber, TrustListSubscriberCapabilities, TrustListValidationSuccess,
};
use crate::repository::error::DataLayerError;
use crate::service::common_dto::ListQueryDTO;
use crate::validator::ecosystem::validate_ecosystem_selection_allow_not_set;
use crate::validator::{
    ParentOrg, throw_if_org_id_not_matching_session,
    throw_if_org_id_not_matching_session_with_parent_check,
};

impl TrustCollectionService {
    pub async fn create_trust_collection(
        &self,
        request: CreateTrustCollectionRequestDTO,
    ) -> Result<TrustCollectionId, TrustCollectionServiceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("validating organisation")?;

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id)
            .await
            .error_while("getting organisation")?;
        validate_ecosystem_selection_allow_not_set(
            Some(&request.ecosystem),
            &organisation,
            self.ecosystem_provider.as_ref(),
        )
        .error_while("validating ecosystem")?;

        let name = request.name.to_owned();

        let trust_collection =
            map_create_trust_collection_request(request, self.organisation_repository.clone());
        let trust_collection_id = self
            .trust_collection_repository
            .create(trust_collection)
            .await
            .map_err(|e| {
                if matches!(e, DataLayerError::AlreadyExists) {
                    TrustCollectionServiceError::TrustCollectionAlreadyExists
                } else {
                    e.error_while("creating trust collection").into()
                }
            })?;

        info!("Created trust collection `{name}` ({trust_collection_id})");
        Ok(trust_collection_id)
    }

    pub async fn delete_trust_collection(
        &self,
        trust_collection_id: TrustCollectionId,
    ) -> Result<(), TrustCollectionServiceError> {
        let trust_collection = self.fetch_trust_collection(&trust_collection_id).await?;
        throw_if_org_id_not_matching_session(
            trust_collection.organisation.id_ref(),
            &*self.session_provider,
        )
        .error_while("validating organisation")?;

        self.delete_trust_list_subscriptions(trust_collection_id)
            .await?;

        self.trust_collection_repository
            .delete(trust_collection_id)
            .await
            .error_while("deleting trust collection")?;
        info!(
            "Removed trust collection `{}` ({})",
            trust_collection.name, trust_collection.id
        );
        Ok(())
    }

    pub async fn get_trust_collection(
        &self,
        trust_collection_id: TrustCollectionId,
    ) -> Result<GetTrustCollectionResponseDTO, TrustCollectionServiceError> {
        let trust_collection = self.fetch_trust_collection(&trust_collection_id).await?;
        throw_if_org_id_not_matching_session_with_parent_check(
            trust_collection.organisation.id(),
            ParentOrg::Allow(self.organisation_repository.clone()),
            &*self.session_provider,
        )
        .await
        .error_while("validating organisation")?;
        Ok(trust_collection.into())
    }

    pub async fn get_trust_collection_list(
        &self,
        query: ListQueryDTO<SortableTrustCollectionColumn, TrustCollectionFilterParamsDTO>,
    ) -> Result<GetTrustCollectionListResponseDTO, TrustCollectionServiceError> {
        throw_if_org_id_not_matching_session(
            &query.filter.organisation_id,
            &*self.session_provider,
        )
        .error_while("validating organisation")?;

        let trust_collection_list = self
            .trust_collection_repository
            .list(query.into())
            .await
            .error_while("getting trust list publications")?;
        Ok(list_response_into(trust_collection_list))
    }

    pub async fn get_public_trust_collection(
        &self,
        trust_collection_id: TrustCollectionId,
    ) -> Result<TrustCollectionPublicResponseDTO, TrustCollectionServiceError> {
        let trust_collection = self.fetch_trust_collection(&trust_collection_id).await?;

        let trust_lists = self
            .trust_list_subscription_repository
            .list(TrustListSubscriptionListQuery {
                filtering: Some(
                    TrustListSubscriptionFilterValue::TrustCollectionId(vec![trust_collection_id])
                        .condition()
                        & TrustListSubscriptionFilterValue::State(vec![
                            TrustListSubscriptionState::Active,
                        ]),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting trust lists")?
            .values;

        Ok(get_public_dto(trust_collection, trust_lists))
    }

    pub async fn create_trust_list_subscription(
        &self,
        trust_collection_id: TrustCollectionId,
        request: CreateTrustListSubscriptionRequestDTO,
    ) -> Result<TrustListSubscriptionId, TrustCollectionServiceError> {
        let trust_collection = self.fetch_trust_collection(&trust_collection_id).await?;
        throw_if_org_id_not_matching_session(
            trust_collection.organisation.id_ref(),
            &*self.session_provider,
        )
        .error_while("validating organisation")?;

        let trust_list_subscriber = self.fetch_trust_list_subscriber(&request.r#type).await?;
        let role = validate_subscription(&trust_list_subscriber, &request).await?;
        validate_trust_list_role_capabilities(
            role.as_ref(),
            trust_list_subscriber.get_capabilities(),
        )?;

        let trust_list_subscription_id = self
            .insert_trust_list_subscription(request.clone(), trust_collection.clone(), role)
            .await?;

        info!(
            "Created trust list subscription `{}` ({}): trust list collection `{}` ({})",
            request.name, trust_list_subscription_id, trust_collection.name, trust_collection.id
        );
        Ok(trust_list_subscription_id)
    }

    pub async fn delete_trust_list_subscription(
        &self,
        trust_list_subscription_id: TrustListSubscriptionId,
    ) -> Result<(), TrustCollectionServiceError> {
        let trust_list_subscription = self
            .fetch_trust_list_subscription(&trust_list_subscription_id)
            .await?;
        let trust_collection = trust_list_subscription.trust_collection.as_ref().await?;
        throw_if_org_id_not_matching_session(
            trust_collection.organisation.id_ref(),
            &*self.session_provider,
        )
        .error_while("validating organisation")?;

        self.trust_list_subscription_repository
            .delete(trust_list_subscription_id)
            .await
            .error_while("deleting trust list subscription")?;
        info!(
            "Removed trust list subscription `{}` ({}): trust list collection `{}` ({})",
            trust_list_subscription.name,
            trust_list_subscription.id,
            trust_collection.name,
            trust_collection.id
        );
        Ok(())
    }

    pub async fn get_trust_list_subscription_list(
        &self,
        trust_collection_id: TrustCollectionId,
        query: ListQueryDTO<
            SortableTrustListSubscriptionColumn,
            TrustListSubscriptionFilterParamsDTO,
        >,
    ) -> Result<GetTrustListSubscriptionListResponseDTO, TrustCollectionServiceError> {
        let trust_collection = self.fetch_trust_collection(&trust_collection_id).await?;
        throw_if_org_id_not_matching_session_with_parent_check(
            trust_collection.organisation.id(),
            ParentOrg::Allow(self.organisation_repository.clone()),
            &*self.session_provider,
        )
        .await
        .error_while("validating organisation")?;

        let list_query: TrustListSubscriptionListQuery = query.into();
        let filtering = list_query.filtering.unwrap_or_default()
            & TrustListSubscriptionFilterValue::TrustCollectionId(vec![trust_collection_id]);

        let trust_list_subscription_list = self
            .trust_list_subscription_repository
            .list(TrustListSubscriptionListQuery {
                pagination: list_query.pagination,
                sorting: list_query.sorting,
                filtering: Some(filtering),
                include: None,
            })
            .await
            .error_while("getting trust list subscriptions")?;

        Ok(list_response_into(trust_list_subscription_list))
    }

    async fn delete_trust_list_subscriptions(
        &self,
        trust_collection_id: TrustCollectionId,
    ) -> Result<(), TrustCollectionServiceError> {
        let trust_list_subscriptions = self
            .trust_list_subscription_repository
            .list(TrustListSubscriptionListQuery {
                filtering: Some(
                    TrustListSubscriptionFilterValue::TrustCollectionId(vec![trust_collection_id])
                        .condition(),
                ),
                ..Default::default()
            })
            .await
            .error_while("listing subscriptions")?
            .values
            .into_iter()
            .map(|s| s.id)
            .collect::<Vec<_>>();

        if trust_list_subscriptions.is_empty() {
            return Ok(());
        }

        self.trust_list_subscription_repository
            .delete_many(trust_list_subscriptions)
            .await
            .error_while("deleting subscriptions")?;
        Ok(())
    }

    async fn insert_trust_list_subscription(
        &self,
        request: CreateTrustListSubscriptionRequestDTO,
        trust_collection: TrustCollection,
        role: Option<TrustListRoleEnum>,
    ) -> Result<TrustListSubscriptionId, TrustCollectionServiceError> {
        let trust_list_subscription =
            map_create_trust_list_subscription_request(request, trust_collection, role)?;
        let trust_list_subscription_id = self
            .trust_list_subscription_repository
            .create(trust_list_subscription)
            .await
            .map_err(|e| {
                if matches!(e, DataLayerError::AlreadyExists) {
                    TrustCollectionServiceError::TrustListSubscriptionAlreadyExists
                } else {
                    e.error_while("creating trust list subscription").into()
                }
            })?;
        Ok(trust_list_subscription_id)
    }

    async fn fetch_trust_list_subscriber(
        &self,
        trust_list_subscriber_id: &TrustListSubscriberId,
    ) -> Result<Arc<dyn TrustListSubscriber>, TrustCollectionServiceError> {
        self.trust_list_subscriber_provider
            .get(trust_list_subscriber_id)
            .map_err(|_| {
                TrustCollectionServiceError::MissingTrustListSubscriber(
                    trust_list_subscriber_id.clone(),
                )
            })
    }

    async fn fetch_trust_collection(
        &self,
        trust_collection_id: &TrustCollectionId,
    ) -> Result<TrustCollection, TrustCollectionServiceError> {
        self.trust_collection_repository
            .get(trust_collection_id)
            .await
            .error_while("getting trust collection")
            .map_err(Into::into)
    }

    async fn fetch_trust_list_subscription(
        &self,
        trust_list_subscription_id: &TrustListSubscriptionId,
    ) -> Result<TrustListSubscription, TrustCollectionServiceError> {
        self.trust_list_subscription_repository
            .get(trust_list_subscription_id)
            .await
            .error_while("getting trust list subscription")
            .map_err(Into::into)
    }
}

fn validate_trust_list_role_capabilities(
    role: Option<&TrustListRoleEnum>,
    capabilities: TrustListSubscriberCapabilities,
) -> Result<(), TrustCollectionServiceError> {
    match role {
        Some(role) => {
            if !capabilities.roles.contains(role) {
                return Err(TrustCollectionServiceError::InvalidTrustListRole(
                    *role,
                    capabilities.roles,
                ));
            }
        }
        None => {
            if !capabilities.roles.is_empty() {
                return Err(TrustCollectionServiceError::MissingTrustListRole(
                    capabilities.roles,
                ));
            }
        }
    }
    Ok(())
}

async fn validate_subscription(
    trust_list_subscriber: &Arc<dyn TrustListSubscriber>,
    request: &CreateTrustListSubscriptionRequestDTO,
) -> Result<Option<TrustListRoleEnum>, TrustCollectionServiceError> {
    let TrustListValidationSuccess { role } = trust_list_subscriber
        .validate_subscription(&request.reference, request.role)
        .await
        .error_while("validating subscription")?;
    Ok(role)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::provider::trust_list_subscriber::Feature;

    fn capabilities(roles: Vec<TrustListRoleEnum>) -> TrustListSubscriberCapabilities {
        TrustListSubscriberCapabilities {
            roles,
            resolvable_identifier_types: vec![],
            features: vec![Feature::SupportsRemoteIdentifiers],
        }
    }

    #[test]
    fn empty_roles_provider_accepts_none_role() {
        assert!(validate_trust_list_role_capabilities(None, capabilities(vec![])).is_ok());
    }

    #[test]
    fn empty_roles_provider_rejects_some_role() {
        let result = validate_trust_list_role_capabilities(
            Some(&TrustListRoleEnum::Issuer),
            capabilities(vec![]),
        );
        assert!(matches!(
            result,
            Err(TrustCollectionServiceError::InvalidTrustListRole(..))
        ));
    }

    #[test]
    fn non_empty_roles_provider_rejects_none_role() {
        let result = validate_trust_list_role_capabilities(
            None,
            capabilities(vec![TrustListRoleEnum::Issuer]),
        );
        assert!(matches!(
            result,
            Err(TrustCollectionServiceError::MissingTrustListRole(..))
        ));
    }

    #[test]
    fn non_empty_roles_provider_accepts_matching_role() {
        assert!(
            validate_trust_list_role_capabilities(
                Some(&TrustListRoleEnum::Issuer),
                capabilities(vec![TrustListRoleEnum::Issuer, TrustListRoleEnum::Verifier]),
            )
            .is_ok()
        );
    }

    #[test]
    fn non_empty_roles_provider_rejects_unsupported_role() {
        let result = validate_trust_list_role_capabilities(
            Some(&TrustListRoleEnum::Verifier),
            capabilities(vec![TrustListRoleEnum::Issuer]),
        );
        assert!(matches!(
            result,
            Err(TrustCollectionServiceError::InvalidTrustListRole(..))
        ));
    }
}
