use std::sync::Arc;

use shared_types::{
    OrganisationId, TrustCollectionId, TrustListSubscriberId, TrustListSubscriptionId,
};
use tracing::info;

use super::TrustCollectionService;
use super::dto::{
    CreateTrustCollectionRequestDTO, CreateTrustListSubscriptionRequestDTO,
    GetTrustCollectionListResponseDTO, GetTrustCollectionResponseDTO,
    GetTrustListSubscriptionListResponseDTO, TrustCollectionPublicResponseDTO,
};
use super::error::TrustCollectionServiceError;
use super::mapper::{
    get_public_dto, map_create_trust_collection_request, map_create_trust_list_subscription_request,
};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::list_response_into;
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListQuery;
use crate::model::trust_collection::{TrustCollection, TrustCollectionListQuery};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{
    TrustListSubscription, TrustListSubscriptionFilterValue, TrustListSubscriptionListQuery,
    TrustListSubscriptionRelations, TrustListSubscriptionState,
};
use crate::provider::trust_list_subscriber::{
    TrustListSubscriber, TrustListSubscriberCapabilities, TrustListValidationSuccess,
};
use crate::repository::error::DataLayerError;
use crate::validator::throw_if_org_not_matching_session;

impl TrustCollectionService {
    pub async fn create_trust_collection(
        &self,
        request: CreateTrustCollectionRequestDTO,
    ) -> Result<TrustCollectionId, TrustCollectionServiceError> {
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("validating organisation")?;
        let trust_collection_id = self.insert_trust_collection(&request).await?;
        info!(
            "Created trust collection `{}` ({})",
            request.name, trust_collection_id
        );
        Ok(trust_collection_id)
    }

    pub async fn delete_trust_collection(
        &self,
        trust_collection_id: TrustCollectionId,
    ) -> Result<(), TrustCollectionServiceError> {
        let trust_collection = self.fetch_trust_collection(&trust_collection_id).await?;
        throw_if_org_not_matching_session(
            &trust_collection.organisation_id,
            &*self.session_provider,
        )
        .error_while("validating organisation")?;

        self.trust_collection_repository
            .delete(trust_collection_id)
            .await
            .error_while("deleting trust collection")?;
        info!(
            "Deleted trust collection `{}` ({})",
            trust_collection.name, trust_collection.id
        );
        Ok(())
    }

    pub async fn get_trust_collection(
        &self,
        trust_collection_id: TrustCollectionId,
    ) -> Result<GetTrustCollectionResponseDTO, TrustCollectionServiceError> {
        let trust_collection = self.fetch_trust_collection(&trust_collection_id).await?;
        throw_if_org_not_matching_session(
            &trust_collection.organisation_id,
            &*self.session_provider,
        )
        .error_while("validating organisation")?;
        Ok(trust_collection.into())
    }

    pub async fn get_trust_collection_list(
        &self,
        organisation_id: OrganisationId,
        query: TrustCollectionListQuery,
    ) -> Result<GetTrustCollectionListResponseDTO, TrustCollectionServiceError> {
        throw_if_org_not_matching_session(&organisation_id, &*self.session_provider)
            .error_while("validating organisation")?;
        let trust_collection_list = self
            .trust_collection_repository
            .list(query)
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
                    TrustListSubscriptionFilterValue::TrustCollectionId(trust_collection_id)
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
        throw_if_org_not_matching_session(
            &trust_collection.organisation_id,
            &*self.session_provider,
        )
        .error_while("validating organisation")?;

        let trust_list_subscriber = self.fetch_trust_list_subscriber(&request.r#type).await?;
        let role = validate_subscription(&trust_list_subscriber, &request).await?;
        validate_trust_list_role_capabilities(&role, trust_list_subscriber.get_capabilities())?;

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
        let trust_collection = trust_list_subscription.trust_collection.ok_or(
            TrustCollectionServiceError::MappingError("missing trust collection".to_string()),
        )?;
        throw_if_org_not_matching_session(
            &trust_collection.organisation_id,
            &*self.session_provider,
        )
        .error_while("validating organisation")?;

        self.trust_list_subscription_repository
            .delete(trust_list_subscription_id)
            .await
            .error_while("deleting trust list subscription")?;
        info!(
            "Deleted trust list subscription `{}` ({}): trust list collection `{}` ({})",
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
        query: TrustListSubscriptionListQuery,
    ) -> Result<GetTrustListSubscriptionListResponseDTO, TrustCollectionServiceError> {
        let trust_collection = self.fetch_trust_collection(&trust_collection_id).await?;
        throw_if_org_not_matching_session(
            &trust_collection.organisation_id,
            &*self.session_provider,
        )
        .error_while("validating organisation")?;
        let trust_list_subscription_list = self
            .trust_list_subscription_repository
            .list(ListQuery {
                filtering: query.filtering.map(|f| {
                    f & TrustListSubscriptionFilterValue::TrustCollectionId(trust_collection_id)
                }),
                ..query
            })
            .await
            .error_while("getting trust list subscriptions")?;

        Ok(list_response_into(trust_list_subscription_list))
    }

    async fn insert_trust_collection(
        &self,
        request: &CreateTrustCollectionRequestDTO,
    ) -> Result<TrustCollectionId, TrustCollectionServiceError> {
        let trust_collection =
            map_create_trust_collection_request(self.clock.as_ref(), request.clone());
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
        Ok(trust_collection_id)
    }

    async fn insert_trust_list_subscription(
        &self,
        request: CreateTrustListSubscriptionRequestDTO,
        trust_collection: TrustCollection,
        role: TrustListRoleEnum,
    ) -> Result<TrustListSubscriptionId, TrustCollectionServiceError> {
        let trust_list_subscription = map_create_trust_list_subscription_request(
            self.clock.as_ref(),
            request,
            trust_collection,
            role,
        )?;
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
            .ok_or_else(|| {
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
            .get(trust_collection_id, &Default::default())
            .await
            .error_while("getting trust collection")?
            .ok_or(TrustCollectionServiceError::TrustCollectionNotFound(
                *trust_collection_id,
            ))
    }

    async fn fetch_trust_list_subscription(
        &self,
        trust_list_subscription_id: &TrustListSubscriptionId,
    ) -> Result<TrustListSubscription, TrustCollectionServiceError> {
        self.trust_list_subscription_repository
            .get(
                trust_list_subscription_id,
                &TrustListSubscriptionRelations {
                    trust_collection: Some(Default::default()),
                },
            )
            .await
            .error_while("getting trust list subscription")?
            .ok_or(TrustCollectionServiceError::TrustListSubscriptionNotFound(
                *trust_list_subscription_id,
            ))
    }
}

fn validate_trust_list_role_capabilities(
    role: &TrustListRoleEnum,
    capabilities: TrustListSubscriberCapabilities,
) -> Result<(), TrustCollectionServiceError> {
    if !capabilities.roles.contains(role) {
        return Err(TrustCollectionServiceError::InvalidTrustListRole(
            *role,
            capabilities.roles,
        ));
    }
    Ok(())
}

async fn validate_subscription(
    trust_list_subscriber: &Arc<dyn TrustListSubscriber>,
    request: &CreateTrustListSubscriptionRequestDTO,
) -> Result<TrustListRoleEnum, TrustCollectionServiceError> {
    let TrustListValidationSuccess { role } = trust_list_subscriber
        .validate_subscription(&request.reference, request.role)
        .await
        .error_while("validating subscription")?;
    Ok(role)
}
