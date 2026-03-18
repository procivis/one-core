use shared_types::{OrganisationId, TrustCollectionId};
use tracing::info;

use super::TrustCollectionService;
use super::dto::{
    CreateTrustCollectionRequestDTO, GetTrustCollectionListResponseDTO,
    GetTrustCollectionResponseDTO, TrustCollectionPublicResponseDTO,
};
use super::error::TrustCollectionServiceError;
use super::mapper::{get_public_dto, map_create_trust_collection_request};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::list_response_into;
use crate::model::list_filter::ListFilterValue;
use crate::model::trust_collection::{TrustCollection, TrustCollectionListQuery};
use crate::model::trust_list_subscription::{
    TrustListSubscriptionFilterValue, TrustListSubscriptionListQuery, TrustListSubscriptionState,
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
        let trust_collection =
            map_create_trust_collection_request(self.clock.as_ref(), request.clone());

        let trust_collection_id = self
            .trust_collection_repository
            .create(trust_collection)
            .await
            .map_err(|e| {
                if matches!(e, DataLayerError::AlreadyExists) {
                    TrustCollectionServiceError::AlreadyExists
                } else {
                    e.error_while("creating trust collection").into()
                }
            })?;
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
            .error_while("checking session")?;
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

    async fn fetch_trust_collection(
        &self,
        trust_collection_id: &TrustCollectionId,
    ) -> Result<TrustCollection, TrustCollectionServiceError> {
        self.trust_collection_repository
            .get(trust_collection_id, &Default::default())
            .await
            .error_while("getting trust collection")?
            .ok_or(TrustCollectionServiceError::NotFound(*trust_collection_id))
    }
}
