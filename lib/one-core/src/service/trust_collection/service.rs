use shared_types::{OrganisationId, TrustCollectionId};
use tracing::info;
use uuid::Uuid;

use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::list_response_into;
use crate::model::trust_collection::{TrustCollection, TrustCollectionListQuery};
use crate::repository::error::DataLayerError;
use crate::service::trust_collection::TrustCollectionService;
use crate::service::trust_collection::dto::{
    CreateTrustCollectionRequestDTO, GetTrustCollectionListResponseDTO,
    GetTrustCollectionResponseDTO,
};
use crate::service::trust_collection::error::TrustCollectionServiceError;
use crate::validator::throw_if_org_not_matching_session;

impl TrustCollectionService {
    pub async fn create_trust_collection(
        &self,
        request: CreateTrustCollectionRequestDTO,
    ) -> Result<TrustCollectionId, TrustCollectionServiceError> {
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("validating organisation")?;
        let trust_collection = self.map_create_trust_collection_request(request.clone())?;

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

    fn map_create_trust_collection_request(
        &self,
        request: CreateTrustCollectionRequestDTO,
    ) -> Result<TrustCollection, TrustCollectionServiceError> {
        let now = self.clock.now_utc();
        Ok(TrustCollection {
            id: Uuid::new_v4().into(),
            name: request.name,
            created_date: now,
            last_modified: now,
            deactivated_at: None,
            organisation_id: request.organisation_id,
            organisation: None,
        })
    }
}
