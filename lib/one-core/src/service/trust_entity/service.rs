use shared_types::TrustEntityId;

use super::dto::{
    CreateTrustEntityRequestDTO, GetTrustEntitiesResponseDTO, GetTrustEntityResponseDTO,
    ListTrustEntitiesQueryDTO,
};
use super::mapper::trust_entity_from_request;
use super::TrustEntityService;
use crate::model::did::DidRelations;
use crate::model::trust_anchor::{TrustAnchorRelations, TrustAnchorRole};
use crate::model::trust_entity::TrustEntityRelations;
use crate::repository::error::DataLayerError;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError,
};

impl TrustEntityService {
    pub async fn create_trust_entity(
        &self,
        request: CreateTrustEntityRequestDTO,
    ) -> Result<TrustEntityId, ServiceError> {
        let trust_anchor = self
            .trust_anchor_repository
            .get(request.trust_anchor_id)
            .await?
            .ok_or(EntityNotFoundError::TrustAnchor(request.trust_anchor_id))?;

        if trust_anchor.role != TrustAnchorRole::Publisher {
            return Err(BusinessLogicError::TrustAnchorMustBePublish.into());
        }

        let did = self
            .did_repository
            .get_did(&request.did_id, &DidRelations::default())
            .await?
            .ok_or(EntityNotFoundError::TrustAnchor(request.trust_anchor_id))?;

        let trust = self
            .trust_provider
            .get(&trust_anchor.type_field)
            .ok_or_else(|| MissingProviderError::TrustManager(trust_anchor.type_field.clone()))?;

        let entity = trust_entity_from_request(request, trust_anchor.clone(), did);

        trust.publish_entity(&trust_anchor, &entity).await;

        self.trust_entity_repository
            .create(entity)
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => {
                    BusinessLogicError::TrustEntityAlreadyPresent.into()
                }
                err => err.into(),
            })
    }

    pub async fn get_trust_entity(
        &self,
        id: TrustEntityId,
    ) -> Result<GetTrustEntityResponseDTO, ServiceError> {
        let result = self
            .trust_entity_repository
            .get(
                id,
                &TrustEntityRelations {
                    trust_anchor: Some(TrustAnchorRelations::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::TrustEntity(id))?;

        Ok(result.into())
    }

    pub async fn delete_trust_entity(&self, id: TrustEntityId) -> Result<(), ServiceError> {
        self.trust_entity_repository
            .get(id, &Default::default())
            .await?
            .ok_or(ServiceError::EntityNotFound(
                EntityNotFoundError::TrustEntity(id),
            ))?;

        self.trust_entity_repository
            .delete(id)
            .await
            .map_err(Into::into)
    }

    pub async fn list_trust_entities(
        &self,
        filters: ListTrustEntitiesQueryDTO,
    ) -> Result<GetTrustEntitiesResponseDTO, ServiceError> {
        self.trust_entity_repository
            .list(filters)
            .await
            .map_err(Into::into)
    }
}
