use shared_types::TrustEntityId;

use super::dto::{
    CreateTrustEntityRequestDTO, GetTrustEntitiesResponseDTO, GetTrustEntityResponseDTO,
    ListTrustEntitiesQueryDTO,
};
use super::mapper::trust_entity_from_request;
use super::TrustEntityService;
use crate::model::history::{HistoryAction, HistoryEntityType};
use crate::model::organisation::OrganisationRelations;
use crate::model::trust_anchor::{TrustAnchorRelations, TrustAnchorRole};
use crate::model::trust_entity::TrustEntityRelations;
use crate::repository::error::DataLayerError;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError,
};
use crate::util::history::history_event;

impl TrustEntityService {
    pub async fn create_trust_entity(
        &self,
        request: CreateTrustEntityRequestDTO,
    ) -> Result<TrustEntityId, ServiceError> {
        let trust_anchor = self
            .trust_anchor_repository
            .get(
                request.trust_anchor_id,
                &TrustAnchorRelations {
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await?
            .ok_or(EntityNotFoundError::TrustAnchor(request.trust_anchor_id))?;

        if trust_anchor.role != TrustAnchorRole::Publisher {
            return Err(BusinessLogicError::TrustAnchorMustBePublish.into());
        }

        let trust = self
            .trust_provider
            .get(&trust_anchor.type_field)
            .ok_or_else(|| MissingProviderError::TrustManager(trust_anchor.type_field.clone()))?;

        let entity = trust_entity_from_request(request, trust_anchor.clone());

        trust.publish_entity(&trust_anchor, &entity).await;

        let result = self.trust_entity_repository.create(entity).await;

        let Some(organisation) = trust_anchor.organisation else {
            return Err(BusinessLogicError::GeneralInputValidationError.into());
        };

        match result {
            Ok(entity_id) => {
                let _ = self
                    .history_repository
                    .create_history(history_event(
                        entity_id,
                        organisation.id,
                        HistoryEntityType::TrustEntity,
                        HistoryAction::Created,
                    ))
                    .await;
                Ok(entity_id)
            }
            Err(DataLayerError::AlreadyExists) => {
                Err(BusinessLogicError::TrustEntityAlreadyPresent.into())
            }
            Err(err) => Err(err.into()),
        }
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
                    trust_anchor: Some(TrustAnchorRelations {
                        organisation: Some(OrganisationRelations::default()),
                    }),
                },
            )
            .await?
            .ok_or(EntityNotFoundError::TrustEntity(id))?;

        result.try_into()
    }

    pub async fn delete_trust_entity(&self, id: TrustEntityId) -> Result<(), ServiceError> {
        let Some(trust_entity) = self
            .trust_entity_repository
            .get(
                id,
                &TrustEntityRelations {
                    trust_anchor: Some(TrustAnchorRelations {
                        organisation: Some(OrganisationRelations::default()),
                    }),
                },
            )
            .await?
        else {
            return Err(ServiceError::EntityNotFound(
                EntityNotFoundError::TrustEntity(id),
            ));
        };

        let Some(trust_anchor) = trust_entity.trust_anchor else {
            return Err(BusinessLogicError::GeneralInputValidationError.into());
        };

        let Some(organisation) = trust_anchor.organisation else {
            return Err(BusinessLogicError::GeneralInputValidationError.into());
        };

        self.trust_entity_repository.delete(id).await?;

        let _ = self
            .history_repository
            .create_history(history_event(
                id,
                organisation.id,
                HistoryEntityType::TrustEntity,
                HistoryAction::Deleted,
            ))
            .await;

        Ok(())
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
