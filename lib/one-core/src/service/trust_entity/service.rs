use shared_types::{OrganisationId, TrustEntityId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::CreateTrustEntityRequestDTO;
use super::TrustEntityService;
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::organisation::Organisation;
use crate::model::trust_anchor::TrustAnchorRole;
use crate::repository::error::DataLayerError;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError,
};

impl TrustEntityService {
    pub async fn create_trust_entity(
        &self,
        entity: CreateTrustEntityRequestDTO,
    ) -> Result<TrustEntityId, ServiceError> {
        let trust_anchor = self
            .trust_anchor_repository
            .get(entity.trust_anchor_id)
            .await?
            .ok_or(EntityNotFoundError::TrustAnchor(entity.trust_anchor_id))?;

        if trust_anchor.role != TrustAnchorRole::Publisher {
            return Err(BusinessLogicError::TrustAnchorMustBePublish.into());
        }

        let trust = self
            .trust_provider
            .get(&trust_anchor.type_field)
            .ok_or_else(|| MissingProviderError::TrustManager(trust_anchor.type_field.clone()))?;

        let entity = entity.into();

        trust.publish_entity(&trust_anchor, &entity).await;

        let result = self.trust_entity_repository.create(entity).await;

        match result {
            Ok(entity_id) => {
                let _ = self
                    .history_repository
                    .create_history(create_history_event(
                        entity_id,
                        trust_anchor.organisation_id,
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
}

fn create_history_event(entity_id: TrustEntityId, organisation_id: OrganisationId) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Created,
        entity_id: Some(entity_id.into()),
        entity_type: HistoryEntityType::TrustEntity,
        metadata: None,
        organisation: Some(Organisation {
            id: organisation_id,
            created_date: OffsetDateTime::UNIX_EPOCH,
            last_modified: OffsetDateTime::UNIX_EPOCH,
        }),
    }
}
