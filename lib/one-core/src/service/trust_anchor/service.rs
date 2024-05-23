use shared_types::{OrganisationId, TrustAnchorId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateTrustAnchorRequestDTO, GetTrustAnchorsResponseDTO, ListTrustAnchorsQueryDTO,
};
use super::TrustAnchorService;
use crate::config::core_config::TrustManagementType;
use crate::config::validator::trust_management::validate_trust_management;
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::organisation::Organisation;
use crate::model::trust_anchor::TrustAnchor;
use crate::repository::error::DataLayerError;
use crate::service::error::{BusinessLogicError, EntityNotFoundError, ServiceError};
use crate::service::trust_anchor::dto::GetTrustAnchorResponseDTO;

impl TrustAnchorService {
    pub async fn create_trust_anchor(
        &self,
        anchor: CreateTrustAnchorRequestDTO,
    ) -> Result<(), ServiceError> {
        validate_trust_management(&anchor.type_, &self.config.trust_management)
            .map_err(|_| BusinessLogicError::UnknownTrustAnchorType)?;

        let organisation_id = anchor.organisation_id;

        let result = self.trust_anchor_repository.create(anchor.into()).await;

        match result {
            Ok(id) => {
                let _ = self
                    .history_repository
                    .create_history(create_history_event(id, organisation_id))
                    .await;
                Ok(())
            }
            Err(DataLayerError::AlreadyExists) => {
                Err(BusinessLogicError::TrustAnchorNameTaken.into())
            }
            Err(err) => Err(err.into()),
        }
    }

    pub async fn get_trust_list(
        &self,
        trust_anchor_id: TrustAnchorId,
    ) -> Result<GetTrustAnchorResponseDTO, ServiceError> {
        let result = self
            .trust_anchor_repository
            .get(trust_anchor_id)
            .await?
            .ok_or(ServiceError::EntityNotFound(
                EntityNotFoundError::TrustAnchor(trust_anchor_id),
            ))?;

        let trust_list_type = self
            .config
            .trust_management
            .get_fields(&result.type_field)?
            .r#type;
        if trust_list_type != TrustManagementType::SimpleTrustList {
            return Err(BusinessLogicError::TrustAnchorTypeIsNotSimpleTrustList.into());
        }

        let entities = self
            .trust_entity_repository
            .get_by_trust_anchor_id(trust_anchor_id)
            .await?;

        Ok(GetTrustAnchorResponseDTO {
            id: result.id,
            name: result.name,
            created_date: result.created_date,
            last_modified: result.last_modified,
            entities: entities.into_iter().map(Into::into).collect(),
        })
    }

    pub async fn get_trust_anchor(
        &self,
        anchor_id: TrustAnchorId,
    ) -> Result<TrustAnchor, ServiceError> {
        self.trust_anchor_repository
            .get(anchor_id)
            .await?
            .ok_or(EntityNotFoundError::TrustAnchor(anchor_id).into())
    }

    pub async fn list_trust_anchors(
        &self,
        filters: ListTrustAnchorsQueryDTO,
    ) -> Result<GetTrustAnchorsResponseDTO, ServiceError> {
        self.trust_anchor_repository
            .list(filters)
            .await
            .map_err(Into::into)
    }

    pub async fn delete_trust_anchor(&self, anchor_id: TrustAnchorId) -> Result<(), ServiceError> {
        self.trust_anchor_repository
            .delete(anchor_id)
            .await
            .map_err(Into::into)
    }
}

fn create_history_event(trust_id: TrustAnchorId, organisation_id: OrganisationId) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Created,
        entity_id: Some(trust_id.into()),
        entity_type: HistoryEntityType::TrustAnchor,
        metadata: None,
        organisation: Some(Organisation {
            id: organisation_id,
            created_date: OffsetDateTime::UNIX_EPOCH,
            last_modified: OffsetDateTime::UNIX_EPOCH,
        }),
    }
}
