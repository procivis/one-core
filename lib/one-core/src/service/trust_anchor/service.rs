use shared_types::TrustAnchorId;

use super::dto::{
    CreateTrustAnchorRequestDTO, GetTrustAnchorDetailResponseDTO,
    GetTrustAnchorEntityListResponseDTO, GetTrustAnchorsResponseDTO, ListTrustAnchorsQueryDTO,
};
use super::mapper::trust_anchor_from_request;
use super::TrustAnchorService;
use crate::config::core_config::TrustManagementType;
use crate::config::validator::trust_management::validate_trust_management;
use crate::repository::error::DataLayerError;
use crate::service::error::{BusinessLogicError, EntityNotFoundError, ServiceError};
use crate::service::trust_anchor::dto::GetTrustAnchorResponseDTO;

impl TrustAnchorService {
    pub async fn create_trust_anchor(
        &self,
        request: CreateTrustAnchorRequestDTO,
    ) -> Result<TrustAnchorId, ServiceError> {
        validate_trust_management(&request.r#type, &self.config.trust_management)
            .map_err(|_| BusinessLogicError::UnknownTrustAnchorType)?;

        let core_base_url = if request
            .is_publisher
            .is_some_and(|is_publisher| is_publisher)
        {
            if request.publisher_reference.is_some() {
                return Err(BusinessLogicError::TrustAnchorInvalidCreateRequest {
                    reason: "Invalid publisher_reference".to_string(),
                }
                .into());
            }

            Some(self.core_base_url.as_ref().ok_or(ServiceError::Other(
                "Missing core_base_url in trust anchor service".to_string(),
            ))?)
        } else {
            if request.publisher_reference.is_none() {
                return Err(BusinessLogicError::TrustAnchorInvalidCreateRequest {
                    reason: "Missing publisher_reference".to_string(),
                }
                .into());
            }
            None
        };

        let anchor = trust_anchor_from_request(request, core_base_url)?;

        self.trust_anchor_repository
            .create(anchor)
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => BusinessLogicError::TrustAnchorNameTaken.into(),
                err => err.into(),
            })
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
            .get_fields(&result.r#type)?
            .r#type;
        if trust_list_type != TrustManagementType::SimpleTrustList {
            return Err(BusinessLogicError::TrustAnchorTypeIsNotSimpleTrustList.into());
        }

        let entities = self
            .trust_entity_repository
            .get_active_by_trust_anchor_id(trust_anchor_id)
            .await?;

        let entities = entities
            .into_iter()
            .map(TryInto::<GetTrustAnchorEntityListResponseDTO>::try_into)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(GetTrustAnchorResponseDTO {
            id: result.id,
            name: result.name,
            created_date: result.created_date,
            last_modified: result.last_modified,
            entities,
        })
    }

    pub async fn get_trust_anchor(
        &self,
        anchor_id: TrustAnchorId,
    ) -> Result<GetTrustAnchorDetailResponseDTO, ServiceError> {
        let response = self.trust_anchor_repository.get(anchor_id).await?.ok_or(
            ServiceError::EntityNotFound(EntityNotFoundError::TrustAnchor(anchor_id)),
        )?;

        Ok(response.into())
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
            .get(anchor_id)
            .await?
            .ok_or(EntityNotFoundError::TrustAnchor(anchor_id))?;

        self.trust_anchor_repository
            .delete(anchor_id)
            .await
            .map_err(Into::into)
    }
}
