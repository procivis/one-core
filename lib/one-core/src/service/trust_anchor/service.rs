use shared_types::TrustAnchorId;

use super::TrustAnchorService;
use super::dto::{
    CreateTrustAnchorRequestDTO, GetTrustAnchorDetailResponseDTO,
    GetTrustAnchorEntityListResponseDTO, GetTrustAnchorResponseDTO, GetTrustAnchorsResponseDTO,
    ListTrustAnchorsQueryDTO,
};
use super::error::TrustAnchorServiceError;
use super::mapper::trust_anchor_from_request;
use crate::config::core_config::TrustManagementType;
use crate::config::validator::trust_management::validate_trust_management;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::repository::error::DataLayerError;

impl TrustAnchorService {
    pub async fn create_trust_anchor(
        &self,
        request: CreateTrustAnchorRequestDTO,
    ) -> Result<TrustAnchorId, TrustAnchorServiceError> {
        validate_trust_management(&request.r#type, &self.config.trust_management)
            .map_err(|_| TrustAnchorServiceError::UnknownType)?;

        let core_base_url = if request
            .is_publisher
            .is_some_and(|is_publisher| is_publisher)
        {
            if request.publisher_reference.is_some() {
                return Err(TrustAnchorServiceError::InvalidCreateRequest(
                    "Invalid publisher_reference".to_string(),
                ));
            }

            Some(
                self.core_base_url
                    .as_ref()
                    .ok_or(TrustAnchorServiceError::MappingError(
                        "Missing core_base_url in trust anchor service".to_string(),
                    ))?,
            )
        } else {
            if request.publisher_reference.is_none() {
                return Err(TrustAnchorServiceError::InvalidCreateRequest(
                    "Missing publisher_reference".to_string(),
                ));
            }
            None
        };

        let anchor = trust_anchor_from_request(request, core_base_url)?;

        let success_log = format!(
            "Created trust anchor `{}` ({}): type `{}`, publisher {}",
            anchor.name, anchor.id, anchor.r#type, anchor.is_publisher
        );
        let id = self
            .trust_anchor_repository
            .create(anchor)
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => TrustAnchorServiceError::AlreadyExists,
                err => err.error_while("creating trust achor").into(),
            })?;
        tracing::info!(message = success_log);
        Ok(id)
    }

    pub async fn get_trust_list(
        &self,
        trust_anchor_id: TrustAnchorId,
    ) -> Result<GetTrustAnchorResponseDTO, TrustAnchorServiceError> {
        let result = self
            .trust_anchor_repository
            .get(trust_anchor_id)
            .await
            .error_while("getting trust achor")?
            .ok_or(TrustAnchorServiceError::NotFound(trust_anchor_id))?;

        let trust_list_type = self
            .config
            .trust_management
            .get_fields(&result.r#type)
            .map_err(|_| TrustAnchorServiceError::UnknownType)?
            .r#type;
        if trust_list_type != TrustManagementType::SimpleTrustList {
            return Err(TrustAnchorServiceError::TypeIsNotSimpleTrustList);
        }

        let entities = self
            .trust_entity_repository
            .get_active_by_trust_anchor_id(trust_anchor_id)
            .await
            .error_while("getting trust entities")?;

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
    ) -> Result<GetTrustAnchorDetailResponseDTO, TrustAnchorServiceError> {
        let response = self
            .trust_anchor_repository
            .get(anchor_id)
            .await
            .error_while("getting trust anchor")?
            .ok_or(TrustAnchorServiceError::NotFound(anchor_id))?;

        Ok(response.into())
    }

    pub async fn list_trust_anchors(
        &self,
        filters: ListTrustAnchorsQueryDTO,
    ) -> Result<GetTrustAnchorsResponseDTO, TrustAnchorServiceError> {
        Ok(self
            .trust_anchor_repository
            .list(filters)
            .await
            .error_while("getting trust achors")?)
    }

    pub async fn delete_trust_anchor(
        &self,
        anchor_id: TrustAnchorId,
    ) -> Result<(), TrustAnchorServiceError> {
        let anchor = self
            .trust_anchor_repository
            .get(anchor_id)
            .await
            .error_while("getting trust achor")?
            .ok_or(TrustAnchorServiceError::NotFound(anchor_id))?;

        self.trust_anchor_repository
            .delete(anchor_id)
            .await
            .error_while("deleting trust achor")?;
        tracing::info!("Deleted trust anchor `{}` ({})", anchor.name, anchor_id);
        Ok(())
    }
}
