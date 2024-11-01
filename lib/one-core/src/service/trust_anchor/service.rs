use shared_types::TrustAnchorId;

use super::dto::{
    CreateTrustAnchorRequestDTO, GetTrustAnchorDetailResponseDTO, GetTrustAnchorsResponseDTO,
    ListTrustAnchorsQueryDTO,
};
use super::mapper::trust_anchor_from_request;
use super::TrustAnchorService;
use crate::config::core_config::TrustManagementType;
use crate::config::validator::trust_management::validate_trust_management;
use crate::model::organisation::OrganisationRelations;
use crate::model::trust_anchor::TrustAnchorRelations;
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

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?;

        let Some(organisation) = organisation else {
            return Err(BusinessLogicError::MissingOrganisation(request.organisation_id).into());
        };

        let core_base_url = self.core_base_url.as_ref().ok_or(ServiceError::Other(
            "Missing core_base_url in trust anchor service".to_string(),
        ))?;

        let anchor = trust_anchor_from_request(request, organisation, core_base_url);

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
            .get(
                trust_anchor_id,
                &TrustAnchorRelations {
                    organisation: Some(OrganisationRelations::default()),
                },
            )
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

        let entities = entities
            .into_iter()
            .filter_map(|entry| entry.try_into().ok())
            .collect();

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
        let response = self
            .trust_anchor_repository
            .get(
                anchor_id,
                &TrustAnchorRelations {
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await?
            .ok_or(ServiceError::EntityNotFound(
                EntityNotFoundError::TrustAnchor(anchor_id),
            ))?;

        response.try_into()
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
            .get(anchor_id, &Default::default())
            .await?
            .ok_or(EntityNotFoundError::TrustAnchor(anchor_id))?;

        self.trust_anchor_repository
            .delete(anchor_id)
            .await
            .map_err(Into::into)
    }
}
