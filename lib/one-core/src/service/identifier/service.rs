use shared_types::{DidId, IdentifierId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::IdentifierService;
use super::dto::{
    CreateIdentifierRequestDTO, GetIdentifierListResponseDTO, GetIdentifierResponseDTO,
};
use crate::model::did::DidRelations;
use crate::model::identifier::{
    Identifier, IdentifierListQuery, IdentifierRelations, IdentifierStatus, IdentifierType,
};
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::repository::error::DataLayerError;
use crate::service::error::{EntityNotFoundError, ServiceError};
use crate::service::identifier::mapper::to_create_did_request;

impl IdentifierService {
    /// Returns details of an identifier
    ///
    /// # Arguments
    ///
    /// * `id` - Identifier uuid
    pub async fn get_identifier(
        &self,
        id: &IdentifierId,
    ) -> Result<GetIdentifierResponseDTO, ServiceError> {
        let identifier = self
            .identifier_repository
            .get(
                *id,
                &IdentifierRelations {
                    did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        keys: Some(KeyRelations::default()),
                    }),
                    key: Some(KeyRelations {
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    organisation: Some(Default::default()),
                },
            )
            .await?;

        let Some(identifier) = identifier else {
            return Err(EntityNotFoundError::Identifier(*id).into());
        };

        identifier.try_into()
    }

    /// Returns an identifier by its DID ID
    ///
    /// # Arguments
    ///
    /// * `did_id` - DID uuid
    pub async fn get_identifier_by_did_id(
        &self,
        did_id: &DidId,
    ) -> Result<GetIdentifierResponseDTO, ServiceError> {
        let identifier = self
            .identifier_repository
            .get_from_did_id(
                *did_id,
                &IdentifierRelations {
                    did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        keys: Some(KeyRelations::default()),
                    }),
                    key: None,
                    organisation: Some(Default::default()),
                },
            )
            .await?;

        let Some(identifier) = identifier else {
            return Err(EntityNotFoundError::IdentifierByDidId(*did_id).into());
        };

        identifier.try_into()
    }

    /// Returns list of identifiers according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_identifier_list(
        &self,
        query: IdentifierListQuery,
    ) -> Result<GetIdentifierListResponseDTO, ServiceError> {
        Ok(self
            .identifier_repository
            .get_identifier_list(query)
            .await?
            .into())
    }

    /// Creates a new identifier with data provided in arguments
    ///
    /// # Arguments
    ///
    /// * `request` - identifier data
    pub async fn create_identifier(
        &self,
        request: CreateIdentifierRequestDTO,
    ) -> Result<IdentifierId, ServiceError> {
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &Default::default())
            .await?
            .ok_or(EntityNotFoundError::Organisation(request.organisation_id))?;

        match (request.did, request.key_id) {
            // IdentifierType::Did
            (Some(did), None) => {
                let did_id = self
                    .did_service
                    .create_did(to_create_did_request(&request.name, did, organisation.id))
                    .await?;
                self.get_identifier_by_did_id(&did_id).await.map(|i| i.id)
            }
            // IdentifierType::Key
            (None, Some(key_id)) => {
                let key = self
                    .key_repository
                    .get_key(&key_id, &Default::default())
                    .await?
                    .ok_or(EntityNotFoundError::Key(key_id))?;

                let id = Uuid::new_v4().into();
                let now = OffsetDateTime::now_utc();
                let identifier = Identifier {
                    id,
                    created_date: now,
                    last_modified: now,
                    name: request.name,
                    organisation: Some(organisation),
                    r#type: IdentifierType::Key,
                    is_remote: false,
                    status: IdentifierStatus::Active,
                    deleted_at: None,
                    did: None,
                    key: Some(key),
                };

                self.identifier_repository.create(identifier).await?;

                Ok(id)
            }
            _ => Err(ServiceError::ValidationError(
                "Invalid request, specify either did or keyId".to_string(),
            )),
        }
    }

    /// Deletes an identifier
    ///
    /// # Arguments
    ///
    /// * `id` - Identifier uuid
    pub async fn delete_identifier(&self, id: &IdentifierId) -> Result<(), ServiceError> {
        self.identifier_repository
            .delete(id)
            .await
            .map_err(|e| match e {
                DataLayerError::RecordNotUpdated => {
                    ServiceError::EntityNotFound(EntityNotFoundError::Identifier(*id))
                }
                e => e.into(),
            })?;
        Ok(())
    }
}
