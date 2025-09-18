use shared_types::{IdentifierId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::IdentifierService;
use super::dto::{
    CreateIdentifierRequestDTO, GetIdentifierListResponseDTO, GetIdentifierResponseDTO,
};
use crate::common_validator::{
    throw_if_org_not_matching_session, throw_if_org_relation_not_matching_session,
};
use crate::config::core_config;
use crate::model::certificate::CertificateRelations;
use crate::model::did::DidRelations;
use crate::model::identifier::{
    Identifier, IdentifierListQuery, IdentifierRelations, IdentifierState, IdentifierType,
};
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::repository::error::DataLayerError;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, ServiceError, ValidationError,
};
use crate::service::identifier::mapper::{map_already_exists_error, to_create_did_request};
use crate::service::identifier::validator::validate_identifier_type;

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
                    certificates: Some(CertificateRelations {
                        key: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    organisation: Some(Default::default()),
                },
            )
            .await?;

        let Some(identifier) = identifier else {
            return Err(EntityNotFoundError::Identifier(*id).into());
        };
        throw_if_org_relation_not_matching_session(
            identifier.organisation.as_ref(),
            &*self.session_provider,
        )?;

        let mut certificates = None;
        if identifier.r#type == IdentifierType::Certificate {
            let mut certs = vec![];
            for certificate in
                identifier
                    .certificates
                    .as_ref()
                    .ok_or(ServiceError::MappingError(
                        "Certificates required for identifier type Certificate".to_string(),
                    ))?
            {
                certs.push(
                    self.certificate_service
                        .get_certificate(certificate.id)
                        .await?,
                );
            }
            certificates = Some(certs);
        }

        let mut result: GetIdentifierResponseDTO = identifier.try_into()?;
        result.certificates = certificates;
        Ok(result)
    }

    /// Returns list of identifiers according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_identifier_list(
        &self,
        organisation_id: &OrganisationId,
        query: IdentifierListQuery,
    ) -> Result<GetIdentifierListResponseDTO, ServiceError> {
        throw_if_org_not_matching_session(organisation_id, &*self.session_provider)?;
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
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)?;
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &Default::default())
            .await?
            .ok_or(EntityNotFoundError::Organisation(request.organisation_id))?;

        if organisation.deactivated_at.is_some() {
            return Err(
                BusinessLogicError::OrganisationIsDeactivated(request.organisation_id).into(),
            );
        }

        let now = OffsetDateTime::now_utc();
        match (request.did, request.key_id, request.certificates) {
            // IdentifierType::Did
            (Some(did), None, None) => {
                validate_identifier_type(
                    &core_config::IdentifierType::Did,
                    &self.config.identifier,
                )?;
                let (did, now) = self
                    .did_service
                    .create_did_without_identifier(to_create_did_request(
                        &request.name,
                        did,
                        organisation.id,
                    ))
                    .await?;
                let id = Uuid::new_v4().into();
                self.identifier_repository
                    .create(Identifier {
                        id,
                        created_date: now,
                        last_modified: now,
                        name: request.name,
                        organisation: Some(organisation),
                        r#type: IdentifierType::Did,
                        is_remote: false,
                        state: IdentifierState::Active,
                        deleted_at: None,
                        did: Some(did),
                        key: None,
                        certificates: None,
                    })
                    .await
                    .map_err(map_already_exists_error)?;
                Ok(id)
            }
            // IdentifierType::Key
            (None, Some(key_id), None) => {
                validate_identifier_type(
                    &core_config::IdentifierType::Key,
                    &self.config.identifier,
                )?;
                let key = self
                    .key_repository
                    .get_key(&key_id, &Default::default())
                    .await?
                    .ok_or(EntityNotFoundError::Key(key_id))?;

                if key.is_remote() {
                    return Err(ValidationError::KeyMustNotBeRemote(key.name).into());
                }

                let id = Uuid::new_v4().into();
                self.identifier_repository
                    .create(Identifier {
                        id,
                        created_date: now,
                        last_modified: now,
                        name: request.name,
                        organisation: Some(organisation),
                        r#type: IdentifierType::Key,
                        is_remote: false,
                        state: IdentifierState::Active,
                        deleted_at: None,
                        did: None,
                        key: Some(key),
                        certificates: None,
                    })
                    .await
                    .map_err(map_already_exists_error)?;

                Ok(id)
            }
            // IdentifierType::Certificate
            (None, None, Some(certificate_requests)) => {
                validate_identifier_type(
                    &core_config::IdentifierType::Certificate,
                    &self.config.identifier,
                )?;
                let id = Uuid::new_v4().into();

                let mut certificates = vec![];
                for request in certificate_requests {
                    certificates.push(
                        self.certificate_service
                            .validate_and_prepare_certificate(id, organisation.id, request)
                            .await?,
                    );
                }

                self.identifier_repository
                    .create(Identifier {
                        id,
                        created_date: now,
                        last_modified: now,
                        name: request.name,
                        organisation: Some(organisation),
                        r#type: IdentifierType::Certificate,
                        is_remote: false,
                        state: IdentifierState::Active,
                        deleted_at: None,
                        did: None,
                        key: None,
                        certificates: None,
                    })
                    .await
                    .map_err(map_already_exists_error)?;

                for certificate in certificates {
                    self.certificate_repository
                        .create(certificate)
                        .await
                        .map_err(map_already_exists_error)?;
                }

                Ok(id)
            }
            // invalid input combinations
            _ => Err(ValidationError::InvalidIdentifierInput.into()),
        }
    }

    /// Deletes an identifier
    ///
    /// # Arguments
    ///
    /// * `id` - Identifier uuid
    pub async fn delete_identifier(&self, id: &IdentifierId) -> Result<(), ServiceError> {
        let identifier = self
            .identifier_repository
            .get(
                *id,
                &IdentifierRelations {
                    organisation: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?;
        let Some(identifier) = identifier else {
            return Err(EntityNotFoundError::Identifier(*id).into());
        };
        throw_if_org_relation_not_matching_session(
            identifier.organisation.as_ref(),
            &*self.session_provider,
        )?;
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
