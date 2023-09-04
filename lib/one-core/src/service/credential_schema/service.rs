use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::organisation::OrganisationRelations;
use crate::service::credential_schema::dto::{
    CreateCredentialSchemaFromJwtRequestDTO, CreateCredentialSchemaRequestDTO,
    CreateCredentialSchemaResponseDTO, GetCredentialSchemaListResponseDTO,
    GetCredentialSchemaQueryDTO,
};
use crate::service::credential_schema::mapper::from_create_request;
use crate::service::credential_schema::CredentialSchemaService;
use crate::{model::credential_schema::CredentialSchemaRelations, service::error::ServiceError};

use super::dto::{
    CreateCredentialSchemaRequestWithIds, CredentialSchemaId, GetCredentialSchemaResponseDTO,
};

impl CredentialSchemaService {
    /// Creates a credential according to request
    ///
    /// # Arguments
    ///
    /// * `request` - create credential schema request
    pub async fn create_credential_schema(
        &self,
        request: CreateCredentialSchemaRequestDTO,
    ) -> Result<CreateCredentialSchemaResponseDTO, ServiceError> {
        let request: CreateCredentialSchemaRequestWithIds = request.into();

        super::validator::validate_create_request(&request, &self.config)?;

        let organisation = self
            .organisation_repository
            .get_organisation(
                &request.organisation_id,
                &OrganisationRelations { did: None },
            )
            .await
            .map_err(ServiceError::from)?;
        let credential_schema = from_create_request(request, organisation)?;

        let result = self
            .credential_schema_repository
            .create_credential_schema(credential_schema)
            .await
            .map_err(ServiceError::from)?;
        Ok(CreateCredentialSchemaResponseDTO { id: result })
    }

    /// Creates a credential according to JWT request
    ///
    /// # Arguments
    ///
    /// * `request` - create credential schema request
    pub async fn create_credential_schema_from_jwt(
        &self,
        request: CreateCredentialSchemaFromJwtRequestDTO,
    ) -> Result<CreateCredentialSchemaResponseDTO, ServiceError> {
        super::validator::validate_create_request(&request, &self.config)?;

        let organisation = self
            .organisation_repository
            .get_organisation(
                &request.organisation_id,
                &OrganisationRelations { did: None },
            )
            .await
            .map_err(ServiceError::from)?;
        let credential_schema = from_create_request(request, organisation)?;

        let result = self
            .credential_schema_repository
            .create_credential_schema(credential_schema)
            .await
            .map_err(ServiceError::from)?;
        Ok(CreateCredentialSchemaResponseDTO { id: result })
    }

    /// Deletes a credential schema
    ///
    /// # Arguments
    ///
    /// * `CredentialSchemaId` - Id of an existing credential schema
    pub async fn delete_credential_schema(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<(), ServiceError> {
        self.credential_schema_repository
            .delete_credential_schema(credential_schema_id)
            .await
            .map_err(ServiceError::from)
    }

    /// Returns details of a credential schema
    ///
    /// # Arguments
    ///
    /// * `CredentialSchemaId` - Id of an existing credential schema
    pub async fn get_credential_schema(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<GetCredentialSchemaResponseDTO, ServiceError> {
        let schema = self
            .credential_schema_repository
            .get_credential_schema(
                credential_schema_id,
                &CredentialSchemaRelations {
                    claim_schema: Some(ClaimSchemaRelations {}),
                    organisation: Some(OrganisationRelations { did: None }),
                },
            )
            .await
            .map_err(ServiceError::from)?;

        schema.try_into()
    }

    /// Returns list of credential schemas according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_credential_schema_list(
        &self,
        query: GetCredentialSchemaQueryDTO,
    ) -> Result<GetCredentialSchemaListResponseDTO, ServiceError> {
        let result = self
            .credential_schema_repository
            .get_credential_schema_list(query)
            .await
            .map_err(ServiceError::from)?;
        result.try_into()
    }
}
