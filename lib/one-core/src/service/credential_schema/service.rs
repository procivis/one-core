use crate::{
    model::{
        claim_schema::ClaimSchemaRelations, credential_schema::CredentialSchemaRelations,
        organisation::OrganisationRelations,
    },
    service::{
        credential_schema::{
            dto::{
                CreateCredentialSchemaRequestDTO, CreateCredentialSchemaResponseDTO,
                CredentialSchemaId, GetCredentialSchemaListResponseDTO,
                GetCredentialSchemaQueryDTO, GetCredentialSchemaResponseDTO,
            },
            mapper::from_create_request,
            CredentialSchemaService,
        },
        error::ServiceError,
    },
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
        super::validator::validate_create_request(&request, &self.config)?;

        super::validator::credential_schema_already_exists(
            &self.credential_schema_repository,
            &request.name,
            &request.organisation_id,
        )
        .await?;

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
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
                    claim_schemas: Some(ClaimSchemaRelations::default()),
                    organisation: Some(OrganisationRelations::default()),
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
