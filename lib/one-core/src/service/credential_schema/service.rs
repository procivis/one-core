use crate::{
    common_mapper::list_response_into,
    model::{
        claim_schema::ClaimSchemaRelations,
        credential_schema::{CredentialSchemaId, CredentialSchemaRelations},
        organisation::OrganisationRelations,
    },
    repository::error::DataLayerError,
    service::{
        credential_schema::{
            dto::{
                CreateCredentialSchemaRequestDTO, CredentialSchemaDetailResponseDTO,
                GetCredentialSchemaListResponseDTO, GetCredentialSchemaQueryDTO,
            },
            mapper::from_create_request,
            CredentialSchemaService,
        },
        error::{EntityNotFoundError, ServiceError},
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
    ) -> Result<CredentialSchemaId, ServiceError> {
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
            .await?;

        let Some(organisation) = organisation else {
            return Err(EntityNotFoundError::Organisation(request.organisation_id).into());
        };

        let credential_schema = from_create_request(request, organisation)?;

        self.credential_schema_repository
            .create_credential_schema(credential_schema)
            .await
            .map_err(ServiceError::from)
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
            .map_err(|error| match error {
                DataLayerError::RecordNotUpdated => {
                    EntityNotFoundError::CredentialSchema(*credential_schema_id).into()
                }
                error => ServiceError::from(error),
            })
    }

    /// Returns details of a credential schema
    ///
    /// # Arguments
    ///
    /// * `CredentialSchemaId` - Id of an existing credential schema
    pub async fn get_credential_schema(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<CredentialSchemaDetailResponseDTO, ServiceError> {
        let schema = self
            .credential_schema_repository
            .get_credential_schema(
                credential_schema_id,
                &CredentialSchemaRelations {
                    claim_schemas: Some(ClaimSchemaRelations::default()),
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await?;

        let Some(schema) = schema else {
            return Err(EntityNotFoundError::CredentialSchema(*credential_schema_id).into());
        };

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
            .await?;
        Ok(list_response_into(result))
    }
}
