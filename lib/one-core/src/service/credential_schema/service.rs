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
            mapper::{
                from_create_request, schema_create_history_event, schema_delete_history_event,
            },
            CredentialSchemaService,
        },
        error::{BusinessLogicError, EntityNotFoundError, ServiceError},
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
        let core_base_url = self
            .core_base_url
            .as_ref()
            .ok_or_else(|| ServiceError::Other("Missing core base_url".to_string()))?;

        super::validator::validate_create_request(&request, &self.config)?;

        super::validator::credential_schema_already_exists(
            &self.credential_schema_repository,
            &request.name,
            request.organisation_id,
        )
        .await?;

        super::validator::check_claims_presence_in_layout_properties(&request)?;
        super::validator::check_background_properties(&request)?;
        super::validator::check_logo_properties(&request)?;

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?;

        let Some(organisation) = organisation else {
            return Err(BusinessLogicError::MissingOrganisation(request.organisation_id).into());
        };

        let credential_schema = from_create_request(request, organisation, core_base_url)?;

        let result = self
            .credential_schema_repository
            .create_credential_schema(credential_schema.to_owned())
            .await
            .map_err(ServiceError::from)?;

        let _ = self
            .history_repository
            .create_history(schema_create_history_event(credential_schema))
            .await;

        Ok(result)
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
        let schema = self
            .credential_schema_repository
            .get_credential_schema(
                credential_schema_id,
                &CredentialSchemaRelations {
                    organisation: Some(OrganisationRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(credential_schema) = schema else {
            return Err(BusinessLogicError::MissingCredentialSchema.into());
        };

        self.credential_schema_repository
            .delete_credential_schema(credential_schema_id)
            .await
            .map_err(|error| match error {
                DataLayerError::RecordNotUpdated => {
                    EntityNotFoundError::CredentialSchema(*credential_schema_id).into()
                }
                error => ServiceError::from(error),
            })?;

        let _ = self
            .history_repository
            .create_history(schema_delete_history_event(credential_schema))
            .await;

        Ok(())
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

        if schema.deleted_at.is_some() {
            return Err(EntityNotFoundError::CredentialSchema(*credential_schema_id).into());
        }

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
