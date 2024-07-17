use shared_types::CredentialSchemaId;

use crate::common_mapper::list_response_into;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::organisation::OrganisationRelations;
use crate::repository::error::DataLayerError;
use crate::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CredentialSchemaDetailResponseDTO,
    CredentialSchemaShareResponseDTO, GetCredentialSchemaListResponseDTO,
    GetCredentialSchemaQueryDTO, ImportCredentialSchemaRequestDTO,
};
use crate::service::credential_schema::mapper::{
    from_create_request, schema_create_history_event, schema_delete_history_event,
    schema_import_history_event, schema_share_history_event,
};
use crate::service::credential_schema::CredentialSchemaService;
use crate::service::error::{BusinessLogicError, EntityNotFoundError, ServiceError};

use super::mapper::from_create_request_with_id;

impl CredentialSchemaService {
    /// Creates a credential schema according to request
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

        super::validator::validate_create_request(
            &request,
            &self.config,
            &self.formatter_provider,
            false,
        )?;

        super::validator::credential_schema_already_exists(
            &self.credential_schema_repository,
            &request.name,
            request.schema_id.clone(),
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

        let format_type = &self.config.format.get_fields(&request.format)?.r#type;
        let credential_schema =
            from_create_request(request, organisation, core_base_url, format_type, None)?;

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
            .get_credential_schema_list(query, &Default::default())
            .await?;
        Ok(list_response_into(result))
    }

    /// Imports a credential schema according to request
    ///
    /// # Arguments
    ///
    /// * `request` - create credential schema request
    pub async fn import_credential_schema(
        &self,
        request: ImportCredentialSchemaRequestDTO,
    ) -> Result<CredentialSchemaId, ServiceError> {
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?
            .ok_or(ServiceError::BusinessLogic(
                BusinessLogicError::MissingOrganisation(request.organisation_id),
            ))?;

        let credential_schema_id = request.schema.id.into();
        let create_request = request.schema.to_owned().into();

        super::validator::validate_create_request(
            &create_request,
            &self.config,
            &self.formatter_provider,
            true,
        )?;

        super::validator::credential_schema_already_exists(
            &self.credential_schema_repository,
            &create_request.name,
            create_request.schema_id.clone(),
            create_request.organisation_id,
        )
        .await?;

        super::validator::check_claims_presence_in_layout_properties(&create_request)?;
        super::validator::check_background_properties(&create_request)?;
        super::validator::check_logo_properties(&create_request)?;

        let format_type = &self
            .config
            .format
            .get_fields(&request.schema.format)?
            .r#type;
        let credential_schema = from_create_request_with_id(
            credential_schema_id,
            create_request,
            organisation,
            "", // importing credential schema will always contain the schema_id
            format_type,
            Some(request.schema.schema_type.to_owned().into()),
        )?;

        let result = self
            .credential_schema_repository
            .create_credential_schema(credential_schema.to_owned())
            .await
            .map_err(ServiceError::from)?;

        let _ = self
            .history_repository
            .create_history(schema_import_history_event(credential_schema))
            .await;

        Ok(result)
    }

    /// Creates share credential schema URL
    ///
    /// # Arguments
    ///
    /// * `credential_schema_id` - id of credential schema to share
    pub async fn share_credential_schema(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<CredentialSchemaShareResponseDTO, ServiceError> {
        let core_base_url = self
            .core_base_url
            .as_ref()
            .ok_or_else(|| ServiceError::Other("Missing core base_url".to_string()))?;

        let credential_schema = self
            .credential_schema_repository
            .get_credential_schema(
                credential_schema_id,
                &CredentialSchemaRelations {
                    claim_schemas: Some(ClaimSchemaRelations::default()),
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await?
            .ok_or(ServiceError::EntityNotFound(
                EntityNotFoundError::CredentialSchema(*credential_schema_id),
            ))?;

        let _ = self
            .history_repository
            .create_history(schema_share_history_event(credential_schema))
            .await;

        Ok(CredentialSchemaShareResponseDTO {
            url: format!("{core_base_url}/ssi/schema/v1/{credential_schema_id}"),
        })
    }
}
