use shared_types::CredentialSchemaId;
use uuid::Uuid;

use super::import::import_credential_schema;
use crate::common_mapper::list_response_into;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::history::HistoryAction;
use crate::model::organisation::OrganisationRelations;
use crate::repository::error::DataLayerError;
use crate::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CredentialSchemaDetailResponseDTO,
    CredentialSchemaShareResponseDTO, GetCredentialSchemaListResponseDTO,
    GetCredentialSchemaQueryDTO, ImportCredentialSchemaRequestDTO,
};
use crate::service::credential_schema::mapper::from_create_request_with_id;
use crate::service::credential_schema::CredentialSchemaService;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError,
};
use crate::util::history::log_history_event_credential_schema;

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

        let formatter = self
            .formatter_provider
            .get_formatter(&request.format)
            .ok_or(MissingProviderError::Formatter(request.format.to_owned()))?;
        super::validator::validate_create_request(
            &request,
            &self.config,
            &*formatter,
            &*self.revocation_method_provider,
            false,
        )?;

        super::validator::credential_schema_already_exists(
            &*self.credential_schema_repository,
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
        let id = CredentialSchemaId::from(Uuid::new_v4());
        let schema_id = formatter.credential_schema_id(id, &request, core_base_url)?;
        let imported_source_url = format!("{core_base_url}/ssi/schema/v1/{id}");
        let credential_schema = from_create_request_with_id(
            id,
            request,
            organisation,
            format_type,
            None,
            schema_id,
            imported_source_url,
        )?;

        let result = self
            .credential_schema_repository
            .create_credential_schema(credential_schema.to_owned())
            .await
            .map_err(ServiceError::from)?;

        let _ = log_history_event_credential_schema(
            &*self.history_repository,
            &credential_schema,
            HistoryAction::Created,
        )
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
        self.credential_schema_repository
            .get_credential_schema(credential_schema_id, &Default::default())
            .await?
            .ok_or(BusinessLogicError::MissingCredentialSchema)?;

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

        let credential_schema = import_credential_schema(
            request.schema,
            organisation,
            &self.config,
            &*self.credential_schema_repository,
            &*self.formatter_provider,
            &*self.revocation_method_provider,
        )
        .await?;

        let _ = log_history_event_credential_schema(
            &*self.history_repository,
            &credential_schema,
            HistoryAction::Imported,
        )
        .await;

        Ok(credential_schema.id)
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

        let _ = log_history_event_credential_schema(
            &*self.history_repository,
            &credential_schema,
            HistoryAction::Shared,
        )
        .await;

        Ok(CredentialSchemaShareResponseDTO {
            url: credential_schema.imported_source_url,
        })
    }
}
