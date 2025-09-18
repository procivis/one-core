use shared_types::{CredentialSchemaId, OrganisationId};
use uuid::Uuid;

use super::import::import_credential_schema;
use crate::common_mapper::list_response_into;
use crate::common_validator::{
    throw_if_org_not_matching_session, throw_if_org_relation_not_matching_session,
};
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::history::HistoryAction;
use crate::model::organisation::OrganisationRelations;
use crate::repository::error::DataLayerError;
use crate::service::credential_schema::CredentialSchemaService;
use crate::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CredentialSchemaDetailResponseDTO,
    CredentialSchemaShareResponseDTO, GetCredentialSchemaListResponseDTO,
    GetCredentialSchemaQueryDTO, ImportCredentialSchemaRequestDTO,
};
use crate::service::credential_schema::mapper::{
    claim_schema_from_metadata_claim_schema, from_create_request_with_id,
};
use crate::service::credential_schema::validator::UniquenessCheckResult;
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
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)?;
        let core_base_url = self
            .core_base_url
            .as_ref()
            .ok_or_else(|| ServiceError::Other("Missing core base_url".to_string()))?;

        let formatter = self
            .formatter_provider
            .get_credential_formatter(&request.format)
            .ok_or(MissingProviderError::Formatter(request.format.to_owned()))?;
        super::validator::validate_create_request(
            &request,
            &self.config,
            &*formatter,
            &*self.revocation_method_provider,
            false,
        )?;

        match super::validator::credential_schema_already_exists(
            &*self.credential_schema_repository,
            &request.name,
            request.schema_id.clone(),
            request.organisation_id,
        )
        .await?
        {
            UniquenessCheckResult::SchemaIdConflict | UniquenessCheckResult::NameConflict => {
                return Err(BusinessLogicError::CredentialSchemaAlreadyExists.into());
            }
            UniquenessCheckResult::Ok => {}
        };

        super::validator::check_claims_presence_in_layout_properties(&request)?;
        super::validator::check_background_properties(&request)?;
        super::validator::check_logo_properties(&request)?;
        super::validator::validate_wallet_storage_type_supported(
            request.wallet_storage_type,
            &self.config,
        )?;

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?;

        let Some(organisation) = organisation else {
            return Err(BusinessLogicError::MissingOrganisation(request.organisation_id).into());
        };

        if organisation.deactivated_at.is_some() {
            return Err(
                BusinessLogicError::OrganisationIsDeactivated(request.organisation_id).into(),
            );
        }

        let format_type = &self.config.format.get_fields(&request.format)?.r#type;
        let id = CredentialSchemaId::from(Uuid::new_v4());
        let schema_id = formatter.credential_schema_id(id, &request, core_base_url)?;
        let imported_source_url = format!("{core_base_url}/ssi/schema/v1/{id}");
        let mut credential_schema = from_create_request_with_id(
            id,
            request,
            organisation,
            format_type,
            None,
            schema_id,
            imported_source_url,
        )?;

        let metadata_claims = formatter
            .get_metadata_claims()
            .into_iter()
            .map(|metadata_claim| {
                claim_schema_from_metadata_claim_schema(
                    metadata_claim,
                    credential_schema.created_date,
                )
            })
            .collect::<Vec<_>>();
        credential_schema
            .claim_schemas
            .as_mut()
            .ok_or(ServiceError::MappingError(
                "Missing claim schemas".to_string(),
            ))?
            .extend(metadata_claims);

        let result = self
            .credential_schema_repository
            .create_credential_schema(credential_schema.to_owned())
            .await
            .map_err(ServiceError::from)?;

        log_history_event_credential_schema(
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
        let credential_schema = self
            .credential_schema_repository
            .get_credential_schema(
                credential_schema_id,
                &CredentialSchemaRelations {
                    organisation: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(BusinessLogicError::MissingCredentialSchema)?;

        throw_if_org_relation_not_matching_session(
            credential_schema.organisation.as_ref(),
            &*self.session_provider,
        )?;

        self.credential_schema_repository
            .delete_credential_schema(&credential_schema)
            .await
            .map_err(|error| match error {
                DataLayerError::RecordNotUpdated => {
                    EntityNotFoundError::CredentialSchema(*credential_schema_id).into()
                }
                error => ServiceError::from(error),
            })?;

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

        throw_if_org_relation_not_matching_session(
            schema.organisation.as_ref(),
            &*self.session_provider,
        )?;

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
        organisation_id: &OrganisationId,
        query: GetCredentialSchemaQueryDTO,
    ) -> Result<GetCredentialSchemaListResponseDTO, ServiceError> {
        throw_if_org_not_matching_session(organisation_id, &*self.session_provider)?;
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
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)?;
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?
            .ok_or(ServiceError::BusinessLogic(
                BusinessLogicError::MissingOrganisation(request.organisation_id),
            ))?;

        if organisation.deactivated_at.is_some() {
            return Err(
                BusinessLogicError::OrganisationIsDeactivated(request.organisation_id).into(),
            );
        }

        let credential_schema = import_credential_schema(
            request.schema,
            organisation,
            &self.config,
            &*self.credential_schema_repository,
            &*self.formatter_provider,
            &*self.revocation_method_provider,
        )
        .await?;

        log_history_event_credential_schema(
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

        throw_if_org_relation_not_matching_session(
            credential_schema.organisation.as_ref(),
            &*self.session_provider,
        )?;

        log_history_event_credential_schema(
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
