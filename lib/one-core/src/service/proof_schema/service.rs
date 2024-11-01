use anyhow::Context;
use futures::future;
use shared_types::{CredentialSchemaId, ProofSchemaId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateProofSchemaRequestDTO, GetProofSchemaListResponseDTO, GetProofSchemaQueryDTO,
    GetProofSchemaResponseDTO, ImportProofSchemaInputSchemaDTO, ImportProofSchemaRequestDTO,
    ImportProofSchemaResponseDTO, ProofSchemaShareResponseDTO,
};
use super::mapper::{proof_input_from_import_request, proof_schema_from_create_request};
use super::validator::{
    extract_claims_from_credential_schema, proof_schema_name_already_exists,
    validate_create_request, validate_imported_proof_schema,
};
use super::ProofSchemaService;
use crate::common_mapper::list_response_into;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, GetCredentialSchemaQuery,
};
use crate::model::history::{HistoryAction, HistoryEntityType};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::proof_schema::{
    ProofInputSchema, ProofInputSchemaRelations, ProofSchema, ProofSchemaClaimRelations,
    ProofSchemaRelations,
};
use crate::provider::exchange_protocol::error::ExchangeProtocolError;
use crate::repository::error::DataLayerError;
use crate::service::credential_schema::dto::{
    CredentialSchemaFilterValue, ImportCredentialSchemaRequestSchemaDTO,
};
use crate::service::credential_schema::import::import_credential_schema;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, ServiceError, ValidationError,
};
use crate::service::proof_schema::mapper::convert_proof_schema_to_response;
use crate::service::proof_schema::validator::{
    throw_if_proof_schema_contains_physical_card_schema_with_other_schemas,
    throw_if_validity_constraint_missing_for_lvvc,
};
use crate::util::history::{history_event, log_history_event_proof_schema};

impl ProofSchemaService {
    /// Returns details of a proof schema
    ///
    /// # Arguments
    ///
    /// * `id` - Proof schema uuid
    pub async fn get_proof_schema(
        &self,
        id: &ProofSchemaId,
    ) -> Result<GetProofSchemaResponseDTO, ServiceError> {
        let result = self
            .proof_schema_repository
            .get_proof_schema(
                id,
                &ProofSchemaRelations {
                    organisation: Some(OrganisationRelations::default()),
                    proof_inputs: Some(ProofInputSchemaRelations {
                        claim_schemas: Some(ProofSchemaClaimRelations::default()),
                        credential_schema: Some(CredentialSchemaRelations {
                            claim_schemas: Some(ClaimSchemaRelations::default()),
                            ..Default::default()
                        }),
                    }),
                },
            )
            .await?
            .ok_or(EntityNotFoundError::ProofSchema(*id))?;

        if result.deleted_at.is_some() {
            return Err(EntityNotFoundError::ProofSchema(*id).into());
        }

        convert_proof_schema_to_response(result, &self.config.datatype)
    }

    /// Returns list of proof schemas according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_proof_schema_list(
        &self,
        query: GetProofSchemaQueryDTO,
    ) -> Result<GetProofSchemaListResponseDTO, ServiceError> {
        let result = self
            .proof_schema_repository
            .get_proof_schema_list(query)
            .await?;
        Ok(list_response_into(result))
    }

    /// Creates a new proof schema
    ///
    /// # Arguments
    ///
    /// * `request` - data
    pub async fn create_proof_schema(
        &self,
        request: CreateProofSchemaRequestDTO,
    ) -> Result<ProofSchemaId, ServiceError> {
        validate_create_request(&request)?;

        proof_schema_name_already_exists(
            &*self.proof_schema_repository,
            &request.name,
            request.organisation_id,
        )
        .await?;

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?;

        let Some(organisation) = organisation else {
            return Err(BusinessLogicError::MissingOrganisation(request.organisation_id).into());
        };

        let credential_schema_ids: Vec<CredentialSchemaId> = request
            .proof_input_schemas
            .iter()
            .map(|proof_input_schema| proof_input_schema.credential_schema_id)
            .collect();

        let expected_credential_schemas = credential_schema_ids.len();
        let credential_schemas = self
            .credential_schema_repository
            .get_credential_schema_list(
                GetCredentialSchemaQuery {
                    pagination: Some(ListPagination {
                        page: 0,
                        page_size: expected_credential_schemas as u32,
                    }),
                    filtering: Some(
                        CredentialSchemaFilterValue::OrganisationId(request.organisation_id)
                            .condition()
                            & CredentialSchemaFilterValue::CredentialSchemaIds(
                                credential_schema_ids,
                            ),
                    ),
                    ..Default::default()
                },
                &CredentialSchemaRelations {
                    claim_schemas: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
            .values;

        if credential_schemas.len() != expected_credential_schemas {
            return Err(BusinessLogicError::MissingCredentialSchema.into());
        }

        throw_if_proof_schema_contains_physical_card_schema_with_other_schemas(
            &credential_schemas,
            &self.config,
        )?;
        throw_if_validity_constraint_missing_for_lvvc(&credential_schemas, &request)?;

        let claim_schemas = extract_claims_from_credential_schema(
            &request.proof_input_schemas,
            &credential_schemas,
            &*self.formatter_provider,
        )?;

        let now = OffsetDateTime::now_utc();
        let proof_schema = proof_schema_from_create_request(
            request,
            now,
            claim_schemas,
            credential_schemas,
            organisation.clone(),
            self.base_url.as_deref(),
        )?;

        let id = self
            .proof_schema_repository
            .create_proof_schema(proof_schema)
            .await?;

        let _ = self
            .history_repository
            .create_history(history_event(
                id,
                organisation.id,
                HistoryEntityType::ProofSchema,
                HistoryAction::Created,
            ))
            .await;

        Ok(id)
    }

    /// Removes a proof schema
    ///
    /// # Arguments
    ///
    /// * `request` - data
    pub async fn delete_proof_schema(&self, id: &ProofSchemaId) -> Result<(), ServiceError> {
        self.proof_schema_repository
            .get_proof_schema(id, &Default::default())
            .await?
            .ok_or(BusinessLogicError::MissingProofSchema {
                proof_schema_id: *id,
            })?;

        let now = OffsetDateTime::now_utc();
        self.proof_schema_repository
            .delete_proof_schema(id, now)
            .await
            .map_err(|error| match error {
                // proof schema not found or already deleted
                DataLayerError::RecordNotUpdated => BusinessLogicError::MissingProofSchema {
                    proof_schema_id: *id,
                }
                .into(),
                error => ServiceError::from(error),
            })
    }

    pub async fn share_proof_schema(
        &self,
        id: ProofSchemaId,
    ) -> Result<ProofSchemaShareResponseDTO, ServiceError> {
        let proof_schema = self
            .proof_schema_repository
            .get_proof_schema(
                &id,
                &ProofSchemaRelations {
                    organisation: Some(OrganisationRelations::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::ProofSchema(id))?;

        let Some(url) = proof_schema.imported_source_url.clone() else {
            return Err(ValidationError::ProofSchemaSharingNotSupported.into());
        };

        let _ = log_history_event_proof_schema(
            &*self.history_repository,
            &proof_schema,
            HistoryAction::Shared,
        )
        .await;

        Ok(ProofSchemaShareResponseDTO { url })
    }

    pub async fn import_proof_schema(
        &self,
        request: ImportProofSchemaRequestDTO,
    ) -> Result<ImportProofSchemaResponseDTO, ServiceError> {
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?
            .ok_or::<ServiceError>(
                BusinessLogicError::MissingOrganisation(request.organisation_id).into(),
            )?;

        let schema = request.schema;
        validate_imported_proof_schema(&schema, &self.config)?;

        proof_schema_name_already_exists(
            &*self.proof_schema_repository,
            &schema.name,
            request.organisation_id,
        )
        .await?;

        let now = OffsetDateTime::now_utc();
        let input_schemas =
            schema
                .proof_input_schemas
                .into_iter()
                .map(|request_input_schema| {
                    let organisation = organisation.clone();

                    async move {
                        // check if the credential schema already exists
                        let maybe_credential_schema = self
                            .credential_schema_repository
                            .get_by_schema_id_and_organisation(
                                &request_input_schema.credential_schema.schema_id,
                                request_input_schema.credential_schema.schema_type.to_owned().into(),
                                organisation.id,
                                &CredentialSchemaRelations {
                                    claim_schemas: Some(Default::default()),
                                    ..Default::default()
                                },
                            )
                            .await?;

                        let credential_schema =
                            // if not exists (or deleted) create new credential schema
                            if let Some(credential_schema) = maybe_credential_schema {
                                if credential_schema.deleted_at.is_some() {
                                    self.create_credential_schema_from_input_schema(&request_input_schema, &organisation).await
                                } else {
                                    Ok(credential_schema)
                                }
                            }
                               else {
                                self.create_credential_schema_from_input_schema(&request_input_schema, &organisation).await
                            }?;

                        proof_input_from_import_request(request_input_schema, credential_schema, &*self.formatter_provider)
                    }
                });

        let input_schemas: Vec<ProofInputSchema> = future::try_join_all(input_schemas).await?;

        let proof_schema = ProofSchema {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            deleted_at: None,
            name: schema.name,
            expire_duration: schema.expire_duration,
            organisation: Some(organisation.clone()),
            input_schemas: Some(input_schemas),
            imported_source_url: Some(schema.imported_source_url),
        };

        let proof_schema_id = self
            .proof_schema_repository
            .create_proof_schema(proof_schema)
            .await?;

        let _ = self
            .history_repository
            .create_history(history_event(
                proof_schema_id,
                organisation.id,
                HistoryEntityType::ProofSchema,
                HistoryAction::Imported,
            ))
            .await;

        Ok(ImportProofSchemaResponseDTO {
            id: proof_schema_id,
        })
    }

    async fn create_credential_schema_from_input_schema(
        &self,
        request_input_schema: &ImportProofSchemaInputSchemaDTO,
        organisation: &Organisation,
    ) -> Result<CredentialSchema, ServiceError> {
        let credential_schema_import_request: ImportCredentialSchemaRequestSchemaDTO = self
            .client
            .get(&request_input_schema.credential_schema.imported_source_url)
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?
            .json()
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)?;

        let credential_schema = import_credential_schema(
            credential_schema_import_request,
            organisation.to_owned(),
            &self.config,
            &*self.credential_schema_repository,
            &*self.formatter_provider,
            &*self.revocation_method_provider,
        )
        .await?;

        let _ = self
            .history_repository
            .create_history(history_event(
                credential_schema.id,
                organisation.id,
                HistoryEntityType::CredentialSchema,
                HistoryAction::Created,
            ))
            .await;

        Ok(credential_schema)
    }
}
