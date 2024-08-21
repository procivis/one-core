use std::collections::HashSet;

use futures::future;
use shared_types::{CredentialSchemaId, ProofSchemaId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateProofSchemaRequestDTO, GetProofSchemaListResponseDTO, GetProofSchemaQueryDTO,
    GetProofSchemaResponseDTO, ImportProofSchemaInputSchemaDTO, ImportProofSchemaRequestDTO,
    ImportProofSchemaResponseDTO, ProofSchemaShareResponseDTO,
};
use super::mapper::{
    credential_schema_from_proof_input_schema, proof_input_from_import_request,
    proof_schema_created_history_event, proof_schema_from_create_request,
    proof_schema_history_event,
};
use super::validator::{
    extract_claims_from_credential_schema, proof_schema_name_already_exists,
    validate_create_request, validate_imported_proof_schema,
};
use super::ProofSchemaService;
use crate::common_mapper::list_response_into;
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, GetCredentialSchemaQuery,
    UpdateCredentialSchemaRequest,
};
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::proof_schema::{
    ProofInputSchema, ProofInputSchemaRelations, ProofSchema, ProofSchemaClaimRelations,
    ProofSchemaRelations,
};
use crate::repository::error::DataLayerError;
use crate::service::common_mapper::regenerate_credential_schema_uuids;
use crate::service::credential_schema::dto::CredentialSchemaFilterValue;
use crate::service::error::{BusinessLogicError, EntityNotFoundError, ServiceError};
use crate::service::proof_schema::mapper::convert_proof_schema_to_response;
use crate::service::proof_schema::validator::{
    throw_if_proof_schema_contains_physical_card_schema_with_other_schemas,
    throw_if_validity_constraint_missing_for_lvvc,
};

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
                    proof_inputs: Some(ProofInputSchemaRelations {
                        claim_schemas: Some(ProofSchemaClaimRelations::default()),
                        credential_schema: Some(CredentialSchemaRelations {}),
                    }),
                },
            )
            .await?
            .ok_or(EntityNotFoundError::ProofSchema(*id))?;

        if result.deleted_at.is_some() {
            return Err(EntityNotFoundError::ProofSchema(*id).into());
        }

        convert_proof_schema_to_response(result, &self.config.datatype).await
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
            .get_credential_schema_list(GetCredentialSchemaQuery {
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: expected_credential_schemas as u32,
                }),
                filtering: Some(
                    CredentialSchemaFilterValue::OrganisationId(request.organisation_id)
                        .condition()
                        & CredentialSchemaFilterValue::CredentialSchemaIds(credential_schema_ids),
                ),
                ..Default::default()
            })
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
        )
        .await?;

        let now = OffsetDateTime::now_utc();
        let proof_schema = proof_schema_from_create_request(
            request,
            now,
            claim_schemas,
            credential_schemas,
            organisation.clone(),
        )?;

        let id = self
            .proof_schema_repository
            .create_proof_schema(proof_schema)
            .await?;

        let _ = self
            .history_repository
            .create_history(proof_schema_created_history_event(id, organisation))
            .await;

        Ok(id)
    }

    /// Removes a proof schema
    ///
    /// # Arguments
    ///
    /// * `request` - data
    pub async fn delete_proof_schema(&self, id: &ProofSchemaId) -> Result<(), ServiceError> {
        let proof_schema = self
            .proof_schema_repository
            .get_proof_schema(
                id,
                &ProofSchemaRelations {
                    ..Default::default()
                },
            )
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
            })?;

        let _ = self
            .history_repository
            .create_history(proof_schema_history_event(
                proof_schema.id,
                Some(Organisation {
                    id: *proof_schema.organisation.id(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                }),
                HistoryAction::Deleted,
            ))
            .await;

        Ok(())
    }

    pub async fn share_proof_schema(
        &self,
        id: ProofSchemaId,
    ) -> Result<ProofSchemaShareResponseDTO, ServiceError> {
        let base_url = self.base_url.as_ref().ok_or_else(|| {
            ServiceError::Other("Missing core_base_url for sharing proof schema".to_string())
        })?;

        let proof_schema = self
            .proof_schema_repository
            .get_proof_schema(
                &id,
                &ProofSchemaRelations {
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::ProofSchema(id))?;

        let _ = self
            .history_repository
            .create_history(proof_schema_history_event(
                proof_schema.id,
                Some(Organisation {
                    id: *proof_schema.organisation.id(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                }),
                HistoryAction::Shared,
            ))
            .await;

        Ok(ProofSchemaShareResponseDTO {
            url: format!("{base_url}/ssi/proof-schema/v1/{id}"),
        })
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
                            )
                            .await?;

                        let credential_schema =
                        // if already exists update only the missing claim schemas
                            if let Some(credential_schema) = maybe_credential_schema {
                                if credential_schema.deleted_at.is_none() {
                                    self.update_existing_credential_schema(credential_schema, &request_input_schema, &organisation, now).await
                                }
                                else {
                                    self.create_credential_schema_from_input_schema(&request_input_schema, &organisation, now).await
                                }
                            }
                             // if not exists create new credential schema deriving the possible claims from the input_schema
                            else {
                                self.create_credential_schema_from_input_schema(&request_input_schema, &organisation, now).await
                            }?;

                        let input_schema = proof_input_from_import_request(
                            &request_input_schema,
                            credential_schema.to_owned()
                        ).await?;

                        Ok::<_, ServiceError>(ProofInputSchema {
                            claim_schemas: input_schema.claim_schemas,
                            credential_schema: Some(credential_schema),
                            validity_constraint: input_schema.validity_constraint,
                        })
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
            organisation: organisation.clone().into(),
            input_schemas: Some(input_schemas),
        };

        let proof_schema_id = self
            .proof_schema_repository
            .create_proof_schema(proof_schema)
            .await?;

        let _ = self
            .history_repository
            .create_history(proof_schema_history_event(
                proof_schema_id,
                Some(organisation),
                HistoryAction::Imported,
            ))
            .await;

        Ok(ImportProofSchemaResponseDTO {
            id: proof_schema_id,
        })
    }

    async fn update_existing_credential_schema(
        &self,
        credential_schema: CredentialSchema,
        request_input_schema: &ImportProofSchemaInputSchemaDTO,
        organisation: &Organisation,
        now: OffsetDateTime,
    ) -> Result<CredentialSchema, ServiceError> {
        let keys: HashSet<_> = credential_schema
            .claim_schemas
            .get()
            .await?
            .iter()
            .map(|x| x.schema.key.to_owned())
            .collect();

        let missing_claim_schemas: Vec<_> = credential_schema_from_proof_input_schema(
            request_input_schema,
            organisation.clone(),
            now,
        )
        .claim_schemas
        .get()
        .await?
        .into_iter()
        .filter(|s| !keys.contains(&s.schema.key))
        .collect();

        if !missing_claim_schemas.is_empty() {
            self.credential_schema_repository
                .update_credential_schema(UpdateCredentialSchemaRequest {
                    id: credential_schema.id,
                    claim_schemas: Some(missing_claim_schemas),
                    revocation_method: None,
                    format: None,
                })
                .await?;

            self.credential_schema_repository
                .get_credential_schema(&credential_schema.id)
                .await?
                .ok_or_else(|| {
                    ServiceError::Other(format!(
                        "Failed fetching updated credential schema {}",
                        credential_schema.id
                    ))
                })
        } else {
            Ok(credential_schema)
        }
    }

    async fn create_credential_schema_from_input_schema(
        &self,
        request_input_schema: &ImportProofSchemaInputSchemaDTO,
        organisation: &Organisation,
        now: OffsetDateTime,
    ) -> Result<CredentialSchema, ServiceError> {
        let credential_schema = credential_schema_from_proof_input_schema(
            request_input_schema,
            organisation.clone(),
            now,
        );
        let credential_schema = regenerate_credential_schema_uuids(credential_schema).await?;

        self.credential_schema_repository
            .create_credential_schema(credential_schema.clone())
            .await?;

        let _ = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: now,
                action: HistoryAction::Created,
                entity_id: Some(credential_schema.id.into()),
                entity_type: HistoryEntityType::CredentialSchema,
                metadata: None,
                organisation: Some(organisation.clone()),
            })
            .await;

        Ok(credential_schema)
    }
}
