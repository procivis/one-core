use std::collections::HashSet;

use anyhow::Context;
use futures::future;
use shared_types::{CredentialSchemaId, OrganisationId, ProofSchemaId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::ProofSchemaService;
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
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::list_response_into;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, GetCredentialSchemaQuery,
};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::proof_schema::{
    ProofInputSchema, ProofInputSchemaRelations, ProofSchema, ProofSchemaClaimRelations,
    ProofSchemaRelations,
};
use crate::proto::credential_schema::dto::ImportCredentialSchemaRequestDTO;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::repository::error::DataLayerError;
use crate::service::credential_schema::dto::{
    CredentialSchemaFilterValue, ImportCredentialSchemaRequestSchemaDTO,
};
use crate::service::credential_schema::validator::validate_key_storage_security_supported;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, ServiceError, ValidationError,
};
use crate::service::proof_schema::mapper::convert_proof_schema_to_response;
use crate::service::proof_schema::validator::{
    throw_if_invalid_credential_combination, throw_if_validity_constraint_missing_for_lvvc,
};
use crate::validator::{
    throw_if_org_not_matching_session, throw_if_org_relation_not_matching_session,
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
            .await
            .error_while("getting proof schema")?
            .ok_or(EntityNotFoundError::ProofSchema(*id))?;
        throw_if_org_relation_not_matching_session(
            result.organisation.as_ref(),
            &*self.session_provider,
        )?;

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
        organisation_id: &OrganisationId,
        query: GetProofSchemaQueryDTO,
    ) -> Result<GetProofSchemaListResponseDTO, ServiceError> {
        throw_if_org_not_matching_session(organisation_id, &*self.session_provider)?;
        let result = self
            .proof_schema_repository
            .get_proof_schema_list(query)
            .await
            .error_while("getting proof schemas")?;
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
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)?;
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
            .await
            .error_while("getting organisation")?;

        let Some(organisation) = organisation else {
            return Err(BusinessLogicError::MissingOrganisation(request.organisation_id).into());
        };

        if organisation.deactivated_at.is_some() {
            return Err(
                BusinessLogicError::OrganisationIsDeactivated(request.organisation_id).into(),
            );
        }

        let credential_schema_ids: Vec<CredentialSchemaId> = request
            .proof_input_schemas
            .iter()
            .map(|proof_input_schema| proof_input_schema.credential_schema_id)
            .collect();
        let deduplicated_schema_ids =
            HashSet::<&CredentialSchemaId>::from_iter(credential_schema_ids.iter());
        if credential_schema_ids.len() != deduplicated_schema_ids.len() {
            return Err(BusinessLogicError::DuplicateProofInputCredentialSchema.into());
        }
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
            .await
            .error_while("getting credential schemas")?
            .values;

        if credential_schemas.len() != expected_credential_schemas {
            return Err(BusinessLogicError::MissingCredentialSchema.into());
        }

        for credential_schema in &credential_schemas {
            validate_key_storage_security_supported(
                credential_schema.key_storage_security,
                &self.config,
            )?;
        }

        throw_if_invalid_credential_combination(&credential_schemas, &*self.formatter_provider)?;

        throw_if_validity_constraint_missing_for_lvvc(&credential_schemas, &request, &self.config)?;

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

        let success_log = format!(
            "Created proof schema `{}` ({})",
            proof_schema.name, proof_schema.id
        );
        let result = self
            .proof_schema_repository
            .create_proof_schema(proof_schema)
            .await
            .error_while("creating proof schema")?;
        tracing::info!(message = success_log);
        Ok(result)
    }

    /// Removes a proof schema
    ///
    /// # Arguments
    ///
    /// * `request` - data
    pub async fn delete_proof_schema(&self, id: &ProofSchemaId) -> Result<(), ServiceError> {
        let schema = self
            .proof_schema_repository
            .get_proof_schema(
                id,
                &ProofSchemaRelations {
                    organisation: Some(OrganisationRelations::default()),
                    proof_inputs: None,
                },
            )
            .await
            .error_while("getting proof schema")?
            .ok_or(BusinessLogicError::MissingProofSchema {
                proof_schema_id: *id,
            })?;
        throw_if_org_relation_not_matching_session(
            schema.organisation.as_ref(),
            &*self.session_provider,
        )?;

        let now = OffsetDateTime::now_utc();
        self.proof_schema_repository
            .delete_proof_schema(id, now)
            .await
            .map_err(|error| match error {
                // proof schema not found or already deleted
                DataLayerError::RecordNotUpdated => {
                    ServiceError::from(BusinessLogicError::MissingProofSchema {
                        proof_schema_id: *id,
                    })
                }
                error => error.error_while("deleting proof schema").into(),
            })?;
        tracing::info!("Deleted proof schema {}", id);
        Ok(())
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
            .await
            .error_while("getting proof schema")?
            .ok_or(EntityNotFoundError::ProofSchema(id))?;
        throw_if_org_relation_not_matching_session(
            proof_schema.organisation.as_ref(),
            &*self.session_provider,
        )?;

        let Some(url) = proof_schema.imported_source_url else {
            return Err(ValidationError::ProofSchemaSharingNotSupported.into());
        };

        Ok(ProofSchemaShareResponseDTO { url })
    }

    pub async fn import_proof_schema(
        &self,
        request: ImportProofSchemaRequestDTO,
    ) -> Result<ImportProofSchemaResponseDTO, ServiceError> {
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)?;
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await
            .error_while("getting organisation")?
            .ok_or::<ServiceError>(
                BusinessLogicError::MissingOrganisation(request.organisation_id).into(),
            )?;

        if organisation.deactivated_at.is_some() {
            return Err(
                BusinessLogicError::OrganisationIsDeactivated(request.organisation_id).into(),
            );
        }

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
                                organisation.id,
                                &CredentialSchemaRelations {
                                    claim_schemas: Some(Default::default()),
                                    ..Default::default()
                                },
                            )
                            .await .error_while("getting credential schema")?;

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

                        proof_input_from_import_request(request_input_schema, credential_schema)
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

        let success_log = format!(
            "Imported proof schema `{}` ({})",
            proof_schema.name, proof_schema.id
        );
        let proof_schema_id = self
            .proof_schema_repository
            .create_proof_schema(proof_schema)
            .await
            .error_while("creating proof schema")?;
        tracing::info!(message = success_log);
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
            .map_err(VerificationProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(VerificationProtocolError::Transport)?
            .json()
            .context("parsing error")
            .map_err(VerificationProtocolError::Transport)?;

        let credential_schema = self
            .credential_schema_import_parser
            .parse_import_credential_schema(ImportCredentialSchemaRequestDTO {
                organisation: organisation.to_owned(),
                schema: credential_schema_import_request.into(),
            })?;

        let credential_schema = self
            .credential_schema_importer
            .import_credential_schema(credential_schema)
            .await?;

        Ok(credential_schema)
    }
}
