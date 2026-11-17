use std::collections::HashSet;

use shared_types::{CredentialSchemaId, ProofSchemaId};

use super::ProofSchemaService;
use super::dto::{
    CreateProofSchemaRequestDTO, ExportProofSchemaResponseDTO, GetProofSchemaListResponseDTO,
    GetProofSchemaResponseDTO, ImportProofSchemaRequestDTO, ImportProofSchemaResponseDTO,
    ProofSchemaFilterParamsDTO, ProofSchemaShareResponseDTO, UpdateProofSchemaRequestDTO,
};
use super::error::ProofSchemaServiceError;
use super::mapper::{
    convert_proof_schema_to_response, proof_schema_from_create_request,
    proof_schema_to_export_response,
};
use super::validator::{
    extract_claims_from_credential_schema, validate_create_request, validate_proof_schema_nesting,
};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::list_response_into;
use crate::model::credential_schema::CredentialSchemaListQuery;
use crate::model::list_filter::ListFilterValue;
use crate::model::proof_schema::{SortableProofSchemaColumn, UpdateProofSchema};
use crate::proto::proof_schema::validator::proof_schema_name_already_exists;
use crate::provider::credential_formatter::model::Features;
use crate::repository::error::DataLayerError;
use crate::service::common_dto::ListQueryDTO;
use crate::service::credential_schema::dto::CredentialSchemaFilterValue;
use crate::service::credential_schema::validator::validate_key_storage_security_supported;
use crate::validator::ecosystem::validate_ecosystem_selection_allow_not_set;
use crate::validator::proof_schema::{ProofInputFormatsError, resolve_proof_input_formats};
use crate::validator::throw_if_org_id_not_matching_session;

impl ProofSchemaService {
    /// Returns details of a proof schema
    ///
    /// # Arguments
    ///
    /// * `id` - Proof schema uuid
    pub async fn get_proof_schema(
        &self,
        id: &ProofSchemaId,
    ) -> Result<GetProofSchemaResponseDTO, ProofSchemaServiceError> {
        let result = self
            .proof_schema_repository
            .get_proof_schema(id)
            .await
            .error_while("getting proof schema")?;
        throw_if_org_id_not_matching_session(result.organisation.id_ref(), &*self.session_provider)
            .error_while("checking session")?;

        if result.deleted_at.is_some() {
            return Err(ProofSchemaServiceError::NotFound(*id));
        }

        convert_proof_schema_to_response(result, &self.config.datatype, &*self.formatter_provider)
            .await
    }

    /// Returns list of proof schemas according to query
    ///
    /// # Arguments
    ///
    /// * `filter_params` - query parameters
    pub async fn get_proof_schema_list(
        &self,
        filter_params: ListQueryDTO<SortableProofSchemaColumn, ProofSchemaFilterParamsDTO>,
    ) -> Result<GetProofSchemaListResponseDTO, ProofSchemaServiceError> {
        throw_if_org_id_not_matching_session(
            &filter_params.filter.organisation_id,
            &*self.session_provider,
        )
        .error_while("checking session")?;

        let result = self
            .proof_schema_repository
            .get_proof_schema_list(filter_params.into())
            .await
            .and_then(|list| list.require_count())
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
    ) -> Result<ProofSchemaId, ProofSchemaServiceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        validate_create_request(&request)?;

        proof_schema_name_already_exists(
            &*self.proof_schema_repository,
            &request.name,
            request.organisation_id,
        )
        .await
        .error_while("checking proof schema name")?;

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id)
            .await
            .error_while("getting organisation")?;

        if organisation.deactivated_at.is_some() {
            return Err(ProofSchemaServiceError::OrganisationIsDeactivated(
                request.organisation_id,
            ));
        }

        validate_ecosystem_selection_allow_not_set(
            request.ecosystem.as_ref(),
            &organisation,
            self.ecosystem_provider.as_ref(),
        )
        .error_while("validating ecosystem")?;

        let credential_schema_ids: Vec<CredentialSchemaId> = request
            .proof_input_schemas
            .iter()
            .map(|proof_input_schema| proof_input_schema.credential_schema_id)
            .collect();
        let deduplicated_schema_ids =
            HashSet::<&CredentialSchemaId>::from_iter(credential_schema_ids.iter());
        if credential_schema_ids.len() != deduplicated_schema_ids.len() {
            return Err(ProofSchemaServiceError::DuplicateProofInputCredentialSchema);
        }
        let expected_credential_schemas = credential_schema_ids.len();
        let credential_schemas = self
            .credential_schema_repository
            .get_credential_schema_list(CredentialSchemaListQuery {
                include_count: false,
                filtering: Some(
                    CredentialSchemaFilterValue::OrganisationId(request.organisation_id)
                        .condition()
                        & CredentialSchemaFilterValue::CredentialSchemaIds(credential_schema_ids),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting credential schemas")?
            .values;

        if credential_schemas.len() != expected_credential_schemas {
            return Err(ProofSchemaServiceError::MissingCredentialSchema);
        }

        for credential_schema in &credential_schemas {
            validate_key_storage_security_supported(
                credential_schema
                    .wallet_attestation
                    .key_storage_security_level,
                &self.config,
            )
            .error_while("validating key storage security")?;
        }

        let claim_schemas = extract_claims_from_credential_schema(
            &request.proof_input_schemas,
            &credential_schemas,
            &*self.formatter_provider,
        )
        .await?;

        let now = crate::clock::now_utc();
        let proof_schema = proof_schema_from_create_request(
            request,
            now,
            claim_schemas,
            credential_schemas,
            organisation.clone(),
            self.base_url.as_deref(),
        )
        .await?;

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
    pub async fn delete_proof_schema(
        &self,
        id: &ProofSchemaId,
    ) -> Result<(), ProofSchemaServiceError> {
        let schema = self
            .proof_schema_repository
            .get_proof_schema(id)
            .await
            .error_while("getting proof schema")?;
        throw_if_org_id_not_matching_session(schema.organisation.id_ref(), &*self.session_provider)
            .error_while("checking session")?;

        let now = crate::clock::now_utc();
        self.proof_schema_repository
            .delete_proof_schema(id, now)
            .await
            .map_err(|error| match error {
                // proof schema not found or already deleted
                DataLayerError::RecordNotUpdated(_) => ProofSchemaServiceError::NotFound(*id),
                error => error.error_while("deleting proof schema").into(),
            })?;
        tracing::info!("Deleted proof schema {}", id);
        Ok(())
    }

    pub async fn share_proof_schema(
        &self,
        id: ProofSchemaId,
    ) -> Result<ProofSchemaShareResponseDTO, ProofSchemaServiceError> {
        let proof_schema = self
            .proof_schema_repository
            .get_proof_schema(&id)
            .await
            .error_while("getting proof schema")?;
        throw_if_org_id_not_matching_session(
            proof_schema.organisation.id_ref(),
            &*self.session_provider,
        )
        .error_while("checking session")?;

        let Some(url) = proof_schema.imported_source_url else {
            return Err(ProofSchemaServiceError::SharingNotSupported);
        };

        Ok(ProofSchemaShareResponseDTO { url })
    }

    pub async fn export_proof_schema(
        &self,
        id: &ProofSchemaId,
    ) -> Result<ExportProofSchemaResponseDTO, ProofSchemaServiceError> {
        let result = self
            .proof_schema_repository
            .get_proof_schema(id)
            .await
            .error_while("getting proof schema")?;

        if result.deleted_at.is_some() {
            return Err(ProofSchemaServiceError::NotFound(*id));
        }

        proof_schema_to_export_response(result, &self.config).await
    }

    pub async fn import_proof_schema(
        &self,
        request: ImportProofSchemaRequestDTO,
    ) -> Result<ImportProofSchemaResponseDTO, ProofSchemaServiceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id)
            .await
            .error_while("getting organisation")?;

        if organisation.deactivated_at.is_some() {
            return Err(ProofSchemaServiceError::OrganisationIsDeactivated(
                request.organisation_id,
            ));
        }

        let proof_schema_id = ProofSchemaId::new();
        let imported_source_url = request.schema.imported_source_url.to_owned();

        let success_log = format!(
            "Imported proof schema `{}` ({proof_schema_id})",
            request.schema.name
        );
        self.proof_schema_importer
            .import_proof_schema(
                request.schema,
                proof_schema_id,
                &organisation,
                imported_source_url,
            )
            .await
            .error_while("importing proof schema")?;
        tracing::info!(message = success_log);
        Ok(ImportProofSchemaResponseDTO {
            id: proof_schema_id,
        })
    }

    pub async fn update_proof_schema(
        &self,
        id: ProofSchemaId,
        request: UpdateProofSchemaRequestDTO,
    ) -> Result<(), ProofSchemaServiceError> {
        let schema = self
            .proof_schema_repository
            .get_proof_schema(&id)
            .await
            .error_while("getting proof schema")?;

        throw_if_org_id_not_matching_session(schema.organisation.id_ref(), &*self.session_provider)
            .error_while("checking session")?;

        let mut update = UpdateProofSchema::default();
        if let Some(expire_duration) = request.expire_duration {
            update.expire_duration = Some(expire_duration);
        }

        if let Some(proof_input_schemas) = request.proof_input_schemas {
            let mut updated_schemas = schema.input_schemas.as_ref().await?.to_owned();
            for proof_input_schema in proof_input_schemas {
                let input_schema = updated_schemas
                    .iter_mut()
                    .find(|is| proof_input_schema.credential_schema_id == is.credential_schema.id())
                    .ok_or(ProofSchemaServiceError::MissingProofInputSchemas)?;

                // formats can only be added, not removed
                if !input_schema
                    .formats
                    .iter()
                    .all(|previous_format| proof_input_schema.formats.contains(previous_format))
                {
                    return Err(ProofInputFormatsError::MissingFormats
                        .error_while("checking formats")
                        .into());
                }

                let mut formatters = vec![];
                for format in &proof_input_schema.formats {
                    let formatter = self.formatter_provider.get_credential_formatter(format)?;
                    if proof_input_schema.formats.len() > 1
                        && !formatter
                            .get_capabilities()
                            .features
                            .contains(&Features::SupportsCombinedPresentation)
                    {
                        return Err(ProofSchemaServiceError::InvalidCredentialCombination {
                            credential_format: format.to_string(),
                        });
                    }
                    formatters.push(formatter);
                }

                let input_claim_schemas = input_schema.claim_schemas.as_ref().await?;
                for proof_claim in &input_claim_schemas {
                    for formatter in &formatters {
                        validate_proof_schema_nesting(&proof_claim.schema, &**formatter)?;
                    }
                }

                let credential_schema = input_schema.credential_schema.as_ref().await?;
                input_schema.formats = resolve_proof_input_formats(
                    Some(proof_input_schema.formats),
                    &credential_schema,
                )
                .await
                .error_while("resolving proof input formats")?;
            }

            update.input_schemas = Some(updated_schemas.into());
        }

        self.proof_schema_repository
            .update_proof_schema(&id, update)
            .await
            .error_while("updating proof schema")?;

        tracing::info!("Proof schema {id} updated");
        Ok(())
    }
}
