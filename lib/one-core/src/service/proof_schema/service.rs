use std::collections::HashSet;

use futures::future;
use shared_types::{CredentialSchemaId, ProofSchemaId};
use uuid::Uuid;

use super::ProofSchemaService;
use super::dto::{
    CreateProofSchemaRequestDTO, GetProofSchemaListResponseDTO, GetProofSchemaResponseDTO,
    ImportProofSchemaRequestDTO, ImportProofSchemaResponseDTO, ProofSchemaFilterParamsDTO,
    ProofSchemaShareResponseDTO,
};
use super::error::ProofSchemaServiceError;
use super::mapper::{
    convert_proof_schema_to_response, proof_input_from_import_request,
    proof_schema_from_create_request,
};
use super::validator::{
    extract_claims_from_credential_schema, proof_schema_name_already_exists,
    throw_if_invalid_credential_combination, validate_create_request,
    validate_imported_proof_schema,
};
use crate::CoreConfig;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::list_response_into;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaListQuery};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::model::organisation::Organisation;
use crate::model::proof_schema::{ProofInputSchema, ProofSchema, SortableProofSchemaColumn};
use crate::proto::credential_schema::dto::{
    ImportCredentialSchemaRequestDTO, ImportCredentialSchemaV2RequestDTO,
};
use crate::proto::credential_schema::importer::CredentialSchemaImporter;
use crate::proto::credential_schema::parser::CredentialSchemaImportParser;
use crate::proto::http_client::HttpClient;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::error::DataLayerError;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::service::common_dto::ListQueryDTO;
use crate::service::credential_schema::dto::{
    CredentialSchemaFilterValue, ImportCredentialSchemaRequestSchemaDTO,
    ImportCredentialSchemaV2RequestSchemaDTO,
};
use crate::service::credential_schema::validator::validate_key_storage_security_supported;
use crate::service::proof_schema::dto::ImportProofSchemaDTO;
use crate::validator::ecosystem::validate_ecosystem_selection_allow_not_set;
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
        .await?;

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
            .await
            .error_while("getting credential schemas")?
            .values;

        if credential_schemas.len() != expected_credential_schemas {
            return Err(ProofSchemaServiceError::MissingCredentialSchema);
        }

        for credential_schema in &credential_schemas {
            validate_key_storage_security_supported(
                credential_schema.key_storage_security,
                &self.config,
            )
            .error_while("validating key storage security")?;
        }

        throw_if_invalid_credential_combination(&credential_schemas, &*self.formatter_provider)
            .await?;

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
                DataLayerError::RecordNotUpdated => ProofSchemaServiceError::NotFound(*id),
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

        let proof_schema_id = Uuid::new_v4().into();
        let imported_source_url = if self.config.global_settings.rehost_imported_schemas {
            let base_url = self.base_url.as_deref().ok_or_else(|| {
                ProofSchemaServiceError::MappingError(
                    "Missing core base_url, cannot rehost schema".to_string(),
                )
            })?;
            format!("{base_url}/ssi/proof-schema/v1/{proof_schema_id}")
        } else {
            request.schema.imported_source_url.to_owned()
        };

        let success_log = format!(
            "Imported proof schema `{}` ({proof_schema_id})",
            request.schema.name
        );
        create_imported_proof_schema(
            request.schema,
            proof_schema_id,
            &organisation,
            imported_source_url,
            self.proof_schema_repository.as_ref(),
            self.credential_schema_repository.as_ref(),
            self.client.as_ref(),
            self.credential_schema_import_parser.as_ref(),
            self.credential_schema_importer.as_ref(),
            &self.config,
        )
        .await?;
        tracing::info!(message = success_log);
        Ok(ImportProofSchemaResponseDTO {
            id: proof_schema_id,
        })
    }
}

pub(crate) async fn create_credential_schema_from_import_url(
    url: &str,
    organisation: Organisation,
    client: &dyn HttpClient,
    credential_schema_import_parser: &dyn CredentialSchemaImportParser,
    credential_schema_importer: &dyn CredentialSchemaImporter,
) -> Result<CredentialSchema, ProofSchemaServiceError> {
    let response = async { client.get(url).send().await?.error_for_status() }
        .await
        .error_while("fetching credential schema")?;

    let credential_schema = if is_v2_credential_schema_url(url) {
        let import_request: ImportCredentialSchemaV2RequestSchemaDTO =
            response.json().error_while("fetching credential schema")?;
        credential_schema_import_parser
            .parse_import_credential_schema_v2(ImportCredentialSchemaV2RequestDTO {
                organisation,
                schema: import_request.into(),
            })
            .error_while("parsing credential schema")?
    } else {
        let import_request: ImportCredentialSchemaRequestSchemaDTO =
            response.json().error_while("fetching credential schema")?;
        credential_schema_import_parser
            .parse_import_credential_schema(ImportCredentialSchemaRequestDTO {
                organisation,
                schema: import_request.into(),
            })
            .error_while("parsing credential schema")?
    };

    Ok(credential_schema_importer
        .import_credential_schema(credential_schema)
        .await
        .error_while("importing credential schema")?)
}

fn is_v2_credential_schema_url(url: &str) -> bool {
    url::Url::parse(url)
        .ok()
        .is_some_and(|u| u.path().contains("/ssi/schema/v2/"))
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn create_imported_proof_schema(
    schema: ImportProofSchemaDTO,
    id: ProofSchemaId,
    organisation: &Organisation,
    imported_source_url: String,
    proof_schema_repository: &dyn ProofSchemaRepository,
    credential_schema_repository: &dyn CredentialSchemaRepository,
    client: &dyn HttpClient,
    credential_schema_import_parser: &dyn CredentialSchemaImportParser,
    credential_schema_importer: &dyn CredentialSchemaImporter,
    config: &CoreConfig,
) -> Result<(), ProofSchemaServiceError> {
    validate_imported_proof_schema(&schema, config)?;

    proof_schema_name_already_exists(proof_schema_repository, &schema.name, organisation.id)
        .await?;

    let now = crate::clock::now_utc();
    let input_schemas = schema
        .proof_input_schemas
        .into_iter()
        .map(|request_input_schema| {
            async move {
                // check if the credential schema already exists
                let maybe_credential_schema = credential_schema_repository
                    .get_by_schema_id_and_organisation(
                        &request_input_schema.credential_schema.schema_id,
                        organisation.id,
                    )
                    .await
                    .error_while("getting credential schema")?;

                let credential_schema =
                    // if not exists (or deleted) create new credential schema
                    if let Some(credential_schema) = maybe_credential_schema
                        && credential_schema.deleted_at.is_none() {
                        credential_schema
                    } else {
                        create_credential_schema_from_import_url(
                            &request_input_schema.credential_schema.imported_source_url,
                            organisation.to_owned(),
                            client,
                            credential_schema_import_parser,
                            credential_schema_importer,
                        ).await?
                    };

                proof_input_from_import_request(request_input_schema, credential_schema).await
            }
        });

    let input_schemas: Vec<ProofInputSchema> = future::try_join_all(input_schemas).await?;

    let proof_schema = ProofSchema {
        ecosystem: None,
        id,
        created_date: now,
        last_modified: now,
        deleted_at: None,
        name: schema.name,
        expire_duration: schema.expire_duration,
        organisation: organisation.clone().into(),
        input_schemas: input_schemas.into(),
        imported_source_url: Some(imported_source_url),
    };
    proof_schema_repository
        .create_proof_schema(proof_schema)
        .await
        .error_while("creating proof schema")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_v2_credential_schema_url;

    #[test]
    fn v2_credential_schema_url_detection() {
        assert!(is_v2_credential_schema_url(
            "https://example.com/ssi/schema/v2/abcd"
        ));
        assert!(!is_v2_credential_schema_url(
            "https://example.com/ssi/schema/v1/abcd"
        ));
        assert!(!is_v2_credential_schema_url("not a url"));
    }
}
