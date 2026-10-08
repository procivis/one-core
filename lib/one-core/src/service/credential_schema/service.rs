use std::collections::HashMap;

use indexmap::IndexMap;
use shared_types::{CredentialFormat, CredentialSchemaId, OrganisationId};
use uuid::Uuid;

use super::CredentialSchemaService;
use super::dto::{
    CreateCredentialSchemaRequestDTO, CreateCredentialSchemaV2RequestDTO,
    CredentialSchemaDetailResponseDTO, CredentialSchemaDetailV2ResponseDTO,
    CredentialSchemaFilterParamsDTO, CredentialSchemaFormatRequestDTO,
    CredentialSchemaListIncludeEntityTypeEnum, CredentialSchemaListItemResponseDTO,
    CredentialSchemaListItemV2ResponseDTO, CredentialSchemaShareResponseDTO,
    CredentialSchemaV2FilterParamsDTO, CredentialSchemaWalletAttestationDTO,
    GetCredentialSchemaListResponseDTO, GetCredentialSchemaListV2ResponseDTO,
    ImportCredentialSchemaRequestDTO, ImportCredentialSchemaV2RequestDTO,
};
use super::error::CredentialSchemaServiceError;
use super::mapper::{
    add_metadata_claims_and_mappings, build_format_with_claim_mappings,
    from_create_v2_request_with_id, map_v1_mdoc_create_claims_to_v2,
    schema_to_detail_v1_response_dto, schema_to_detail_v2_response_dto,
    to_credential_schema_list_response, to_credential_schema_list_v2_response,
    unnest_claim_schemas,
};
use super::validator::{
    UniquenessCheckResult, validate_claim_mappings_for_format,
    validate_revocation_method_is_compatible_with_suspension,
};
use crate::config::core_config::FormatType;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::credential_schema_claim::{
    backfill_default_translations, from_request_claim_schema,
};
use crate::model::common::GetListResponse;
use crate::model::credential_schema::SortableCredentialSchemaColumn;
use crate::model::organisation::Organisation;
use crate::provider::ProviderExt;
use crate::provider::revocation::model::Operation;
use crate::repository::error::DataLayerError;
use crate::service::common_dto::ListQueryDTO;
use crate::util::logging::quoted_opt_provider;
use crate::validator::ecosystem::validate_ecosystem_selection_allow_not_set;
use crate::validator::throw_if_org_id_not_matching_session;

impl CredentialSchemaService {
    /// Creates a credential schema according to request
    ///
    /// internally translating to v2 request
    pub async fn create_credential_schema(
        &self,
        mut request: CreateCredentialSchemaRequestDTO,
    ) -> Result<CredentialSchemaId, CredentialSchemaServiceError> {
        let format_type = self
            .config
            .format
            .get_type(&request.format)
            .error_while("parsing format")?;

        let claims = match format_type {
            FormatType::Mdoc => map_v1_mdoc_create_claims_to_v2(
                request.claims,
                self.config.as_ref(),
                &request.format,
                &mut request.layout_properties,
            )?,
            _ => request.claims,
        };

        let (allow_revocation, method) = match request.revocation_method {
            None => (Some(false), None),
            Some(revocation_method_id) => {
                let formatter = self
                    .formatter_provider
                    .get_credential_formatter(&request.format)?;

                if formatter
                    .revocation_method_id()
                    .is_none_or(|formatter_method_id| formatter_method_id != &revocation_method_id)
                {
                    return Err(CredentialSchemaServiceError::RevocationMethodNotCompatibleWithSelectedFormat);
                }

                let method = self
                    .revocation_method_provider
                    .get_revocation_method(&revocation_method_id)?;
                method.ensure_enabled()?;

                (
                    Some(
                        method
                            .get_capabilities()
                            .operations
                            .contains(&Operation::Revoke),
                    ),
                    Some(method),
                )
            }
        };
        validate_revocation_method_is_compatible_with_suspension(
            request.allow_suspension,
            method.as_ref().map(|m| m.as_ref()),
        )?;

        let request_v2 = CreateCredentialSchemaV2RequestDTO {
            name: request.name,
            formats: vec![CredentialSchemaFormatRequestDTO {
                format: request.format,
                ecosystem_schema_id: request.schema_id,
            }],
            organisation_id: request.organisation_id,
            claims,
            wallet_attestation: Some(CredentialSchemaWalletAttestationDTO {
                require_instance_attestation: request.requires_wallet_instance_attestation,
                key_storage_security_level: request.key_storage_security,
                preferred_key_storage_attestation_lifetime: None,
                preferred_instance_attestation_lifetime: None,
            }),
            layout_properties: request.layout_properties,
            allow_suspension: request.allow_suspension,
            allow_revocation,
            batch_size: None,
            transaction_code: request.transaction_code,
            translations: None,
            embedded_disclosure_policy: None,
            expiration: None,
            ecosystem: request.ecosystem,
        };

        let id = self
            .create_credential_schema_v2(request_v2)
            .await
            .error_while("creating credential schema (v2 translated)")?;

        Ok(id)
    }

    pub async fn create_credential_schema_v2(
        &self,
        request: CreateCredentialSchemaV2RequestDTO,
    ) -> Result<CredentialSchemaId, CredentialSchemaServiceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;

        let core_base_url = self.core_base_url.as_ref().ok_or_else(|| {
            CredentialSchemaServiceError::MappingError("Missing core base_url".to_string())
        })?;

        let ecosystem_schema_ids = request
            .formats
            .iter()
            .flat_map(|format| format.ecosystem_schema_id.clone())
            .collect();

        super::validator::validate_create_v2_request(
            &request,
            &self.config,
            &*self.formatter_provider,
        )?;

        super::validator::check_claims_presence_in_layout_properties(
            request.layout_properties.as_ref(),
            &request.claims,
        )?;
        super::validator::check_background_properties(request.layout_properties.as_ref())?;
        super::validator::check_logo_properties(request.layout_properties.as_ref())?;
        super::validator::validate_key_storage_security_supported(
            request
                .wallet_attestation
                .as_ref()
                .and_then(|wallet_attestation| wallet_attestation.key_storage_security_level),
            &self.config,
        )?;

        self.validate_credential_schema_already_exists(
            &request.name,
            ecosystem_schema_ids,
            request.organisation_id,
        )
        .await?;

        let organisation = self.get_organisation(request.organisation_id).await?;
        validate_ecosystem_selection_allow_not_set(
            request.ecosystem.as_ref(),
            &organisation,
            self.ecosystem_provider.as_ref(),
        )
        .error_while("validating ecosystem")?;

        let credential_schema_id = CredentialSchemaId::from(Uuid::new_v4());
        let now = crate::clock::now_utc();

        let mut formats = Vec::with_capacity(request.formats.len());
        let mut default_namespaces = HashMap::new();
        for format in &request.formats {
            formats.push(&format.format);
            let format_type = self
                .config
                .format
                .get_type(&format.format)
                .error_while("getting format type")?;

            if format_type == FormatType::Mdoc {
                let formatter = self
                    .formatter_provider
                    .get_credential_formatter(&format.format)?;
                let schema_id = formatter
                    .credential_schema_id(
                        credential_schema_id,
                        organisation.id,
                        format.ecosystem_schema_id.as_deref(),
                        core_base_url,
                        &format.format,
                    )
                    .error_while("creating schemaId")?;
                default_namespaces.insert(&format.format, schema_id);
            }
        }

        let flat_claims =
            unnest_claim_schemas(request.claims.clone(), &formats, &default_namespaces)?;
        validate_claim_mappings_for_format(
            &flat_claims,
            &request.formats,
            &*self.formatter_provider,
        )?;

        // Use indexmap because the order of the claims is relevant when inserting into the DB.
        let mut key_to_claim_schemas_and_mappings = flat_claims
            .into_iter()
            .map(|claim_schema_request| {
                let claim_schema = from_request_claim_schema(now, &claim_schema_request);
                (
                    claim_schema.key.clone(),
                    (
                        claim_schema,
                        claim_schema_request.mappings.unwrap_or_default(),
                    ),
                )
            })
            .collect::<IndexMap<_, _>>();

        let mut resolved_formats = vec![];
        for format_req in &request.formats {
            let formatter = self
                .formatter_provider
                .get_credential_formatter(&format_req.format)?;

            let schema_id = formatter
                .credential_schema_id(
                    credential_schema_id,
                    organisation.id,
                    format_req.ecosystem_schema_id.as_deref(),
                    core_base_url,
                    &format_req.format,
                )
                .error_while("creating schemaId")?;

            add_metadata_claims_and_mappings(
                &format_req.format,
                formatter.as_ref(),
                now,
                &mut key_to_claim_schemas_and_mappings,
            );

            let schema_format = build_format_with_claim_mappings(
                credential_schema_id,
                format_req.format.clone(),
                schema_id,
                now,
                &key_to_claim_schemas_and_mappings,
            )?;
            resolved_formats.push(schema_format);
        }
        let resolved_format_types = resolved_formats
            .iter()
            .map(|f| f.format.clone())
            .collect::<Vec<_>>();

        let imported_source_url = format!("{core_base_url}/ssi/schema/v2/{credential_schema_id}");
        let credential_schema = from_create_v2_request_with_id(
            credential_schema_id,
            request,
            organisation,
            now,
            resolved_formats,
            key_to_claim_schemas_and_mappings
                .into_values()
                .map(|(cs, _)| cs)
                .collect(),
            imported_source_url,
            &self.config.global_settings.default_language,
            self.core_base_url.as_ref(),
        )?;

        let credential_schema = backfill_default_translations(
            credential_schema,
            &self.config.global_settings.default_language,
        )
        .await
        .error_while("backfilling default translations")?;

        let success_log = format!(
            "Created credential schema v2 `{}` ({credential_schema_id}): formats `{:?}`: key storage security {}",
            credential_schema.name,
            resolved_format_types,
            quoted_opt_provider(
                &credential_schema
                    .wallet_attestation
                    .key_storage_security_level
            )
        );

        let schema_id = self
            .credential_schema_repository
            .create_credential_schema(credential_schema)
            .await
            .error_while("creating credential schema")?;

        tracing::info!(message = success_log);
        Ok(schema_id)
    }

    async fn get_organisation(
        &self,
        organisation_id: OrganisationId,
    ) -> Result<Organisation, CredentialSchemaServiceError> {
        let organisation = self
            .organisation_repository
            .get_organisation(&organisation_id)
            .await
            .error_while("getting organisation")?;

        if organisation.deactivated_at.is_some() {
            return Err(CredentialSchemaServiceError::OrganisationIsDeactivated(
                organisation_id,
            ));
        }
        Ok(organisation)
    }

    async fn validate_credential_schema_already_exists(
        &self,
        name: &str,
        ecosystem_schema_ids: Vec<String>,
        organisation_id: OrganisationId,
    ) -> Result<(), CredentialSchemaServiceError> {
        match super::validator::credential_schema_already_exists(
            &*self.credential_schema_repository,
            name,
            ecosystem_schema_ids,
            organisation_id,
        )
        .await?
        {
            UniquenessCheckResult::SchemaIdConflict | UniquenessCheckResult::NameConflict => {
                Err(CredentialSchemaServiceError::AlreadyExists)
            }
            UniquenessCheckResult::Ok => Ok(()),
        }
    }

    /// Deletes a credential schema
    ///
    /// # Arguments
    ///
    /// * `CredentialSchemaId` - Id of an existing credential schema
    pub async fn delete_credential_schema(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<(), CredentialSchemaServiceError> {
        let credential_schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?;

        throw_if_org_id_not_matching_session(
            credential_schema.organisation.id_ref(),
            &*self.session_provider,
        )
        .error_while("checking session")?;

        self.credential_schema_repository
            .delete_credential_schema(&credential_schema)
            .await
            .map_err(|error| match error {
                DataLayerError::RecordNotUpdated(_) => {
                    CredentialSchemaServiceError::NotFound(*credential_schema_id)
                }
                error => error.error_while("deleting credential schema").into(),
            })?;

        tracing::info!(
            "Deleted credential schema `{}` ({})",
            credential_schema.name,
            credential_schema.id
        );
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
    ) -> Result<CredentialSchemaDetailResponseDTO, CredentialSchemaServiceError> {
        let schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?;

        throw_if_org_id_not_matching_session(schema.organisation.id_ref(), &*self.session_provider)
            .error_while("checking session")?;

        if schema.deleted_at.is_some() {
            return Err(CredentialSchemaServiceError::NotFound(
                *credential_schema_id,
            ));
        }

        schema_to_detail_v1_response_dto(schema, &self.config, &*self.formatter_provider).await
    }

    pub async fn get_credential_schema_v2(
        &self,
        credential_schema_id: &CredentialSchemaId,
        format: Option<&CredentialFormat>,
    ) -> Result<CredentialSchemaDetailV2ResponseDTO, CredentialSchemaServiceError> {
        let schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?;

        throw_if_org_id_not_matching_session(schema.organisation.id_ref(), &*self.session_provider)
            .error_while("checking session")?;

        if schema.deleted_at.is_some() {
            return Err(CredentialSchemaServiceError::NotFound(
                *credential_schema_id,
            ));
        }
        if let Some(format) = format
            && !schema
                .formats
                .as_ref()
                .await?
                .iter()
                .any(|f| f.format == *format)
        {
            return Err(CredentialSchemaServiceError::NotFound(
                *credential_schema_id,
            ));
        }

        schema_to_detail_v2_response_dto(schema, format, &self.config).await
    }

    /// Returns list of credential schemas according to query
    ///
    /// # Arguments
    ///
    /// * `filter_params` - query parameters
    pub async fn get_credential_schema_list(
        &self,
        filter_params: ListQueryDTO<
            SortableCredentialSchemaColumn,
            CredentialSchemaFilterParamsDTO,
            CredentialSchemaListIncludeEntityTypeEnum,
        >,
    ) -> Result<GetCredentialSchemaListResponseDTO, CredentialSchemaServiceError> {
        throw_if_org_id_not_matching_session(
            &filter_params.filter.organisation_id,
            &*self.session_provider,
        )
        .error_while("checking session")?;

        let include_translations = filter_params
            .include
            .as_ref()
            .is_some_and(|i| i.contains(&CredentialSchemaListIncludeEntityTypeEnum::Translations));
        let result = self
            .credential_schema_repository
            .get_credential_schema_list(filter_params.into())
            .await
            .and_then(|list| list.require_count())
            .error_while("getting credential schemas")?;

        let mut items: Vec<CredentialSchemaListItemResponseDTO> =
            Vec::with_capacity(result.values.len());
        for credential_schema in result.values {
            items.push(
                to_credential_schema_list_response(
                    credential_schema,
                    include_translations,
                    &*self.formatter_provider,
                )
                .await
                .error_while("mapping credential schemas")?,
            );
        }

        Ok(GetListResponse {
            values: items,
            total_items: result.total_items,
            total_pages: result.total_pages,
        })
    }

    pub async fn get_credential_schema_list_v2(
        &self,
        filter_params: ListQueryDTO<
            SortableCredentialSchemaColumn,
            CredentialSchemaV2FilterParamsDTO,
            CredentialSchemaListIncludeEntityTypeEnum,
        >,
    ) -> Result<GetCredentialSchemaListV2ResponseDTO, CredentialSchemaServiceError> {
        throw_if_org_id_not_matching_session(
            &filter_params.filter.organisation_id,
            &*self.session_provider,
        )
        .error_while("checking session")?;

        let include_translations = filter_params
            .include
            .as_ref()
            .is_some_and(|i| i.contains(&CredentialSchemaListIncludeEntityTypeEnum::Translations));
        let result = self
            .credential_schema_repository
            .get_credential_schema_list(filter_params.into())
            .await
            .and_then(|list| list.require_count())
            .error_while("getting credential schemas")?;

        let mut items: Vec<CredentialSchemaListItemV2ResponseDTO> =
            Vec::with_capacity(result.values.len());
        for credential_schema in result.values {
            items.push(
                to_credential_schema_list_v2_response(
                    credential_schema,
                    include_translations,
                    &self.config,
                    self.formatter_provider.as_ref(),
                )
                .await
                .error_while("mapping credential schemas")?,
            );
        }

        Ok(GetListResponse {
            values: items,
            total_items: result.total_items,
            total_pages: result.total_pages,
        })
    }

    /// Imports a credential schema according to request
    ///
    /// # Arguments
    ///
    /// * `request` - create credential schema request
    pub async fn import_credential_schema(
        &self,
        request: ImportCredentialSchemaRequestDTO,
    ) -> Result<CredentialSchemaId, CredentialSchemaServiceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        let organisation = self.get_organisation(request.organisation_id).await?;

        let credential_schema = self
            .import_parser
            .parse_import_credential_schema(
                crate::proto::credential_schema::dto::ImportCredentialSchemaRequestDTO {
                    organisation,
                    schema: request.schema.into(),
                },
            )
            .error_while("parsing schema")?;

        let success_log = format!(
            "Imported credential schema `{}` ({}): format `{}`, allow revocation `{}`, key storage security {}",
            credential_schema.name,
            credential_schema.id,
            credential_schema.format().await?,
            credential_schema.allow_revocation,
            quoted_opt_provider(
                &credential_schema
                    .wallet_attestation
                    .key_storage_security_level
            )
        );

        let credential_schema = self
            .importer_proto
            .import_credential_schema(credential_schema)
            .await
            .error_while("importing schema")?;
        tracing::info!(message = success_log);
        Ok(credential_schema.id)
    }

    pub async fn import_credential_schema_v2(
        &self,
        request: ImportCredentialSchemaV2RequestDTO,
    ) -> Result<CredentialSchemaId, CredentialSchemaServiceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        let organisation = self.get_organisation(request.organisation_id).await?;

        let credential_schema = self
            .import_parser
            .parse_import_credential_schema_v2(
                crate::proto::credential_schema::dto::ImportCredentialSchemaV2RequestDTO {
                    organisation,
                    schema: request.schema.into(),
                },
            )
            .error_while("parsing schema")?;

        let success_log = format!(
            "Imported credential schema v2 `{}` ({}): key storage security {}",
            credential_schema.name,
            credential_schema.id,
            quoted_opt_provider(
                &credential_schema
                    .wallet_attestation
                    .key_storage_security_level
            )
        );

        let credential_schema = self
            .importer_proto
            .import_credential_schema(credential_schema)
            .await
            .error_while("importing schema")?;
        tracing::info!(message = success_log);
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
    ) -> Result<CredentialSchemaShareResponseDTO, CredentialSchemaServiceError> {
        let credential_schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?;

        throw_if_org_id_not_matching_session(
            credential_schema.organisation.id_ref(),
            &*self.session_provider,
        )
        .error_while("checking session")?;

        Ok(CredentialSchemaShareResponseDTO {
            url: credential_schema.imported_source_url,
        })
    }
}
