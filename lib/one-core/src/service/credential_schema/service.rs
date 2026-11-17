use std::collections::HashMap;

use indexmap::IndexMap;
use shared_types::{CredentialFormat, CredentialSchemaId, HistoryId, OrganisationId};
use time::OffsetDateTime;

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
    UpdateCredentialSchemaRequestDTO,
};
use super::error::CredentialSchemaServiceError;
use super::mapper::{
    add_metadata_claims_and_mappings, build_format_with_claim_mappings,
    embedded_disclosure_policy_json, from_create_v2_request_with_id,
    map_v1_mdoc_create_claims_to_v2, merge_layout_properties, merge_transaction_code,
    schema_to_detail_v1_response_dto, schema_to_detail_v2_response_dto, schema_translations,
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
    backfill_default_translations, claim_name_translations_from_dto, from_request_claim_schema,
};
use crate::model::claim_schema::ClaimSchema;
use crate::model::common::GetListResponse;
use crate::model::credential::{
    CredentialFilterValue, CredentialListQuery, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::credential_schema::{
    CredentialSchema, SortableCredentialSchemaColumn, UpdateCredentialSchemaRequest,
};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::list_filter::ListFilterCondition;
use crate::model::organisation::Organisation;
use crate::proto::credential_schema::dto::CredentialClaimSchemaMappingDTO;
use crate::proto::session_provider::SessionExt;
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
                monitor_credential_lifetime: false,
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

        let credential_schema_id = CredentialSchemaId::new();
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

    pub async fn update_credential_schema(
        &self,
        credential_schema_id: &CredentialSchemaId,
        request: UpdateCredentialSchemaRequestDTO,
    ) -> Result<(), CredentialSchemaServiceError> {
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

        let existing_formats = schema.formats.as_ref().await?;
        let claim_schemas = schema.claim_schemas.as_ref().await?;
        super::validator::validate_update_request(
            &request,
            &schema,
            &existing_formats,
            &claim_schemas,
            &self.config,
            &*self.formatter_provider,
        )?;

        let layout_properties = match request.layout_properties {
            None => None,
            Some(None) => Some(None),
            Some(Some(update)) => {
                let layout_properties =
                    merge_layout_properties(schema.layout_properties.clone(), update)?;
                super::validator::validate_layout_properties(&layout_properties, &claim_schemas)?;
                Some(Some(layout_properties.into()))
            }
        };
        let transaction_code = match request.transaction_code {
            None => None,
            Some(None) => Some(None),
            Some(Some(update)) => {
                let transaction_code =
                    merge_transaction_code(schema.transaction_code.clone(), update)?;
                super::validator::validate_transaction_code_description(&transaction_code)?;
                Some(Some(transaction_code.into()))
            }
        };

        let now = crate::clock::now_utc();
        let mut updated_claim_schemas = vec![];
        for claim in request.claims.unwrap_or_default() {
            let Some(translations) = claim.translations else {
                continue;
            };
            let claim_schema = claim_schemas
                .iter()
                .find(|claim_schema| claim_schema.id == claim.id)
                .ok_or(CredentialSchemaServiceError::MissingClaimSchema(claim.id))?;
            updated_claim_schemas.push(ClaimSchema {
                last_modified: now,
                translations: claim_name_translations_from_dto(claim.id, &translations, now).into(),
                ..claim_schema.clone()
            });
        }

        let (formats, metadata_claim_schemas) = self
            .added_formats(
                &schema,
                &claim_schemas,
                request.formats.unwrap_or_default(),
                now,
            )
            .await?;
        updated_claim_schemas.extend(metadata_claim_schemas);

        let translations = request
            .translations
            .map(|translations| {
                schema_translations(schema.id, translations.name, translations.description, now)
            })
            .unwrap_or_default();

        let embedded_disclosure_policy = match request.embedded_disclosure_policy {
            None => None,
            Some(None) => Some(None),
            Some(Some(policy)) => Some(Some(embedded_disclosure_policy_json(
                schema.id,
                policy,
                self.core_base_url.as_ref(),
            )?)),
        };

        self.credential_schema_repository
            .update_credential_schema(
                &schema.id,
                UpdateCredentialSchemaRequest {
                    claim_schemas: (!updated_claim_schemas.is_empty())
                        .then_some(updated_claim_schemas),
                    claim_mappings: None,
                    formats: (!formats.is_empty()).then_some(formats),
                    layout_properties,
                    translations: (!translations.is_empty()).then_some(translations),
                    batch_size: request.batch_size,
                    expiration: request.expiration,
                    transaction_code,
                    embedded_disclosure_policy,
                },
            )
            .await
            .map_err(|error| match error {
                DataLayerError::RecordNotUpdated(_) => {
                    CredentialSchemaServiceError::NotFound(*credential_schema_id)
                }
                error => error.error_while("updating credential schema").into(),
            })?;

        self.expire_pending_credentials(schema.id).await?;

        let history = self
            .history_repository
            .create_history(History {
                id: HistoryId::new(),
                created_date: now,
                action: HistoryAction::Updated,
                name: schema.name.clone(),
                source: HistorySource::Core,
                target: None,
                entity_id: Some(schema.id.into()),
                entity_type: HistoryEntityType::CredentialSchema,
                metadata: None,
                metadata_blob_id: None,
                organisation_id: Some(schema.organisation.id()),
                user: self.session_provider.session().user(),
            })
            .await;
        if let Err(err) = history {
            tracing::warn!("failed to insert credential schema history event: {err:?}");
        }

        tracing::info!(
            "Updated credential schema `{}` ({})",
            schema.name,
            schema.id
        );
        Ok(())
    }

    async fn added_formats(
        &self,
        schema: &CredentialSchema,
        claim_schemas: &[ClaimSchema],
        new_formats: Vec<CredentialSchemaFormatRequestDTO>,
        now: OffsetDateTime,
    ) -> Result<(Vec<CredentialSchemaFormat>, Vec<ClaimSchema>), CredentialSchemaServiceError> {
        if new_formats.is_empty() {
            return Ok((vec![], vec![]));
        }
        let core_base_url = self.core_base_url.as_ref().ok_or_else(|| {
            CredentialSchemaServiceError::MappingError("Missing core base_url".to_string())
        })?;

        let ecosystem_schema_ids = new_formats
            .iter()
            .flat_map(|format| format.ecosystem_schema_id.clone())
            .collect::<Vec<_>>();
        if !ecosystem_schema_ids.is_empty()
            && matches!(
                super::validator::credential_schema_already_exists(
                    &*self.credential_schema_repository,
                    &schema.name,
                    ecosystem_schema_ids,
                    schema.organisation.id(),
                )
                .await?,
                UniquenessCheckResult::SchemaIdConflict
            )
        {
            return Err(CredentialSchemaServiceError::AlreadyExists);
        }

        let mut key_to_claim_schemas_and_mappings = claim_schemas
            .iter()
            .map(|claim_schema| (claim_schema.key.clone(), (claim_schema.clone(), vec![])))
            .collect::<IndexMap<_, _>>();
        let mut formats = Vec::with_capacity(new_formats.len());
        for format in &new_formats {
            let formatter = self
                .formatter_provider
                .get_credential_formatter(&format.format)?;
            let schema_id = formatter
                .credential_schema_id(
                    schema.id,
                    schema.organisation.id(),
                    format.ecosystem_schema_id.as_deref(),
                    core_base_url,
                    &format.format,
                )
                .error_while("creating schemaId")?;
            let format_type = self
                .config
                .format
                .get_type(&format.format)
                .error_while("getting format type")?;
            let namespace = (format_type == FormatType::Mdoc).then(|| schema_id.clone());
            for (claim_schema, mappings) in key_to_claim_schemas_and_mappings.values_mut() {
                if !claim_schema.metadata {
                    mappings.push(CredentialClaimSchemaMappingDTO {
                        format: format.format.clone(),
                        technical_key: claim_schema.key.clone(),
                        namespace: namespace.clone(),
                    });
                }
            }
            add_metadata_claims_and_mappings(
                &format.format,
                formatter.as_ref(),
                now,
                &mut key_to_claim_schemas_and_mappings,
            );
            formats.push(build_format_with_claim_mappings(
                schema.id,
                format.format.clone(),
                schema_id,
                now,
                &key_to_claim_schemas_and_mappings,
            )?);
        }

        let metadata_claim_schemas = key_to_claim_schemas_and_mappings
            .into_values()
            .map(|(claim_schema, _)| claim_schema)
            .filter(|claim_schema| !claim_schemas.iter().any(|c| c.id == claim_schema.id))
            .collect();
        Ok((formats, metadata_claim_schemas))
    }

    async fn expire_pending_credentials(
        &self,
        credential_schema_id: CredentialSchemaId,
    ) -> Result<(), CredentialSchemaServiceError> {
        let pending = self
            .credential_repository
            .get_credential_list(CredentialListQuery {
                include_count: false,
                pagination: None,
                sorting: None,
                filtering: Some(
                    ListFilterCondition::from(CredentialFilterValue::CredentialSchemaIds(vec![
                        credential_schema_id,
                    ])) & CredentialFilterValue::States(vec![CredentialStateEnum::Pending]),
                ),
                include: None,
            })
            .await
            .error_while("getting pending credentials")?;

        for credential in pending.values {
            self.credential_repository
                .update_credential(
                    credential.common().id,
                    UpdateCredentialRequest {
                        state: Some(CredentialStateEnum::InteractionExpired),
                        ..Default::default()
                    },
                )
                .await
                .error_while("expiring pending credential")?;
        }
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
            "Imported credential schema `{}` ({}): formats `{}`, allow revocation `{}`, key storage security {}",
            credential_schema.name,
            credential_schema.id,
            credential_schema
                .formats
                .as_ref()
                .await?
                .iter()
                .map(|format| format.format.to_string())
                .collect::<Vec<_>>()
                .join(", "),
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
