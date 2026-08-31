use std::collections::{HashMap, HashSet};

use indexmap::IndexMap;
use one_dto_mapper::convert_inner;
use shared_types::{CredentialFormat, CredentialSchemaId, OrganisationId};
use standardized_types::etsi_119_472::disclosure_policy::DisclosurePolicy;
use standardized_types::openid4vp::dcql;
use standardized_types::openid4vp::dcql::{MsoMdocMeta, SdJwtVcMeta, W3cVcMeta};
use url::Url;
use uuid::Uuid;

use super::dto::{
    CreateCredentialSchemaV2RequestDTO, CredentialClaimSchemaDTO, CredentialClaimSchemaRequestDTO,
    CredentialClaimSchemaTranslationsDTO, CredentialClaimSchemaV2DTO,
    CredentialSchemaBackgroundPropertiesRequestDTO, CredentialSchemaCodePropertiesDTO,
    CredentialSchemaDcqlResponseDTO, CredentialSchemaDetailResponseDTO,
    CredentialSchemaDetailV2ResponseDTO, CredentialSchemaFilterParamsDTO,
    CredentialSchemaFilterValue, CredentialSchemaFormatResponseDTO,
    CredentialSchemaLayoutPropertiesRequestDTO, CredentialSchemaListItemResponseDTO,
    CredentialSchemaListItemV2ResponseDTO, CredentialSchemaLogoPropertiesRequestDTO,
    CredentialSchemaTranslationsDTO, CredentialSchemaV2FilterParamsDTO,
};
use super::error::CredentialSchemaServiceError;
use crate::config::core_config::{CoreConfig, DatatypeType, FormatType};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::mapper::credential_schema_claim::{
    claim_schema_from_metadata_claim_schema, claim_schema_to_dto, translations_to_i18n,
};
use crate::mapper::{NESTED_CLAIM_MARKER, remove_first_nesting_layer};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaExactColumn, CredentialSchemaListQuery,
};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use crate::model::list_query::ListPagination;
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::model::organisation::Organisation;
use crate::model::relation::RelatedVec;
use crate::proto::credential_schema::dto::CredentialClaimSchemaMappingDTO;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::Context;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;

pub(super) fn map_v1_mdoc_create_claims_to_v2(
    claims: Vec<CredentialClaimSchemaRequestDTO>,
    config: &CoreConfig,
    format: &CredentialFormat,
    layout_properties: &mut Option<CredentialSchemaLayoutPropertiesRequestDTO>,
) -> Result<Vec<CredentialClaimSchemaRequestDTO>, CredentialSchemaServiceError> {
    let mut result = vec![];

    #[derive(Clone, Copy, Hash, PartialEq, Eq)]
    enum LayoutClaimAttribute {
        Primary,
        Secondary,
        Picture,
        Code,
    }
    let mut modified_layout_attrs = HashSet::new();
    let mut known_keys = HashSet::new();

    for root_claim in claims {
        if let Some(mappings) = &root_claim.mappings
            && let Some(mapping) = mappings.iter().find(|m| &m.format == format)
            && mapping.namespace.is_some()
        {
            // namespace already filled, do not modify
            result.push(root_claim);
            continue;
        }

        let data_type = config
            .datatype
            .get_fields(&root_claim.datatype)
            .error_while("getting datatype config")?
            .r#type;
        if data_type != DatatypeType::Object
            || root_claim.array == Some(true)
            || root_claim.claims.is_empty()
        {
            return Err(
                CredentialSchemaServiceError::InvalidClaimTypeMdocTopLevelOnlyObjectsAllowed,
            );
        }

        let namespace = root_claim.key;

        for mut element in root_claim.claims {
            element.mappings = Some(vec![CredentialClaimSchemaMappingDTO {
                format: format.to_owned(),
                technical_key: element.key.to_owned(),
                namespace: Some(namespace.to_owned()),
            }]);
            if known_keys.contains(&element.key) {
                element.key = format!("{namespace}_{}", element.key);
            }
            known_keys.insert(element.key.clone());
            result.push(element);
        }

        // modify layout properties where modified claim paths mentioned
        if let Some(layout_properties) = layout_properties {
            let get_modified_path = |path: &str| {
                if path.starts_with(&format!("{namespace}{NESTED_CLAIM_MARKER}")) {
                    let strip_len = namespace.len() + 1;
                    return Some(path[strip_len..].to_string());
                }
                None
            };
            let mut modify_path = |path: &mut Option<String>, prop: LayoutClaimAttribute| {
                if !modified_layout_attrs.contains(&prop)
                    && let Some(path_ref) = path
                    && let Some(modified) = get_modified_path(path_ref)
                {
                    *path = Some(modified);
                    modified_layout_attrs.insert(prop);
                }
            };

            modify_path(
                &mut layout_properties.primary_attribute,
                LayoutClaimAttribute::Primary,
            );
            modify_path(
                &mut layout_properties.secondary_attribute,
                LayoutClaimAttribute::Secondary,
            );
            modify_path(
                &mut layout_properties.picture_attribute,
                LayoutClaimAttribute::Picture,
            );
            if !modified_layout_attrs.contains(&LayoutClaimAttribute::Code)
                && let Some(code) = layout_properties.code.as_mut()
                && let Some(modified) = get_modified_path(&code.attribute)
            {
                code.attribute = modified;
                modified_layout_attrs.insert(LayoutClaimAttribute::Code);
            }
        }
    }

    Ok(result)
}

pub(crate) async fn schema_to_detail_v1_response_dto(
    value: CredentialSchema,
    config: &CoreConfig,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<CredentialSchemaDetailResponseDTO, CredentialSchemaServiceError> {
    let formats = value.formats.as_ref().await?;
    let format = formats
        .first()
        .ok_or(CredentialSchemaServiceError::MappingError(
            "Missing formats".to_string(),
        ))?;
    let dcql = map_dcql_format_meta(format, config);
    let mut non_metadata_claims = non_metadata_claim_schemas(&value).await?;
    let mut claim_schema_dtos = Vec::with_capacity(non_metadata_claims.len());

    let format_type = config
        .format
        .get_type(&format.format)
        .error_while("getting format config")?;
    if format_type == FormatType::Mdoc {
        let claim_mappings = format.claim_mappings.as_ref().await?;

        // prepend namespaces
        for cs in non_metadata_claims.iter_mut() {
            let mapping = claim_mappings
                .iter()
                .find(|m| m.claim_schema_id == cs.id)
                .ok_or(CredentialSchemaServiceError::MappingError(
                    "Missing MDOC claim mapping".to_string(),
                ))?;

            let namespace =
                mapping
                    .namespace
                    .as_ref()
                    .ok_or(CredentialSchemaServiceError::MappingError(
                        "Missing MDOC claim mapping namespace".to_string(),
                    ))?;

            cs.key = format!("{namespace}{NESTED_CLAIM_MARKER}{}", cs.key);
        }

        // re-create namespace level claim schemas
        let mut namespaces: HashMap<String, ClaimSchema> = HashMap::new();
        for claim_mapping in &claim_mappings {
            let Some(namespace) = &claim_mapping.namespace else {
                continue;
            };

            // stable id
            let id = Uuid::from(claim_mapping.id).into();

            if !namespaces.contains_key(namespace) {
                namespaces.insert(
                    namespace.to_owned(),
                    ClaimSchema {
                        id,
                        key: namespace.to_owned(),
                        data_type: DatatypeType::Object.to_string(),
                        created_date: claim_mapping.created_date,
                        last_modified: claim_mapping.last_modified,
                        array: false,
                        metadata: false,
                        required: true,
                        translations: vec![LocalizedText {
                            entity_id: id.into(),
                            field: LocalizedTextField::Name,
                            created_date: claim_mapping.created_date,
                            last_modified: claim_mapping.last_modified,
                            lang: config.global_settings.default_language.to_owned(),
                            value: namespace.to_owned(),
                            entity_type: LocalizedTextEntityType::ClaimSchema,
                        }]
                        .into(),
                    },
                );
            }
        }

        non_metadata_claims.extend(namespaces.into_values());
    }

    for cs in non_metadata_claims {
        claim_schema_dtos.push(
            claim_schema_to_dto(cs)
                .await
                .map_err(|e| CredentialSchemaServiceError::MappingError(e.to_string()))?,
        );
    }
    let claim_schemas = renest_claim_schemas(claim_schema_dtos)?;

    let formatter = formatter_provider.get_credential_formatter(&format.format)?;
    let revocation_method = value.revocation_method_id(&*formatter).cloned();

    Ok(CredentialSchemaDetailResponseDTO {
        translations: map_translations(&value).await?,
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
        format: format.format.clone(),
        imported_source_url: value.imported_source_url,
        revocation_method,
        organisation_id: value.organisation.id(),
        claims: claim_schemas,
        key_storage_security: value.key_storage_security,
        schema_id: format.ecosystem_schema_id.clone(),
        layout_properties: value.layout_properties.map(|item| item.into()),
        allow_suspension: value.allow_suspension,
        requires_wallet_instance_attestation: value.requires_wallet_instance_attestation,
        transaction_code: convert_inner(value.transaction_code),
        dcql,
        expiration: value.expiration,
        ecosystem: value.ecosystem,
    })
}

pub(crate) async fn schema_to_detail_v2_response_dto(
    value: CredentialSchema,
    format: Option<&CredentialFormat>,
    config: &CoreConfig,
) -> Result<CredentialSchemaDetailV2ResponseDTO, CredentialSchemaServiceError> {
    let formats = value.formats.as_ref().await?;
    let formats = if let Some(format) = format {
        formats
            .into_iter()
            .filter(|csf| csf.format == *format)
            .map(ToOwned::to_owned)
            .collect()
    } else {
        formats.to_vec()
    };

    let format_responses: Vec<CredentialSchemaFormatResponseDTO> = formats
        .iter()
        .map(|f| CredentialSchemaFormatResponseDTO {
            format: f.format.clone(),
            schema_id: f.ecosystem_schema_id.clone(),
            dcql: map_dcql_format_meta(f, config),
        })
        .collect();

    let non_metadata_claim_schemas = non_metadata_claim_schemas(&value).await?;
    let mut claim_mappings_map: HashMap<
        shared_types::ClaimSchemaId,
        Vec<CredentialClaimSchemaMappingDTO>,
    > = HashMap::new();

    for format in &formats {
        let mappings = format.claim_mappings.as_ref().await?;
        for mapping in &mappings {
            claim_mappings_map
                .entry(mapping.claim_schema_id)
                .or_default()
                .push(CredentialClaimSchemaMappingDTO {
                    format: format.format.clone(),
                    technical_key: mapping.technical_key.clone(),
                    namespace: mapping.namespace.clone(),
                });
        }
    }

    let mut claim_schemas_v2 = vec![];
    for cs in non_metadata_claim_schemas {
        let mappings = claim_mappings_map.remove(&cs.id);
        let translations = cs.translations.as_ref().await?;
        let dto = CredentialClaimSchemaV2DTO {
            id: cs.id,
            created_date: cs.created_date,
            last_modified: cs.last_modified,
            key: cs.key,
            datatype: cs.data_type,
            required: cs.required,
            array: cs.array,
            claims: vec![],
            mappings,
            translations: CredentialClaimSchemaTranslationsDTO {
                name: translations_to_i18n(&translations, LocalizedTextField::Name).ok_or(
                    CredentialSchemaServiceError::MappingError(format!(
                        "No translations for `name` of claim schema {}",
                        cs.id
                    )),
                )?,
            },
        };
        claim_schemas_v2.push(dto);
    }

    let claim_schemas_v2 = renest_claim_schemas_v2(claim_schemas_v2)?;

    let embedded_disclosure_policy = match &value.embedded_disclosure_policy {
        None => None,
        Some(policy) => Some(
            serde_json::from_str(policy)
                .map_err(|e| CredentialSchemaServiceError::MappingError(e.to_string()))?,
        ),
    };

    Ok(CredentialSchemaDetailV2ResponseDTO {
        translations: map_translations(&value).await?,
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
        formats: format_responses,
        imported_source_url: value.imported_source_url,
        organisation_id: value.organisation.id(),
        claims: claim_schemas_v2,
        key_storage_security: value.key_storage_security,
        layout_properties: value.layout_properties.map(|item| item.into()),
        allow_suspension: value.allow_suspension,
        allow_revocation: Some(value.allow_revocation),
        batch_size: value.batch_size,
        requires_wallet_instance_attestation: value.requires_wallet_instance_attestation,
        transaction_code: convert_inner(value.transaction_code),
        embedded_disclosure_policy,
        expiration: value.expiration,
        ecosystem: value.ecosystem,
    })
}

async fn non_metadata_claim_schemas(
    value: &CredentialSchema,
) -> Result<Vec<ClaimSchema>, CredentialSchemaServiceError> {
    Ok(value
        .claim_schemas
        .as_ref()
        .await?
        .into_iter()
        .filter(|schema| !schema.metadata)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>())
}
fn renest_claim_schemas_v2(
    claim_schemas: Vec<CredentialClaimSchemaV2DTO>,
) -> Result<Vec<CredentialClaimSchemaV2DTO>, CredentialSchemaServiceError> {
    let mut result = vec![];

    for claim_schema in claim_schemas.iter() {
        if claim_schema.key.find(NESTED_CLAIM_MARKER).is_none() {
            result.push(claim_schema.to_owned());
        }
    }

    for mut claim_schema in claim_schemas.into_iter() {
        if claim_schema.key.find(NESTED_CLAIM_MARKER).is_some() {
            let matching_entry = result
                .iter_mut()
                .find(|result_schema| {
                    claim_schema
                        .key
                        .starts_with(&format!("{}{NESTED_CLAIM_MARKER}", result_schema.key))
                })
                .ok_or(CredentialSchemaServiceError::MissingParentClaimSchema {
                    claim_schema_id: claim_schema.id,
                })?;
            claim_schema.key = remove_first_nesting_layer(&claim_schema.key);
            matching_entry.claims.push(claim_schema);
        }
    }

    result
        .into_iter()
        .map(|mut claim_schema| {
            claim_schema.claims = renest_claim_schemas_v2(claim_schema.claims)?;
            Ok(claim_schema)
        })
        .collect::<Result<Vec<CredentialClaimSchemaV2DTO>, _>>()
}

fn map_dcql_format_meta(
    format: &CredentialSchemaFormat,
    config: &CoreConfig,
) -> Option<CredentialSchemaDcqlResponseDTO> {
    // Ignore failures here, as we don't want to fail the whole request if we can't map the format.
    // This would happen e.g., if a provider is renamed and the schema is still using the old name.
    let format_type = config.format.get_type(&format.format).ok()?;
    let dcql = CredentialSchemaDcqlResponseDTO {
        format: schema_to_dcql_meta(format, &format_type),
    };
    Some(dcql)
}

fn schema_to_dcql_meta(
    format: &CredentialSchemaFormat,
    format_type: &FormatType,
) -> dcql::CredentialFormat {
    match format_type {
        FormatType::SdJwtVc => dcql::CredentialFormat::SdJwt(SdJwtVcMeta {
            vct_values: vec![format.ecosystem_schema_id.clone()],
        }),
        FormatType::Mdoc => dcql::CredentialFormat::MsoMdoc(MsoMdocMeta {
            doctype_value: format.ecosystem_schema_id.clone(),
        }),
        FormatType::Jwt => dcql::CredentialFormat::JwtVc(w3c_meta_from_format(format)),
        FormatType::SdJwt => dcql::CredentialFormat::W3cSdJwt(w3c_meta_from_format(format)),
        FormatType::JsonLdClassic => dcql::CredentialFormat::LdpVc(w3c_meta_from_format(format)),
        FormatType::JsonLdBbsPlus => dcql::CredentialFormat::LdpVc(w3c_meta_from_format(format)),
    }
}

fn w3c_meta_from_format(format: &CredentialSchemaFormat) -> W3cVcMeta {
    // This is a terrible heuristic, but until proper support for JSON-LD contexts is added, this is the best we can do.
    let context = if let Ok(url) = Url::parse(&format.ecosystem_schema_id)
        && url.path().starts_with("/ssi/schema/v1/")
    {
        format
            .ecosystem_schema_id
            .replace("/ssi/schema/v1/", "/ssi/context/v1/")
    } else {
        format.ecosystem_schema_id.clone()
    };
    W3cVcMeta {
        type_values: vec![vec![Context::CredentialsV2.to_string(), context]],
    }
}

pub(super) fn create_unique_name_check_request(
    name: &str,
    schema_ids: Vec<String>,
    organisation_id: OrganisationId,
) -> Result<CredentialSchemaListQuery, CredentialSchemaServiceError> {
    Ok(CredentialSchemaListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 1,
        }),
        filtering: Some(
            CredentialSchemaFilterValue::OrganisationId(organisation_id).condition()
                & (CredentialSchemaFilterValue::Name(StringMatch {
                    r#match: StringMatchType::Equals,
                    value: name.to_owned(),
                })
                .condition()
                    | CredentialSchemaFilterValue::SchemaIds(schema_ids)),
        ),
        ..Default::default()
    })
}

#[expect(clippy::too_many_arguments)]
pub(super) fn from_create_v2_request_with_id(
    id: CredentialSchemaId,
    request: CreateCredentialSchemaV2RequestDTO,
    organisation: Organisation,
    now: time::OffsetDateTime,
    formats: Vec<CredentialSchemaFormat>,
    claim_schemas: Vec<ClaimSchema>,
    imported_source_url: String,
    default_language: &str,
    core_base_url: Option<&String>,
) -> Result<CredentialSchema, CredentialSchemaServiceError> {
    let embedded_disclosure_policy = match request.embedded_disclosure_policy {
        None => None,
        Some(request) => {
            let core_base_url = core_base_url.ok_or(CredentialSchemaServiceError::MappingError(
                "missing core_base_url".to_string(),
            ))?;
            let policy = DisclosurePolicy {
                id: format!("{core_base_url}/ssi/disclosure-policy/v1/{id}"),
                policy: request.policy,
                description: request.description,
                url: request.url,
            };
            Some(
                serde_json::to_string(&policy)
                    .map_err(|e| CredentialSchemaServiceError::MappingError(e.to_string()))?,
            )
        }
    };

    Ok(CredentialSchema {
        id,
        allow_revocation: request.allow_revocation.unwrap_or(false),
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: request.name.clone(),
        key_storage_security: request.key_storage_security,
        claim_schemas: claim_schemas.into(),
        organisation: organisation.into(),
        layout_properties: request.layout_properties.map(Into::into),
        imported_source_url,
        allow_suspension: request.allow_suspension.unwrap_or_default(),
        requires_wallet_instance_attestation: request.requires_wallet_instance_attestation,
        transaction_code: convert_inner(request.transaction_code),
        batch_size: request.batch_size,
        formats: formats.into(),
        translations: match request.translations {
            Some(translations) => schema_translations_from_dto(id, translations, now),
            None => default_name_translation(id, request.name, now, default_language),
        }
        .into(),
        embedded_disclosure_policy,
        expiration: request.expiration,
        ecosystem: request.ecosystem,
    })
}

pub(crate) fn schema_translations_from_dto(
    id: CredentialSchemaId,
    translations: CredentialSchemaTranslationsDTO,
    now: time::OffsetDateTime,
) -> Vec<LocalizedText> {
    let mut result = Vec::new();
    for (lang, value) in translations.name.0 {
        result.push(LocalizedText {
            entity_id: id.into(),
            field: LocalizedTextField::Name,
            created_date: now,
            last_modified: now,
            lang,
            value,
            entity_type: LocalizedTextEntityType::CredentialSchema,
        });
    }
    if let Some(description) = translations.description {
        for (lang, value) in description.0 {
            result.push(LocalizedText {
                entity_id: id.into(),
                field: LocalizedTextField::Description,
                created_date: now,
                last_modified: now,
                lang,
                value,
                entity_type: LocalizedTextEntityType::CredentialSchema,
            });
        }
    }
    result
}

fn default_name_translation(
    id: CredentialSchemaId,
    name: String,
    now: time::OffsetDateTime,
    default_language: &str,
) -> Vec<LocalizedText> {
    vec![LocalizedText {
        entity_id: id.into(),
        field: LocalizedTextField::Name,
        created_date: now,
        last_modified: now,
        lang: default_language.to_string(),
        value: name,
        entity_type: LocalizedTextEntityType::CredentialSchema,
    }]
}

pub(super) fn add_metadata_claims_and_mappings(
    format: &CredentialFormat,
    formatter: &dyn CredentialFormatter,
    now: time::OffsetDateTime,
    key_to_claim_schema_and_mappings: &mut IndexMap<
        String,
        (ClaimSchema, Vec<CredentialClaimSchemaMappingDTO>),
    >,
) {
    for metadata_claim in formatter.get_metadata_claims() {
        let key = metadata_claim.key.clone();
        // the metadata claim could already have been created by a different formatter of the same type
        if let Some((metadata_claim, mappings)) = key_to_claim_schema_and_mappings.get_mut(&key) {
            mappings.push(CredentialClaimSchemaMappingDTO {
                format: format.clone(),
                technical_key: metadata_claim.key.clone(),
                namespace: None,
            })
        } else {
            let metadata_claim = claim_schema_from_metadata_claim_schema(metadata_claim, now);
            key_to_claim_schema_and_mappings.insert(
                key.clone(),
                (
                    metadata_claim,
                    vec![CredentialClaimSchemaMappingDTO {
                        format: format.clone(),
                        technical_key: key,
                        namespace: None,
                    }],
                ),
            );
        };
    }
}
pub(super) fn build_format_with_claim_mappings(
    credential_schema_id: CredentialSchemaId,
    format: CredentialFormat,
    ecosystem_schema_id: String,
    now: time::OffsetDateTime,
    key_to_claim_schema_and_mappings: &IndexMap<
        String,
        (ClaimSchema, Vec<CredentialClaimSchemaMappingDTO>),
    >,
) -> Result<CredentialSchemaFormat, CredentialSchemaServiceError> {
    let format_id = Uuid::new_v4().into();
    let mut format_specific_mappings = vec![];
    for (claim_schema, mappings) in key_to_claim_schema_and_mappings.values() {
        let mapping = mappings.iter().find(|m| m.format == format);
        if mapping.is_none() && claim_schema.metadata {
            // metadata claims do only exist for their respective format
            continue;
        }
        let CredentialClaimSchemaMappingDTO {
            technical_key,
            namespace,
            ..
        } = mapping
            .ok_or(CredentialSchemaServiceError::MappingError(format!(
                "missing mapping for claim schema `{}` and format `{format}`",
                claim_schema.key
            )))?
            .clone();
        format_specific_mappings.push(CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            credential_schema_format_id: format_id,
            claim_schema_id: claim_schema.id,
            technical_key,
            namespace,
        })
    }

    Ok(CredentialSchemaFormat {
        id: format_id,
        created_date: now,
        last_modified: now,
        credential_schema_id,
        format,
        ecosystem_schema_id,
        claim_mappings: RelatedVec::from(format_specific_mappings),
    })
}

pub(crate) async fn to_credential_schema_list_response(
    credential_schema: CredentialSchema,
    include_translations: bool,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<CredentialSchemaListItemResponseDTO, NestedError> {
    let format = credential_schema.format().await?.to_owned();
    let schema_id = credential_schema.schema_id().await?;
    let translations = if include_translations {
        Some(
            map_translations(&credential_schema)
                .await
                .error_while("mapping translations")?,
        )
    } else {
        None
    };
    let formatter = formatter_provider.get_credential_formatter(&format)?;
    let revocation_method = credential_schema.revocation_method_id(&*formatter).cloned();
    Ok(CredentialSchemaListItemResponseDTO {
        id: credential_schema.id,
        created_date: credential_schema.created_date,
        last_modified: credential_schema.last_modified,
        deleted_at: credential_schema.deleted_at,
        name: credential_schema.name,
        format,
        ecosystem: credential_schema.ecosystem,
        revocation_method,
        key_storage_security: credential_schema.key_storage_security,
        schema_id,
        imported_source_url: credential_schema.imported_source_url,
        layout_properties: credential_schema.layout_properties.map(|item| item.into()),
        allow_suspension: credential_schema.allow_suspension,
        requires_wallet_instance_attestation: credential_schema
            .requires_wallet_instance_attestation,
        translations,
    })
}

pub(crate) async fn to_credential_schema_list_v2_response(
    credential_schema: CredentialSchema,
    config: &CoreConfig,
) -> Result<CredentialSchemaListItemV2ResponseDTO, NestedError> {
    let formats = credential_schema.formats.as_ref().await?;
    let format_responses: Vec<CredentialSchemaFormatResponseDTO> = formats
        .iter()
        .map(|f| CredentialSchemaFormatResponseDTO {
            format: f.format.clone(),
            schema_id: f.ecosystem_schema_id.clone(),
            dcql: map_dcql_format_meta(f, config),
        })
        .collect();

    Ok(CredentialSchemaListItemV2ResponseDTO {
        id: credential_schema.id,
        created_date: credential_schema.created_date,
        last_modified: credential_schema.last_modified,
        name: credential_schema.name,
        formats: format_responses,
        ecosystem: credential_schema.ecosystem,
        key_storage_security: credential_schema.key_storage_security,
        imported_source_url: credential_schema.imported_source_url,
        layout_properties: credential_schema.layout_properties.map(|item| item.into()),
        allow_suspension: credential_schema.allow_suspension,
        allow_revocation: Some(credential_schema.allow_revocation),
        batch_size: credential_schema.batch_size,
        requires_wallet_instance_attestation: credential_schema
            .requires_wallet_instance_attestation,
        expiration: credential_schema.expiration,
    })
}

async fn map_translations(
    schema: &CredentialSchema,
) -> Result<CredentialSchemaTranslationsDTO, CredentialSchemaServiceError> {
    let texts = schema.translations.as_ref().await?;
    Ok(CredentialSchemaTranslationsDTO {
        name: translations_to_i18n(&texts, LocalizedTextField::Name).ok_or(
            CredentialSchemaServiceError::MappingError(format!(
                "No translations for `name` of credential schema {}",
                schema.id
            )),
        )?,
        description: translations_to_i18n(&texts, LocalizedTextField::Description),
    })
}

pub(super) fn renest_claim_schemas(
    claim_schemas: Vec<CredentialClaimSchemaDTO>,
) -> Result<Vec<CredentialClaimSchemaDTO>, CredentialSchemaServiceError> {
    let mut result = vec![];

    // Iterate over all and copy all unnested claims to new vec
    for claim_schema in claim_schemas.iter() {
        if claim_schema.key.find(NESTED_CLAIM_MARKER).is_none() {
            result.push(claim_schema.to_owned());
        }
    }

    // Find all nested claims and move them to related entries in result vec
    for mut claim_schema in claim_schemas.into_iter() {
        if claim_schema.key.find(NESTED_CLAIM_MARKER).is_some() {
            let matching_entry = result
                .iter_mut()
                .find(|result_schema| {
                    claim_schema
                        .key
                        .starts_with(&format!("{}{NESTED_CLAIM_MARKER}", result_schema.key))
                })
                .ok_or(CredentialSchemaServiceError::MissingParentClaimSchema {
                    claim_schema_id: claim_schema.id,
                })?;
            claim_schema.key = remove_first_nesting_layer(&claim_schema.key);

            matching_entry.claims.push(claim_schema);
        }
    }

    // Repeat for all claims to nest all subclaims
    result
        .into_iter()
        .map(|mut claim_schema| {
            claim_schema.claims = renest_claim_schemas(claim_schema.claims)?;
            Ok(claim_schema)
        })
        .collect::<Result<Vec<CredentialClaimSchemaDTO>, _>>()
}

pub(super) fn unnest_claim_schemas(
    claim_schemas: Vec<CredentialClaimSchemaRequestDTO>,
    formats: &[&CredentialFormat],
    default_namespaces: &HashMap<&CredentialFormat, String>,
) -> Result<Vec<CredentialClaimSchemaRequestDTO>, CredentialSchemaServiceError> {
    unnest_claim_schemas_inner(
        claim_schemas,
        Prefixes::root(),
        formats,
        default_namespaces,
        &mut HashMap::new(),
    )
}

#[derive(Debug, Clone)]
struct Prefixes {
    key: String,
    technical_key: HashMap<CredentialFormat, String>,
}

impl Prefixes {
    fn root() -> Self {
        Self {
            key: "".to_string(),
            technical_key: HashMap::new(),
        }
    }

    fn is_root(&self) -> bool {
        self.key.is_empty()
    }

    fn nest_key(&mut self, key: &String) -> String {
        let key = format!("{}{key}", self.key);
        self.key = format!("{key}{NESTED_CLAIM_MARKER}");
        key
    }

    fn nest_technical_key(&mut self, format: &CredentialFormat, technical_key: &String) -> String {
        let entry = self.technical_key.entry(format.clone()).or_default();
        let technical_key = format!("{}{}", entry, technical_key);
        *entry = format!("{technical_key}{NESTED_CLAIM_MARKER}");
        technical_key
    }
}

fn unnest_claim_schemas_inner(
    claim_schemas: Vec<CredentialClaimSchemaRequestDTO>,
    prefixes: Prefixes,
    formats: &[&CredentialFormat],
    default_namespaces: &HashMap<&CredentialFormat, String>,
    parent_namespaces: &mut HashMap<CredentialFormat, String>,
) -> Result<Vec<CredentialClaimSchemaRequestDTO>, CredentialSchemaServiceError> {
    let mut result = vec![];

    let root_level = prefixes.is_root();
    if root_level && !parent_namespaces.is_empty() {
        return Err(CredentialSchemaServiceError::MappingError(
            "parent namespaces supplied on root level".to_string(),
        ));
    }

    for claim_schema in claim_schemas {
        let mut claim_prefixes = prefixes.clone();
        let key = claim_prefixes.nest_key(&claim_schema.key);
        if root_level {
            // each root claim starts fresh for each schema
            parent_namespaces.clear();
        }

        let mut mappings = claim_schema.mappings.unwrap_or_default();
        for format in formats {
            if let Some(mapping) = mappings.iter_mut().find(|m| m.format == **format) {
                mapping.technical_key =
                    claim_prefixes.nest_technical_key(format, &mapping.technical_key);
                if let Some(namespace) = &mapping.namespace {
                    if !root_level {
                        return Err(CredentialSchemaServiceError::MappingError(format!(
                            "namespace must only be supplied on root level, but was supplied for claim schema with key `{key}`"
                        )));
                    }
                    parent_namespaces.insert((*format).clone(), namespace.to_string());
                } else {
                    mapping.namespace = parent_namespaces
                        .get(format)
                        .or_else(|| default_namespaces.get(format))
                        .cloned()
                }
            } else {
                mappings.push(CredentialClaimSchemaMappingDTO {
                    format: (*format).clone(),
                    technical_key: claim_prefixes.nest_technical_key(format, &claim_schema.key),
                    namespace: parent_namespaces
                        .get(format)
                        .or_else(|| default_namespaces.get(format))
                        .cloned(),
                });
            }
        }

        let nested = unnest_claim_schemas_inner(
            claim_schema.claims,
            claim_prefixes,
            formats,
            default_namespaces,
            parent_namespaces,
        )?;
        result.push(CredentialClaimSchemaRequestDTO {
            key,
            claims: vec![],
            mappings: Some(mappings),
            ..claim_schema
        });

        result.extend(nested);
    }

    Ok(result)
}

impl From<CredentialSchemaLogoPropertiesRequestDTO>
    for crate::proto::credential_schema::dto::CredentialSchemaLogoPropertiesRequestDTO
{
    fn from(value: CredentialSchemaLogoPropertiesRequestDTO) -> Self {
        Self {
            font_color: value.font_color,
            background_color: value.background_color,
            image: value.image,
        }
    }
}

impl From<CredentialSchemaCodePropertiesDTO>
    for crate::proto::credential_schema::dto::CredentialSchemaCodePropertiesDTO
{
    fn from(value: CredentialSchemaCodePropertiesDTO) -> Self {
        Self {
            attribute: value.attribute,
            r#type: value.r#type.into(),
        }
    }
}

impl From<CredentialSchemaBackgroundPropertiesRequestDTO>
    for crate::proto::credential_schema::dto::CredentialSchemaBackgroundPropertiesRequestDTO
{
    fn from(value: CredentialSchemaBackgroundPropertiesRequestDTO) -> Self {
        Self {
            color: value.color,
            image: value.image,
        }
    }
}

impl From<CredentialSchemaFilterParamsDTO> for ListFilterCondition<CredentialSchemaFilterValue> {
    fn from(value: CredentialSchemaFilterParamsDTO) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id =
            CredentialSchemaFilterValue::OrganisationId(value.organisation_id).condition();

        let name = value.name.map(|name| {
            CredentialSchemaFilterValue::Name(StringMatch {
                r#match: get_string_match_type(CredentialSchemaExactColumn::Name),
                value: name,
            })
        });

        let schema_id = value.schema_id.map(|schema_id| {
            CredentialSchemaFilterValue::SchemaId(StringMatch {
                r#match: get_string_match_type(CredentialSchemaExactColumn::SchemaId),
                value: schema_id,
            })
        });

        let formats = value.formats.map(CredentialSchemaFilterValue::Formats);

        let ecosystems = value
            .ecosystems
            .map(CredentialSchemaFilterValue::Ecosystems);

        let key_storage_security = value
            .key_storage_security
            .map(CredentialSchemaFilterValue::KeyStorageSecurity);

        let requires_wia = value
            .requires_wallet_instance_attestation
            .map(CredentialSchemaFilterValue::RequiresWalletInstanceAttestation);

        let credential_schema_ids = value
            .credential_schema_ids
            .map(CredentialSchemaFilterValue::CredentialSchemaIds);

        let created_date_after = value.created_date_after.map(|date| {
            CredentialSchemaFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            CredentialSchemaFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            CredentialSchemaFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            CredentialSchemaFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let uses_batch_issuance = value
            .uses_batch_issuance
            .map(CredentialSchemaFilterValue::UsesBatchIssuance);

        let is_multiformat_schema = value
            .is_multiformat_schema
            .map(CredentialSchemaFilterValue::IsMultiformatSchema);

        let schema_ids = value.schema_ids.map(CredentialSchemaFilterValue::SchemaIds);

        organisation_id
            & name
            & schema_id
            & schema_ids
            & formats
            & ecosystems
            & key_storage_security
            & requires_wia
            & credential_schema_ids
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
            & uses_batch_issuance
            & is_multiformat_schema
    }
}

impl From<CredentialSchemaV2FilterParamsDTO> for ListFilterCondition<CredentialSchemaFilterValue> {
    fn from(value: CredentialSchemaV2FilterParamsDTO) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id =
            CredentialSchemaFilterValue::OrganisationId(value.organisation_id).condition();

        let name = value.name.map(|name| {
            CredentialSchemaFilterValue::Name(StringMatch {
                r#match: get_string_match_type(CredentialSchemaExactColumn::Name),
                value: name,
            })
        });

        let formats = value.formats.map(CredentialSchemaFilterValue::Formats);

        let ecosystems = value
            .ecosystems
            .map(CredentialSchemaFilterValue::Ecosystems);

        let key_storage_security = value
            .key_storage_security
            .map(CredentialSchemaFilterValue::KeyStorageSecurity);

        let requires_wia = value
            .requires_wallet_instance_attestation
            .map(CredentialSchemaFilterValue::RequiresWalletInstanceAttestation);

        let credential_schema_ids = value
            .credential_schema_ids
            .map(CredentialSchemaFilterValue::CredentialSchemaIds);

        let created_date_after = value.created_date_after.map(|date| {
            CredentialSchemaFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            CredentialSchemaFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            CredentialSchemaFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            CredentialSchemaFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let uses_batch_issuance = value
            .uses_batch_issuance
            .map(CredentialSchemaFilterValue::UsesBatchIssuance);

        let is_multiformat_schema = value
            .is_multiformat_schema
            .map(CredentialSchemaFilterValue::IsMultiformatSchema);

        let schema_ids = value.schema_ids.map(CredentialSchemaFilterValue::SchemaIds);

        let expiration_greater_than = value.expiration_greater_than.map(|expiration| {
            CredentialSchemaFilterValue::Expiration(ValueComparison {
                comparison: ComparisonType::GreaterThan,
                value: expiration.whole_seconds(),
            })
        });
        let expiration_less_than = value.expiration_less_than.map(|expiration| {
            CredentialSchemaFilterValue::Expiration(ValueComparison {
                comparison: ComparisonType::LessThan,
                value: expiration.whole_seconds(),
            })
        });

        organisation_id
            & name
            & schema_ids
            & formats
            & ecosystems
            & key_storage_security
            & requires_wia
            & credential_schema_ids
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
            & uses_batch_issuance
            & is_multiformat_schema
            & expiration_greater_than
            & expiration_less_than
    }
}
