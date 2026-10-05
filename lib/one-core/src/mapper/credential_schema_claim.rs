use std::collections::{HashMap, VecDeque};

use itertools::Itertools;
use shared_types::ClaimSchemaId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ContextWithErrorCode;
use crate::mapper::{
    NESTED_CLAIM_MARKER, NESTED_CLAIM_MARKER_STR, paths_to_leafs, translations_to_i18n,
};
use crate::model::claim::Claim;
use crate::model::claim_path::ClaimPathSegment;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::model::relation::OptionalRelatedRefExt;
use crate::provider::credential_formatter::MetadataClaimSchema;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::repository::error::DataLayerError;
use crate::service::credential_schema::dto::{
    CredentialClaimSchemaDTO, CredentialClaimSchemaRequestDTO, CredentialClaimSchemaTranslationsDTO,
};
use crate::service::error::ServiceError;

pub(crate) fn claim_schema_from_metadata_claim_schema(
    metadata_claim: MetadataClaimSchema,
    now: OffsetDateTime,
) -> ClaimSchema {
    ClaimSchema {
        id: Uuid::new_v4().into(),
        key: metadata_claim.key.to_string(),
        data_type: metadata_claim.data_type,
        created_date: now,
        last_modified: now,
        array: metadata_claim.array,
        required: metadata_claim.required,
        metadata: true,
        // metadata claims are not translated
        translations: vec![].into(),
    }
}

pub(crate) fn claim_name_translations_from_dto(
    id: ClaimSchemaId,
    translations: &CredentialClaimSchemaTranslationsDTO,
    now: OffsetDateTime,
) -> Vec<LocalizedText> {
    translations
        .name
        .0
        .iter()
        .map(|(lang, value)| LocalizedText {
            entity_id: id.into(),
            field: LocalizedTextField::Name,
            created_date: now,
            last_modified: now,
            lang: lang.clone(),
            value: value.clone(),
            entity_type: LocalizedTextEntityType::ClaimSchema,
        })
        .collect()
}

pub(crate) fn from_request_claim_schema(
    now: OffsetDateTime,
    request: &CredentialClaimSchemaRequestDTO,
) -> ClaimSchema {
    let id: ClaimSchemaId = Uuid::new_v4().into();
    let translations = match &request.translations {
        Some(t) => claim_name_translations_from_dto(id, t, now).into(),
        None => Default::default(),
    };
    ClaimSchema {
        id,
        key: request.key.clone(),
        data_type: request.datatype.clone(),
        created_date: now,
        last_modified: now,
        array: request.array.unwrap_or(false),
        metadata: false,
        required: request.required,
        translations,
    }
}

pub(crate) async fn claim_schema_to_dto(
    value: ClaimSchema,
) -> Result<CredentialClaimSchemaDTO, DataLayerError> {
    let raw = value.translations.as_ref().await?;
    let Some(name) = translations_to_i18n(&raw, LocalizedTextField::Name) else {
        return Err(DataLayerError::MissingRequiredRelation {
            relation: "translations",
            id: value.key.to_string(),
        });
    };
    Ok(CredentialClaimSchemaDTO {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        key: value.key,
        datatype: value.data_type,
        required: value.required,
        array: value.array,
        claims: vec![],
        translations: CredentialClaimSchemaTranslationsDTO { name },
    })
}

pub(crate) async fn backfill_default_translations(
    mut credential_schema: CredentialSchema,
    default_language: &str,
) -> Result<CredentialSchema, DataLayerError> {
    {
        let mut translations = credential_schema.translations.as_mut().await?;
        if !translations
            .iter()
            .any(|t| t.lang == default_language && t.field == LocalizedTextField::Name)
        {
            translations.push(LocalizedText {
                entity_id: credential_schema.id.into(),
                field: LocalizedTextField::Name,
                created_date: credential_schema.created_date,
                last_modified: credential_schema.last_modified,
                lang: default_language.to_string(),
                value: credential_schema.name.clone(),
                entity_type: LocalizedTextEntityType::CredentialSchema,
            });
        }
    }

    let mut claim_schemas = vec![];
    for claim_schema in credential_schema.claim_schemas.as_ref().await?.to_owned() {
        claim_schemas.push(add_fallback_translation(claim_schema, default_language).await?);
    }
    credential_schema.claim_schemas = claim_schemas.into();
    Ok(credential_schema)
}

pub(crate) async fn add_fallback_translation(
    mut claim_schema: ClaimSchema,
    default_language: &str,
) -> Result<ClaimSchema, DataLayerError> {
    {
        let mut translations = claim_schema.translations.as_mut().await?;
        if !claim_schema.metadata
            && !translations
                .iter()
                .any(|t| t.lang == default_language && t.field == LocalizedTextField::Name)
        {
            translations.push(LocalizedText {
                entity_id: claim_schema.id.into(),
                field: LocalizedTextField::Name,
                created_date: claim_schema.created_date,
                last_modified: claim_schema.last_modified,
                lang: default_language.to_string(),
                value: claim_schema
                    .key
                    .rsplit_once(NESTED_CLAIM_MARKER)
                    .map(|(_, end)| end.to_string())
                    .unwrap_or(claim_schema.key.clone()),
                entity_type: LocalizedTextEntityType::ClaimSchema,
            });
        }
    }
    Ok(claim_schema)
}

/// Returns the path of the claim in the formatted credential. The schema keys are replaced by
/// the technical keys of the claim mapping, the array indices of the stored path are kept.
pub(crate) fn technical_claim_path(
    claim: &Claim,
    claim_schema: &ClaimSchema,
    claim_mapping: &CredentialSchemaFormatClaimSchema,
) -> Result<Vec<ClaimPathSegment>, FormatterError> {
    let key_segments = claim_schema
        .key
        .split(NESTED_CLAIM_MARKER)
        .collect::<Vec<&str>>();
    let technical_key_segments = claim_mapping
        .technical_key
        .split(NESTED_CLAIM_MARKER)
        .collect::<Vec<&str>>();
    let mut path_segments = claim
        .path
        .split(NESTED_CLAIM_MARKER)
        .collect::<VecDeque<&str>>();
    if key_segments.len() != technical_key_segments.len() {
        return Err(FormatterError::CouldNotFormat(format!(
            "key `{}` and technical key `{}` have different number of segments",
            claim_schema.key, claim_mapping.technical_key
        )));
    }
    let mut path = vec![];
    if let Some(namespace) = &claim_mapping.namespace {
        path.push(ClaimPathSegment::Key(namespace.clone()));
    }
    for (key_segment, technical_key_segment) in
        key_segments.iter().zip(technical_key_segments.iter())
    {
        map_array_indices(&mut path_segments, key_segment, &mut path)?;
        path.push(ClaimPathSegment::Key(technical_key_segment.to_string()));
    }
    // path segments left over are array indices, which are not part of the schema keys
    for index in path_segments {
        path.push(array_index(index)?);
    }
    Ok(path)
}

/// Maps path segments to the mapped path until one matches the key segment.
/// The path may contain additional segments (the array indices), which are not represented in the
/// schema keys, which is why we need to do this in the first place.
fn map_array_indices(
    path_segments: &mut VecDeque<&str>,
    key_segment: &str,
    path: &mut Vec<ClaimPathSegment>,
) -> Result<(), FormatterError> {
    loop {
        let Some(curr_path_segment) = path_segments.pop_front() else {
            return Err(FormatterError::CouldNotFormat(format!(
                "path segment missing for key segment `{key_segment}`"
            )));
        };
        if curr_path_segment == key_segment {
            return Ok(());
        }
        path.push(array_index(curr_path_segment)?);
    }
}

fn array_index(segment: &str) -> Result<ClaimPathSegment, FormatterError> {
    segment
        .parse()
        .map(ClaimPathSegment::Index)
        .map_err(|_| FormatterError::CouldNotFormat(format!("`{segment}` is not an array index")))
}

pub(crate) fn claim_path_to_formatted_path(
    claim: &Claim,
    claim_schema: &ClaimSchema,
    claim_mapping: &CredentialSchemaFormatClaimSchema,
) -> Result<String, IssuanceProtocolError> {
    let path = technical_claim_path(claim, claim_schema, claim_mapping)
        .error_while("mapping claim path")?;
    Ok(path.iter().join(NESTED_CLAIM_MARKER_STR))
}

/// Maps credential claims (as shown in credential details) to disclosed keys as formatted in the
/// actual credential.
pub(crate) async fn presented_paths_to_disclosed_keys(
    presented_paths: &[String],
    credential: &Credential,
) -> Result<Vec<String>, ServiceError> {
    let claims = credential.claims()?.as_ref().await?;
    let format = credential.format().as_required_ref().await?;
    let mappings = format.claim_mappings.as_ref().await?;
    let mappings_by_schema_id: HashMap<_, _> = mappings
        .into_iter()
        .map(|m| (m.claim_schema_id, m))
        .collect();

    // credential formatters do not use intermediary claims
    let leafs = paths_to_leafs(presented_paths);
    let mut disclosed_keys = Vec::with_capacity(leafs.len());
    for presented_path in leafs {
        let claim = claims
            .iter()
            .find(|c| c.path == presented_path)
            .ok_or_else(|| {
                ServiceError::MappingError(format!("no claim found for path `{}`", presented_path))
            })?;
        let claim_schema = claim.schema.as_ref().await?;
        let mapping = mappings_by_schema_id.get(&claim_schema.id).ok_or_else(|| {
            ServiceError::MappingError(format!(
                "claim schema `{}` has no mapping for schema format {}",
                claim_schema.id, format.id
            ))
        })?;
        let mapped_path = claim_path_to_formatted_path(claim, &claim_schema, mapping)
            .error_while("mapping claim path")?;
        disclosed_keys.push(mapped_path);
    }
    Ok(disclosed_keys)
}
