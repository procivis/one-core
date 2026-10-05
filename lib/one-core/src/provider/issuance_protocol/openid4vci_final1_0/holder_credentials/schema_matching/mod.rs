#[cfg(test)]
mod test;

use std::collections::{HashMap, HashSet};

use shared_types::{ClaimSchemaId, OrganisationId};
use uuid::Uuid;

use crate::config::core_config::{CoreConfig, DatatypeConfig, DatatypeType};
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin};
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::mapper::credential_schema_claim::add_fallback_translation;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::Credential;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaListQuery};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::model::localized_text::LocalizedTextField;
use crate::model::relation::{OptionalRelatedExt, OptionalRelatedRefExt};
use crate::proto::credential_schema::importer::CredentialSchemaImporter;
use crate::provider::issuance_protocol::IssuanceProtocolError;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::service::credential_schema::dto::CredentialSchemaFilterValue;

async fn find_credential_schemas(
    repository: &dyn CredentialSchemaRepository,
    schema_id: &str,
    display_names: &[(String, String)],
    organisation_id: OrganisationId,
) -> Result<Vec<CredentialSchema>, IssuanceProtocolError> {
    let mut schema_filter =
        CredentialSchemaFilterValue::EcosystemSchemaId(StringMatch::equals(schema_id)).condition();
    if !display_names.is_empty() {
        schema_filter = schema_filter
            | CredentialSchemaFilterValue::DisplayNames(
                display_names
                    .iter()
                    .map(|(language, name)| {
                        (language.to_owned(), StringMatch::equals(name.to_owned()))
                    })
                    .collect(),
            )
            .condition();
    }

    Ok(repository
        .get_credential_schema_list(CredentialSchemaListQuery {
            include_count: false,
            // All candidates are needed so an ecosystem-schema-ID match can be preferred over a
            // display-name match, regardless of repository ordering.
            pagination: None,
            filtering: Some(
                CredentialSchemaFilterValue::OrganisationId(organisation_id).condition()
                    & schema_filter,
            ),
            ..Default::default()
        })
        .await
        .error_while("getting credential schema")?
        .values)
}

#[derive(Debug)]
pub(super) struct CredentialSchemaResolution {
    pub(super) schema: CredentialSchema,
    pub(super) new_format: Option<CredentialSchemaFormat>,
}

pub(super) async fn find_or_import_credential_schema(
    credential_schema_importer: &dyn CredentialSchemaImporter,
    credential_schema_repository: &dyn CredentialSchemaRepository,
    parsed_schema: CredentialSchema,
    parsed_format: &CredentialSchemaFormat,
    organisation_id: OrganisationId,
    config: &CoreConfig,
) -> Result<CredentialSchemaResolution, IssuanceProtocolError> {
    let parsed_display_names = parsed_schema
        .translations
        .as_ref()
        .await?
        .iter()
        .filter(|translation| translation.field == LocalizedTextField::Name)
        .map(|translation| (translation.lang.to_owned(), translation.value.to_owned()))
        .collect::<Vec<_>>();

    let stored_schemas = find_credential_schemas(
        credential_schema_repository,
        &parsed_format.ecosystem_schema_id,
        &parsed_display_names,
        organisation_id,
    )
    .await?;

    if let Some(stored_schema) =
        find_schema_by_ecosystem_schema_id(&stored_schemas, &parsed_format.ecosystem_schema_id)
            .await?
    {
        if let Some(stored_format) = stored_schema
            .formats
            .as_ref()
            .await?
            .iter()
            .find(|format| {
                format.ecosystem_schema_id == parsed_format.ecosystem_schema_id
                    && format.format != parsed_format.format
            })
            .cloned()
        {
            if config
                .format
                .get_type(&stored_format.format)
                .error_while("getting format type")?
                != config
                    .format
                    .get_type(&parsed_format.format)
                    .error_while("getting format type")?
            {
                return Err(IssuanceProtocolError::Failed(format!(
                    "Credential schema conflict: credential schema with id {} has matching schema_id `{}` but different format `{}`",
                    stored_format.id, stored_format.ecosystem_schema_id, stored_format.format
                )));
            }

            tracing::debug!(
                "Found matching existing schema {} with different format `{}` of same type, replacing format `{}`.",
                stored_format.id,
                stored_format.format,
                parsed_format.format
            );
        };

        return Ok(CredentialSchemaResolution {
            schema: stored_schema,
            new_format: None,
        });
    }

    // A display-name match reuses the existing schema only when the new format can be added
    // without colliding with another ecosystem schema ID or with existing claim definitions.
    for mut stored_schema in stored_schemas {
        let stored_formats = stored_schema.formats.as_ref().await?.to_owned();
        if stored_formats
            .iter()
            // It is already known here that the ecosystem schema ID does not match, otherwise this
            // candidate would not have been in the list of display-name matches.
            .any(|format| format.format == parsed_format.format)
        {
            continue;
        }

        let Some(new_format) = prepare_display_name_matched_format(
            &stored_schema,
            &parsed_schema,
            parsed_format,
            &config.datatype,
        )
        .await?
        else {
            continue;
        };
        stored_schema
            .formats
            .as_mut()
            .await?
            .push(new_format.clone());

        return Ok(CredentialSchemaResolution {
            schema: stored_schema,
            new_format: Some(new_format),
        });
    }

    match credential_schema_importer
        .import_credential_schema(parsed_schema)
        .await
    {
        Ok(schema) => {
            return Ok(CredentialSchemaResolution {
                schema,
                new_format: None,
            });
        }
        Err(error) if error.error_code() == ErrorCode::BR_0007 => {
            tracing::debug!("Conflicting schema detected during parsing, refetching");
        }
        Err(e) => {
            return Err(IssuanceProtocolError::Failed(e.to_string()));
        }
    };

    // Another request may have imported the same ecosystem schema concurrently -> refetch it.
    let stored_schemas = find_credential_schemas(
        credential_schema_repository,
        &parsed_format.ecosystem_schema_id,
        &[],
        organisation_id,
    )
    .await?;
    let stored_schema =
        find_schema_by_ecosystem_schema_id(&stored_schemas, &parsed_format.ecosystem_schema_id)
            .await?
            .ok_or(IssuanceProtocolError::Failed(
                "Credential schema not found".to_string(),
            ))?;
    Ok(CredentialSchemaResolution {
        schema: stored_schema,
        new_format: None,
    })
}

async fn find_schema_by_ecosystem_schema_id(
    schemas: &[CredentialSchema],
    ecosystem_schema_id: &str,
) -> Result<Option<CredentialSchema>, IssuanceProtocolError> {
    for schema in schemas {
        if schema
            .formats
            .as_ref()
            .await?
            .iter()
            .any(|format| format.ecosystem_schema_id == ecosystem_schema_id)
        {
            return Ok(Some(schema.clone()));
        }
    }
    Ok(None)
}

/// Return missing claim paths required by the schema or this issuer's metadata.
///
/// # Arguments
///
/// * `schema` - The parsed or reused credential schema whose `required` flags are validated.
/// * `credential` - The issued claims and current format mappings. Their claim schema IDs and
///   claim paths must already be aligned with `schema`.
/// * `mandatory_claim_ids` - Claim schema IDs from `schema` that this issuer marks as mandatory.
///   These add validation requirements without changing the schema's `required` flags. An empty
///   slice checks only the schema's requirements.
///
/// Only non-metadata claims mapped to the credential's current format are checked. Required
/// children are checked under each present parent, including every concrete array element.
pub(super) async fn missing_required_claims(
    schema: &CredentialSchema,
    credential: &Credential,
    mandatory_claim_ids: &[ClaimSchemaId],
) -> Result<Vec<String>, IssuanceProtocolError> {
    let format = credential.format().as_required_ref().await?;
    let credential_mappings = format.claim_mappings.as_ref().await?;
    let claims = credential.claims().as_ref().await?;
    let format_schema_ids = credential_mappings
        .iter()
        .map(|mapping| mapping.claim_schema_id)
        .collect::<HashSet<_>>();
    let mut issued_paths_by_schema_id: HashMap<ClaimSchemaId, HashSet<&str>> = HashMap::new();
    for claim in claims.iter() {
        issued_paths_by_schema_id
            .entry(claim.schema.id())
            .or_default()
            .insert(&claim.path);
    }

    let claim_schemas = schema.claim_schemas.as_ref().await?;
    let claim_schemas_by_key = claim_schemas
        .iter()
        .map(|claim_schema| (claim_schema.key.as_str(), claim_schema))
        .collect::<HashMap<_, _>>();
    let mut missing = vec![];
    for claim_schema in claim_schemas.iter() {
        if (!claim_schema.required && !mandatory_claim_ids.contains(&claim_schema.id))
            || claim_schema.metadata
            || !format_schema_ids.contains(&claim_schema.id)
        {
            continue;
        }
        let issued_paths = issued_paths_by_schema_id.get(&claim_schema.id);
        for expected_path in expected_required_claim_paths(
            claim_schema,
            &claim_schemas_by_key,
            &issued_paths_by_schema_id,
        )? {
            if !issued_paths.is_some_and(|paths| paths.contains(expected_path.as_str())) {
                missing.push(expected_path);
            }
        }
    }
    missing.sort();
    missing.dedup();
    Ok(missing)
}

/// Return the concrete claim paths required under present parents. A root schema yields its own
/// key. A required child of an absent parent yields no paths; a missing required parent is checked
/// separately. An array parent expands only the element paths already present in issued claims.
/// A missing ancestor schema definition is an error.
fn expected_required_claim_paths(
    claim_schema: &ClaimSchema,
    claim_schemas_by_key: &HashMap<&str, &ClaimSchema>,
    issued_paths_by_schema_id: &HashMap<ClaimSchemaId, HashSet<&str>>,
) -> Result<Vec<String>, IssuanceProtocolError> {
    let segments = claim_schema
        .key
        .split(NESTED_CLAIM_MARKER)
        .collect::<Vec<_>>();
    let Some((leaf, ancestors)) = segments.split_last() else {
        return Ok(vec![]);
    };
    let mut ancestor_schema_key = String::new();
    let mut concrete_parent_paths = vec![String::new()];
    for segment in ancestors {
        if !ancestor_schema_key.is_empty() {
            ancestor_schema_key.push(NESTED_CLAIM_MARKER);
        }
        ancestor_schema_key.push_str(segment);
        let parent_schema = claim_schemas_by_key
            .get(ancestor_schema_key.as_str())
            .ok_or_else(|| {
                IssuanceProtocolError::Failed(format!(
                    "Malformed credential schema: claim `{}` is missing ancestor `{}`",
                    claim_schema.key, ancestor_schema_key
                ))
            })?;
        let Some(parent_claim_paths) = issued_paths_by_schema_id.get(&parent_schema.id) else {
            concrete_parent_paths.clear();
            continue;
        };
        let mut next_parent_paths = vec![];
        for parent_path in concrete_parent_paths {
            let property_path = if parent_path.is_empty() {
                (*segment).to_string()
            } else {
                format!("{parent_path}{NESTED_CLAIM_MARKER}{segment}")
            };
            if parent_schema.array {
                for array_element_path in parent_claim_paths {
                    // An issued array element is a direct indexed child, such as `degrees/0`.
                    let Some(index) = array_element_path
                        .strip_prefix(&property_path)
                        .and_then(|suffix| suffix.strip_prefix(NESTED_CLAIM_MARKER))
                    else {
                        continue;
                    };
                    if index.parse::<usize>().is_ok() {
                        next_parent_paths.push((*array_element_path).to_string());
                    }
                }
            } else if parent_claim_paths.contains(property_path.as_str()) {
                next_parent_paths.push(property_path);
            }
        }
        concrete_parent_paths = next_parent_paths;
    }
    Ok(concrete_parent_paths
        .into_iter()
        .map(|parent_path| {
            if parent_path.is_empty() {
                (*leaf).to_string()
            } else {
                format!("{parent_path}{NESTED_CLAIM_MARKER}{leaf}")
            }
        })
        .collect())
}

async fn prepare_display_name_matched_format(
    stored_schema: &CredentialSchema,
    parsed_schema: &CredentialSchema,
    parsed_format: &CredentialSchemaFormat,
    datatype_config: &DatatypeConfig,
) -> Result<Option<CredentialSchemaFormat>, IssuanceProtocolError> {
    let stored_claim_schemas = stored_schema.claim_schemas.as_ref().await?;
    let parsed_claim_schemas = parsed_schema.claim_schemas.as_ref().await?;
    let parsed_mappings = parsed_format.claim_mappings.as_ref().await?;

    // Stored claims paired with the localized names used for semantic matching.
    let mut stored_claims_with_display_names = Vec::with_capacity(stored_claim_schemas.len());
    for stored_claim_schema in stored_claim_schemas.iter() {
        stored_claims_with_display_names.push((
            stored_claim_schema,
            claim_display_names(stored_claim_schema).await?,
        ));
    }

    let mut parsed_claim_schemas = parsed_claim_schemas.iter().collect::<Vec<_>>();
    // sort by key, so parents are ordered before their children
    parsed_claim_schemas.sort_by(|left, right| left.key.cmp(&right.key));

    // New-format mappings redirected to matched stored claim schemas.
    let mut reusable_mappings = vec![];
    // Stored claims already paired, enforcing one-to-one matching.
    let mut matched_stored_claim_schema_ids = HashSet::new();
    // Parsed keys mapped to stored keys; `None` marks an entirely new subtree.
    let mut parsed_to_stored_keys = HashMap::<String, Option<String>>::new();
    for parsed_claim_schema in parsed_claim_schemas {
        let parsed_mapping = parsed_mappings
            .iter()
            .find(|mapping| mapping.claim_schema_id == parsed_claim_schema.id)
            .ok_or(IssuanceProtocolError::Failed(format!(
                "missing mapping for claim schema `{}`",
                parsed_claim_schema.key
            )))?;

        let stored_parent_key =
            if let Some(parsed_parent_key) = claim_parent_key(parsed_claim_schema) {
                let Some(stored_parent_key) = parsed_to_stored_keys.get(parsed_parent_key) else {
                    // The hierarchy is incomplete, so this schema cannot be matched conservatively.
                    return Ok(None);
                };
                let Some(stored_parent_key) = stored_parent_key else {
                    // The parsed parent is new, so this child must be new as well.
                    parsed_to_stored_keys.insert(parsed_claim_schema.key.to_owned(), None);
                    continue;
                };
                Some(stored_parent_key.to_owned())
            } else {
                None
            };

        let parsed_display_names = claim_display_names(parsed_claim_schema).await?;
        let mut matching_stored_claims = stored_claims_with_display_names.iter().filter(
            |(stored_claim_schema, stored_display_names)| {
                if parsed_claim_schema.metadata {
                    stored_claim_schema.metadata
                        && stored_claim_schema.key == parsed_claim_schema.key
                } else {
                    !parsed_display_names.is_disjoint(stored_display_names)
                        && claim_parent_key(stored_claim_schema) == stored_parent_key.as_deref()
                }
            },
        );
        let Some((stored_claim_schema, _)) = matching_stored_claims.next() else {
            // This is a new, non-conflicting claim. Alignment adds it and its mapping later.
            parsed_to_stored_keys.insert(parsed_claim_schema.key.to_owned(), None);
            continue;
        };
        let has_multiple_matches = matching_stored_claims.next().is_some();
        let was_previously_matched =
            !matched_stored_claim_schema_ids.insert(stored_claim_schema.id);
        if has_multiple_matches || was_previously_matched {
            // Claim display names do not identify a unique one-to-one mapping.
            return Ok(None);
        }
        if !claim_schemas_are_compatible(parsed_claim_schema, stored_claim_schema, datatype_config)?
        {
            return Ok(None);
        }
        parsed_to_stored_keys.insert(
            parsed_claim_schema.key.to_owned(),
            Some(stored_claim_schema.key.to_owned()),
        );

        let mut reusable_mapping = parsed_mapping.to_owned();
        reusable_mapping.credential_schema_format_id = parsed_format.id;
        reusable_mapping.claim_schema_id = stored_claim_schema.id;
        reusable_mappings.push(reusable_mapping);
    }

    if stored_claim_schemas.iter().any(|stored_claim_schema| {
        stored_claim_schema.required
            && !stored_claim_schema.metadata
            && !matched_stored_claim_schema_ids.contains(&stored_claim_schema.id)
    }) {
        return Ok(None);
    }

    let mut new_format = parsed_format.to_owned();
    new_format.credential_schema_id = stored_schema.id;
    new_format.claim_mappings = reusable_mappings.into();
    Ok(Some(new_format))
}

fn claim_parent_key(claim_schema: &ClaimSchema) -> Option<&str> {
    claim_schema
        .key
        .rsplit_once(NESTED_CLAIM_MARKER)
        .map(|(parent, _)| parent)
}

async fn claim_display_names(
    claim_schema: &ClaimSchema,
) -> Result<HashSet<(String, String)>, IssuanceProtocolError> {
    Ok(claim_schema
        .translations
        .as_ref()
        .await?
        .iter()
        .filter(|translation| translation.field == LocalizedTextField::Name)
        .map(|translation| (translation.lang.to_owned(), translation.value.to_owned()))
        .collect())
}

fn claim_schemas_are_compatible(
    parsed: &ClaimSchema,
    stored: &ClaimSchema,
    datatype_config: &DatatypeConfig,
) -> Result<bool, IssuanceProtocolError> {
    if parsed.data_type != stored.data_type {
        let parsed_type = datatype_config
            .get_type(&parsed.data_type)
            .error_while("getting parsed claim datatype")?;
        let stored_type = datatype_config
            .get_type(&stored.data_type)
            .error_while("getting stored claim datatype")?;
        if (parsed_type == DatatypeType::Object) != (stored_type == DatatypeType::Object) {
            return Ok(false);
        }
        // This is just a warning because the data type detection is just a heuristic.
        tracing::warn!(
            "detected data type mismatch on claim `{}`: expected `{}` but parsed `{}`",
            parsed.key,
            stored.data_type,
            parsed.data_type
        );
    }
    Ok(parsed.array == stored.array && parsed.metadata == stored.metadata)
}

pub(super) struct AlignmentUpdate {
    pub(super) new_claim_schemas: Vec<ClaimSchema>,
    pub(super) new_mappings: Vec<CredentialSchemaFormatClaimSchema>,
}

pub(super) async fn align_format_claim_schemas_and_mappings(
    stored_schema: &mut CredentialSchema,
    credential: &mut Credential,
    default_language: &str,
    format_id: Option<shared_types::CredentialSchemaFormatId>,
) -> Result<AlignmentUpdate, IssuanceProtocolError> {
    let Credential::Generic {
        claims,
        common,
        format,
        ..
    } = credential
    else {
        return Err(IssuanceProtocolError::Failed(
            "Expected a holder credential".into(),
        ));
    };
    let mut claims = claims.as_mut().await?;
    claims.sort_by_key(|c| c.path.clone());

    let mut parsed_claim_schemas = {
        let parsed_schema = common.schema.as_ref().await?;
        parsed_schema.claim_schemas.as_ref().await?.to_owned()
    };
    parsed_claim_schemas.sort_by_key(|s| s.key.clone());

    let (parsed_format, parsed_mappings) = {
        let parsed_format = format.as_required_ref().await?;
        let mappings = parsed_format.claim_mappings.as_ref().await?.to_owned();
        (parsed_format.format.clone(), mappings)
    };

    let mut new_claim_schemas = vec![];
    let mut new_mappings = vec![];
    let mut stored_format = {
        let stored_formats = stored_schema.formats.as_ref().await?;
        stored_formats
            .iter()
            .find(|format| {
                format.format == parsed_format && format_id.is_none_or(|id| format.id == id)
            })
            .cloned()
            .ok_or(IssuanceProtocolError::Failed(format!(
                "No matching stored format found for `{parsed_format}`"
            )))?
    };
    let stored_format_id = stored_format.id;
    {
        let mut stored_mappings = stored_format.claim_mappings.as_mut().await?;
        let mut stored_claim_schemas = stored_schema.claim_schemas.as_mut().await?;
        // parsed key -> stored key
        let mut key_translations = HashMap::new();
        // parsed path -> stored path
        let mut claim_path_translations = HashMap::new();

        // iterate sorted by key -> parent schemas before their children
        for mut parsed_claim_schema in parsed_claim_schemas {
            let parsed_mapping = parsed_mappings
                .iter()
                .find(|mapping| mapping.claim_schema_id == parsed_claim_schema.id)
                .ok_or(IssuanceProtocolError::Failed(format!(
                    "missing mapping for claim schema `{}`",
                    parsed_claim_schema.key
                )))?;
            let stored_claim_schema_id =
                find_matching_stored_schema(parsed_mapping, &stored_mappings);

            if let Some(stored_claim_schema_id) = stored_claim_schema_id {
                let known_claim_schema = stored_claim_schemas
                    .iter()
                    .find(|schema| schema.id == stored_claim_schema_id)
                    .ok_or(IssuanceProtocolError::Failed(format!(
                        "stored claim schema {} not found",
                        stored_claim_schema_id
                    )))?;
                key_translations.insert(
                    parsed_claim_schema.key.clone(),
                    known_claim_schema.key.clone(),
                );
                relink_claims(
                    &mut claims,
                    parsed_claim_schema.id,
                    known_claim_schema,
                    &mut claim_path_translations,
                )
                .await?;
                continue;
            }

            let parsed_claim_schema_key = parsed_claim_schema.key.to_owned();
            let candidate_key = if let Some((parent_key, new_child_key)) =
                parsed_claim_schema_key.rsplit_once(NESTED_CLAIM_MARKER)
            {
                // Due to ordering, parent key must have been processed already.
                let parent_key =
                    key_translations
                        .get(parent_key)
                        .ok_or(IssuanceProtocolError::Failed(format!(
                            "failed to find key translation for parent claim schema for key `{}`",
                            parent_key
                        )))?;
                format!("{parent_key}{NESTED_CLAIM_MARKER}{new_child_key}")
            } else {
                parsed_claim_schema_key.to_owned()
            };
            let mapped_key =
                unique_claim_schema_key(&candidate_key, &stored_claim_schemas, &new_claim_schemas);
            key_translations.insert(parsed_claim_schema_key.to_owned(), mapped_key.to_owned());

            if parsed_claim_schema_key != mapped_key {
                parsed_claim_schema.key = mapped_key;
                relink_claims(
                    &mut claims,
                    parsed_claim_schema.id,
                    &parsed_claim_schema,
                    &mut claim_path_translations,
                )
                .await?;
            } else {
                // Child claims look up their parent path here, so unchanged paths (including
                // array items) must also be registered.
                for claim in claims
                    .iter()
                    .filter(|claim| claim.schema.id() == parsed_claim_schema.id)
                {
                    claim_path_translations.insert(claim.path.clone(), claim.path.clone());
                }
            }

            let mut new_mapping = parsed_mapping.clone();
            new_mapping.credential_schema_format_id = stored_format_id;
            stored_mappings.push(new_mapping.clone());
            new_mappings.push(new_mapping);
            new_claim_schemas.push(
                add_fallback_translation(parsed_claim_schema, default_language)
                    .await
                    .error_while("adding fallback claim translation")?,
            );
        }
        stored_claim_schemas.extend(new_claim_schemas.clone());
    }

    *format = Some(stored_format.into());
    common.schema = stored_schema.clone().into();
    Ok(AlignmentUpdate {
        new_claim_schemas,
        new_mappings,
    })
}

/// Link all claims currently linked to `claim_schema_id` to `new_claim_schema`, while rewriting
/// the path to match the new key.
async fn relink_claims(
    claims: &mut [Claim],
    claim_schema_id: ClaimSchemaId,
    new_claim_schema: &ClaimSchema,
    claim_path_translations: &mut HashMap<String, String>,
) -> Result<(), IssuanceProtocolError> {
    for claim in claims
        .iter_mut()
        .filter(|claim| claim.schema.id() == claim_schema_id)
    {
        let (data_type, key) = {
            let cs = claim.schema.as_ref().await?;
            (cs.data_type.to_owned(), cs.key.to_owned())
        };
        if data_type != new_claim_schema.data_type {
            // This is just a warning because the data type detection is just a heuristic
            tracing::warn!(
                "detected data type mismatch on claim `{}`: expected `{}` but parsed `{}`",
                claim.path,
                new_claim_schema.data_type,
                data_type
            );
        }
        let mapped_path = remap_claim_path(
            claim.path.as_str(),
            claim_path_translations,
            &key,
            new_claim_schema,
        )?;
        claim.path = mapped_path;
        claim.schema = new_claim_schema.to_owned().into();
    }
    Ok(())
}

fn unique_claim_schema_key(
    candidate: &str,
    stored_claim_schemas: &[ClaimSchema],
    new_claim_schemas: &[ClaimSchema],
) -> String {
    let key_exists = |key: &str| {
        stored_claim_schemas
            .iter()
            .chain(new_claim_schemas)
            .any(|claim_schema| claim_schema.key == key)
    };
    if !key_exists(candidate) {
        return candidate.to_owned();
    }
    format!("{candidate}_{}", Uuid::new_v4())
}

fn find_matching_stored_schema(
    parsed_mapping: &CredentialSchemaFormatClaimSchema,
    stored_mappings: &[CredentialSchemaFormatClaimSchema],
) -> Option<ClaimSchemaId> {
    stored_mappings
        .iter()
        .find(|m| {
            m.technical_key == parsed_mapping.technical_key
                && m.namespace == parsed_mapping.namespace
        })
        .map(|m| m.claim_schema_id)
}

fn remap_claim_path(
    claim_path: &str,
    claim_path_translations: &mut HashMap<String, String>,
    parsed_schema_key: &str,
    stored_claim_schema: &ClaimSchema,
) -> Result<String, IssuanceProtocolError> {
    if claim_path == parsed_schema_key {
        // adjust path to match schema
        claim_path_translations.insert(
            parsed_schema_key.to_string(),
            stored_claim_schema.key.clone(),
        );
        return Ok(stored_claim_schema.key.clone());
    } else if let Some((parent_claim, child)) = claim_path.rsplit_once(NESTED_CLAIM_MARKER) {
        let parent_key = claim_path_translations.get(parent_claim).ok_or(IssuanceProtocolError::Failed(format!(
            "claim path `{parent_claim}` not found in translated claim paths for parsed claim with path `{claim_path}`" )))?;
        let new_path = if parsed_schema_key.ends_with(&format!("{NESTED_CLAIM_MARKER}{child}")) {
            // normal nesting
            let (_, cs_leaf) = stored_claim_schema
                .key
                .rsplit_once(NESTED_CLAIM_MARKER)
                .ok_or(IssuanceProtocolError::Failed(format!(
                    "expected claim schema path `{}` to contain nesting",
                    stored_claim_schema.key
                )))?;
            format!("{parent_key}{NESTED_CLAIM_MARKER}{cs_leaf}")
        } else {
            // `child` is an array index, which is not represented in the technical key.
            // Preserve the index, just map to the parent key.
            format!("{parent_key}{NESTED_CLAIM_MARKER}{child}")
        };
        claim_path_translations.insert(claim_path.to_string(), new_path.clone());
        return Ok(new_path);
    }
    Err(IssuanceProtocolError::Failed(format!(
        "Failed to map claim path `{claim_path}` to claim schema {} with parsed schema key `{parsed_schema_key}`",
        stored_claim_schema.id
    )))
}
