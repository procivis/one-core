use std::collections::VecDeque;

use itertools::Itertools;
use regex::Regex;
use url::Url;

use super::dto::CredentialRequestClaimDTO;
use super::error::CredentialServiceError;
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, DatatypeType, IdentifierType};
use crate::config::validator::datatype::{DatatypeValidationError, validate_datatype_value};
use crate::config::validator::protocol::validate_protocol_type;
use crate::error::ContextWithErrorCode;
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::mapper::exchange::get_issuance_param_redirect_uri;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::credential_schema::CredentialSchema;
use crate::proto::notification_scheduler::NotificationScheduler;
use crate::provider::credential_formatter::model::FormatterCapabilities;
use crate::provider::issuance_protocol::model::CommonParams;

pub(crate) fn throw_if_credential_state_eq(
    credential: &Credential,
    state: CredentialStateEnum,
) -> Result<(), CredentialServiceError> {
    let current_state = credential.state;
    if current_state == state {
        return Err(CredentialServiceError::InvalidState(
            current_state.to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_create_request(
    exchange: &str,
    claims: &[CredentialRequestClaimDTO],
    schema: &CredentialSchema,
    formatter_capabilities: &FormatterCapabilities,
    config: &CoreConfig,
) -> Result<(), CredentialServiceError> {
    validate_protocol_type(exchange, &config.issuance_protocol)
        .error_while("validating protocol type")?;
    validate_format_and_exchange_protocol_compatibility(exchange, formatter_capabilities, config)?;

    // ONE-843: cannot create credential based on deleted schema
    if schema.deleted_at.is_some() {
        return Err(CredentialServiceError::MissingCredentialSchema(schema.id));
    }

    let claim_schemas =
        &schema
            .claim_schemas
            .as_ref()
            .ok_or(CredentialServiceError::MappingError(
                "claim_schemas is None".to_string(),
            ))?;

    let mut paths: Vec<&str> = vec![];

    // check all claims have valid content
    for claim in claims {
        let claim_schema_id = claim.claim_schema_id;
        let schema = claim_schemas
            .iter()
            .find(|schema| schema.id == claim_schema_id);

        match schema {
            None => return Err(CredentialServiceError::MissingClaimSchema(claim_schema_id)),
            Some(schema) => {
                validate_path(claim, schema, claim_schemas)?;
                validate_array_value_non_empty(claim, schema)?;
                validate_object_value_non_empty(claim, schema)?;
                validate_value_non_empty(claim)?;

                validate_datatype_value(&claim.value, &schema.data_type, &config.datatype)
                    .map_err(|err| CredentialServiceError::InvalidDatatype {
                        value: claim.value.clone(),
                        datatype: schema.data_type.clone(),
                        source: err,
                    })?;

                paths.push(claim.path.as_str());
            }
        }
    }

    validate_continuity(&paths, claim_schemas)?;

    let claim_schemas =
        adapt_required_state_based_on_claim_presence(claim_schemas, claims, config)?;

    // check all required claims are present
    claim_schemas
        .iter()
        .map(|claim_schema| {
            let datatype = &claim_schema.data_type;
            let config = config
                .datatype
                .get_fields(datatype)
                .error_while("getting datatype config")?;

            if claim_schema.required
                && !claim_schema.metadata // Clients are not expected to submit _metadata_ claims.
                && config.r#type != DatatypeType::Object
            {
                claims
                    .iter()
                    .find(|claim| claim.claim_schema_id == claim_schema.id)
                    .ok_or(CredentialServiceError::MissingClaimSchema(claim_schema.id))?;
            }
            Ok(())
        })
        .collect::<Result<Vec<_>, CredentialServiceError>>()?;

    Ok(())
}

pub(super) fn validate_redirect_uri(
    exchange: &str,
    redirect_uri: Option<&str>,
    config: &CoreConfig,
) -> Result<(), CredentialServiceError> {
    let params = get_issuance_param_redirect_uri(config, exchange)
        .error_while("getting redirect_uri config")?;

    if let Some(redirect_uri) = redirect_uri {
        if !params.enabled {
            return Err(CredentialServiceError::InvalidRedirectUri);
        }

        let url =
            Url::parse(redirect_uri).map_err(|_| CredentialServiceError::InvalidRedirectUri)?;

        if !params.allowed_schemes.contains(&url.scheme().to_string()) {
            return Err(CredentialServiceError::InvalidRedirectUri);
        }
    }

    Ok(())
}

pub(super) fn validate_webhook_url(
    url: Option<&String>,
    issuance_protocol: &str,
    config: &CoreConfig,
    notification_scheduler: &dyn NotificationScheduler,
) -> Result<(), CredentialServiceError> {
    let Some(url) = url else {
        return Ok(());
    };

    let params: CommonParams = config
        .issuance_protocol
        .get(issuance_protocol)
        .error_while("getting protocol config")?;

    let Some(task_id) = params.webhook_task else {
        return Err(CredentialServiceError::NotificationsNotAllowed {
            protocol: issuance_protocol.to_string(),
        });
    };

    Ok(notification_scheduler
        .validate_url(url, &task_id)
        .error_while("validating webhook URL")?)
}

struct PathNode {
    pub key: Option<String>,
    pub subnodes: Vec<PathNode>,
}

impl PathNode {
    fn insert(&mut self, path: &str) -> Result<(), CredentialServiceError> {
        let (first, rest) = get_first_path_element(path);

        if rest.is_empty() {
            self.subnodes.push(PathNode {
                key: Some(first.to_string()),
                subnodes: vec![],
            });
        } else {
            match self
                .subnodes
                .iter_mut()
                .find(|subnode| subnode.key.as_ref().is_some_and(|key| key == first))
            {
                None => {
                    self.subnodes.push(PathNode {
                        key: Some(first.to_string()),
                        subnodes: vec![],
                    });
                    let last =
                        self.subnodes
                            .last_mut()
                            .ok_or(CredentialServiceError::MappingError(
                                "subnodes is empty".to_string(),
                            ))?;
                    last.insert(rest)?;
                }
                Some(value) => {
                    value.insert(rest)?;
                }
            }
        }

        Ok(())
    }

    fn check_continuity(
        &self,
        array_claim_paths: &Option<Regex>,
        parent_path: Option<&String>,
    ) -> Result<(), CredentialServiceError> {
        let subkeys = self
            .subnodes
            .iter()
            .filter_map(|subnode| subnode.key.as_ref())
            .collect::<Vec<_>>();
        if subkeys.is_empty() {
            return Ok(());
        }

        let key_path = match parent_path {
            None => self.key.to_owned(),
            Some(parent) => {
                let key = self
                    .key
                    .as_ref()
                    .ok_or(CredentialServiceError::MappingError(format!(
                        "Missing subclaim key under {parent}"
                    )))?;
                Some(format!("{parent}{NESTED_CLAIM_MARKER}{key}"))
            }
        };

        if let (Some(key), Some(array_claim_paths)) = (&key_path, &array_claim_paths) {
            let is_array = array_claim_paths.is_match(key);
            if is_array {
                if subkeys.first().is_some_and(|key| *key != "0") {
                    return Err(CredentialServiceError::MappingError(
                        "Array indexes need to start at 0".to_string(),
                    ));
                }

                let indexes = subkeys
                    .iter()
                    .map(|index| {
                        index.parse::<u64>().map_err(|e| {
                            ConfigValidationError::DatatypeValidation(
                                DatatypeValidationError::IndexParseFailure(e),
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .error_while("validating array path")?;

                let continuous = indexes
                    .iter()
                    .tuple_windows()
                    .all(|(i1, i2)| i1 < i2 && i2 - i1 == 1);
                if !continuous {
                    return Err(CredentialServiceError::MappingError(
                        "indexes are not continuous".to_string(),
                    ));
                }
            }
        }

        self.subnodes.iter().try_for_each(|subnode| {
            subnode.check_continuity(array_claim_paths, key_path.as_ref())
        })?;

        Ok(())
    }
}

fn get_first_path_element(path: &str) -> (&str, &str) {
    match path.find(NESTED_CLAIM_MARKER) {
        None => (path, ""),
        Some(value) => (&path[0..value], &path[value + 1..]),
    }
}

fn validate_continuity(
    paths: &[&str],
    claim_schemas: &[ClaimSchema],
) -> Result<(), CredentialServiceError> {
    let mut tree = PathNode {
        key: None,
        subnodes: vec![],
    };

    paths.iter().try_for_each(|path| tree.insert(path))?;

    let array_paths = claim_schemas
        .iter()
        .filter_map(|schema| {
            if schema.array {
                Some(schema.key.as_str())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let array_claim_paths = array_paths_to_claim_paths_regex(&array_paths)?;

    tree.check_continuity(&array_claim_paths, None)?;

    Ok(())
}

fn validate_value_non_empty(
    claim: &CredentialRequestClaimDTO,
) -> Result<(), CredentialServiceError> {
    if claim.value.is_empty() {
        return Err(CredentialServiceError::EmptyValueNotAllowed);
    }

    Ok(())
}

fn validate_object_value_non_empty(
    claim: &CredentialRequestClaimDTO,
    schema: &ClaimSchema,
) -> Result<(), CredentialServiceError> {
    if claim.path.contains(NESTED_CLAIM_MARKER) && !schema.array && claim.value.is_empty() {
        return Err(CredentialServiceError::EmptyObjectNotAllowed);
    }

    Ok(())
}

fn validate_array_value_non_empty(
    claim: &CredentialRequestClaimDTO,
    schema: &ClaimSchema,
) -> Result<(), CredentialServiceError> {
    if claim.value.is_empty() && schema.array {
        return Err(CredentialServiceError::EmptyArrayValueNotAllowed);
    }

    Ok(())
}

/// Converts set of array claim schema keys into a regex matching claim path
fn array_paths_to_claim_paths_regex(
    array_paths: &[&str],
) -> Result<Option<Regex>, CredentialServiceError> {
    let mut patterns = vec![];

    let mut to_be_processed = array_paths
        .iter()
        .sorted()
        .map(|s| regex::escape(s))
        .collect::<VecDeque<_>>();
    while let Some(first) = to_be_processed.pop_front() {
        let prefix = format!("{first}{NESTED_CLAIM_MARKER}");
        patterns.push(first);
        to_be_processed.iter_mut().for_each(|item| {
            if item.starts_with(&prefix) {
                *item = format!(
                    "{prefix}\\d+{NESTED_CLAIM_MARKER}{}",
                    item.split_at(prefix.len()).1
                );
            }
        })
    }

    if patterns.is_empty() {
        return Ok(None);
    }

    Ok(Some(
        Regex::new(&format!("^({})$", patterns.join("|")))
            .map_err(|e| CredentialServiceError::MappingError(e.to_string()))?,
    ))
}

fn get_nth_segment_of_key(key: &str, index: usize) -> Result<&str, CredentialServiceError> {
    key.split(NESTED_CLAIM_MARKER)
        .nth(index)
        .ok_or(CredentialServiceError::MappingError(
            "wrong segment index".to_string(),
        ))
}

fn validate_path(
    claim: &CredentialRequestClaimDTO,
    schema: &ClaimSchema,
    claim_schemas: &[ClaimSchema],
) -> Result<(), CredentialServiceError> {
    let related_claim_schemas = resolve_parent_claim_schemas(schema, claim_schemas)?;

    let segments = claim.path.split(NESTED_CLAIM_MARKER).collect::<Vec<&str>>();
    let expected_segments = related_claim_schemas
        .iter()
        .map(|schema| if schema.array { 2 } else { 1 })
        .sum::<usize>();

    if segments.len() != expected_segments {
        return Err(CredentialServiceError::MappingError(format!(
            "invalid segments [{} vs {expected_segments}]",
            segments.len()
        )));
    }

    let mut schema_index = 0;
    let mut segment_index = 0;
    loop {
        let related_schema = related_claim_schemas.get(schema_index).ok_or_else(|| {
            CredentialServiceError::MappingError(format!(
                "Could not find schema index: {schema_index}"
            ))
        })?;
        let key_segment = get_nth_segment_of_key(&related_schema.key, schema_index)?;
        let segment = segments.get(segment_index).ok_or_else(|| {
            CredentialServiceError::MappingError(format!(
                "Could not find segment index: {segment_index}"
            ))
        })?;
        if key_segment != *segment {
            return Err(CredentialServiceError::MappingError(format!(
                "expected: {key_segment}, found: {segment}"
            )));
        }

        if related_schema.array {
            segment_index += 1;
            let segment = segments.get(segment_index).ok_or_else(|| {
                CredentialServiceError::MappingError(format!(
                    "Could not find segment index: {segment_index}"
                ))
            })?;
            segment
                .parse::<u64>()
                .map_err(|e| {
                    ConfigValidationError::DatatypeValidation(
                        DatatypeValidationError::IndexParseFailure(e),
                    )
                })
                .error_while("validating array path")?;
        }

        segment_index += 1;
        schema_index += 1;

        if schema_index >= related_claim_schemas.len() {
            break;
        }
    }

    Ok(())
}

fn adapt_required_state_based_on_claim_presence(
    claim_schemas: &[ClaimSchema],
    claims: &[CredentialRequestClaimDTO],
    config: &CoreConfig,
) -> Result<Vec<ClaimSchema>, CredentialServiceError> {
    let claims_with_names = claims
        .iter()
        .map(|claim| {
            let matching_claim_schema = claim_schemas
                .iter()
                .find(|claim_schema| claim_schema.id == claim.claim_schema_id)
                .ok_or(CredentialServiceError::MissingClaimSchema(
                    claim.claim_schema_id,
                ))?;
            Ok((claim, matching_claim_schema.key.to_owned()))
        })
        .collect::<Result<Vec<(&CredentialRequestClaimDTO, String)>, CredentialServiceError>>()?;

    let mut result = claim_schemas.to_vec();
    claim_schemas.iter().try_for_each(|claim_schema| {
        let prefix = format!("{}/", claim_schema.key);

        let is_parent_schema_of_provided_claim = claims_with_names
            .iter()
            .any(|(_, claim_name)| claim_name.starts_with(&prefix));

        let is_object = config
            .datatype
            .get_fields(&claim_schema.data_type)
            .error_while("getting datatype config")?
            .r#type
            == DatatypeType::Object;

        let should_make_all_child_claims_non_required =
            !is_parent_schema_of_provided_claim && is_object && !claim_schema.required;

        if should_make_all_child_claims_non_required {
            result.iter_mut().for_each(|result_schema| {
                if result_schema.key.starts_with(&prefix) {
                    result_schema.required = false;
                }
            });
        }

        Ok::<(), CredentialServiceError>(())
    })?;

    Ok(result)
}

fn validate_format_and_exchange_protocol_compatibility(
    exchange: &str,
    formatter_capabilities: &FormatterCapabilities,
    config: &CoreConfig,
) -> Result<(), CredentialServiceError> {
    let exchange_protocol = config
        .issuance_protocol
        .get_fields(exchange)
        .error_while("getting protocol config")?;

    if !formatter_capabilities
        .issuance_exchange_protocols
        .contains(&exchange_protocol.r#type)
    {
        return Err(CredentialServiceError::IncompatibleIssuanceExchangeProtocol);
    }

    Ok(())
}

pub(crate) fn validate_format_and_did_method_compatibility(
    did_method: &str,
    formatter_capabilities: &FormatterCapabilities,
    config: &CoreConfig,
) -> Result<(), CredentialServiceError> {
    let did_method_type = config
        .did
        .get_fields(did_method)
        .error_while("getting did method config")?
        .r#type;

    if !formatter_capabilities
        .issuance_did_methods
        .contains(&did_method_type)
    {
        return Err(CredentialServiceError::IncompatibleIssuanceDidMethod);
    }

    if !formatter_capabilities
        .issuance_identifier_types
        .contains(&IdentifierType::Did)
    {
        return Err(CredentialServiceError::IncompatibleIssuanceIdentifier);
    }

    Ok(())
}

fn resolve_parent_claim_schemas<'a>(
    schema: &'a ClaimSchema,
    claim_schemas: &'a [ClaimSchema],
) -> Result<Vec<&'a ClaimSchema>, CredentialServiceError> {
    let splits = schema.key.split(NESTED_CLAIM_MARKER).collect::<Vec<&str>>();

    let mut result = vec![];

    let mut current_str = String::new();

    for split in splits {
        current_str += split;

        result.push(
            claim_schemas
                .iter()
                .find(|schema| schema.key == current_str)
                .ok_or(CredentialServiceError::MissingParentClaimSchema {
                    claim_schema_id: schema.id,
                })?,
        );

        current_str += &NESTED_CLAIM_MARKER.to_string();
    }

    Ok(result)
}
