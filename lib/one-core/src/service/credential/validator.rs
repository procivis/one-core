use std::collections::VecDeque;

use itertools::Itertools;
use regex::Regex;
use url::Url;

use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::common_validator::throw_if_org_relation_not_matching_session;
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, DatatypeType, IdentifierType, IssuanceProtocolType};
use crate::config::validator::datatype::{DatatypeValidationError, validate_datatype_value};
use crate::config::validator::protocol::validate_protocol_type;
use crate::model::credential::Credential;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::proto::session_provider::SessionProvider;
use crate::provider::credential_formatter::model::FormatterCapabilities;
use crate::provider::issuance_protocol::openid4vci_draft13::model::OpenID4VCIDraft13Params;
use crate::provider::issuance_protocol::openid4vci_draft13_swiyu::OpenID4VCISwiyuParams;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::OpenID4VCIFinal1Params;
use crate::provider::revocation::model::CredentialRevocationState;
use crate::service::credential::dto::CredentialRequestClaimDTO;
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};

pub(super) fn throw_if_credential_schema_not_in_session_org(
    credential: &Credential,
    session_provider: &dyn SessionProvider,
) -> Result<(), ServiceError> {
    let schema = credential
        .schema
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "credential_schema is None".to_string(),
        ))?;
    throw_if_org_relation_not_matching_session(schema.organisation.as_ref(), session_provider)
}

pub(crate) fn validate_create_request(
    exchange: &str,
    claims: &[CredentialRequestClaimDTO],
    schema: &CredentialSchema,
    formatter_capabilities: &FormatterCapabilities,
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    validate_protocol_type(exchange, &config.issuance_protocol)?;
    validate_format_and_exchange_protocol_compatibility(exchange, formatter_capabilities, config)?;

    // ONE-843: cannot create credential based on deleted schema
    if schema.deleted_at.is_some() {
        return Err(BusinessLogicError::MissingCredentialSchema.into());
    }

    let claim_schemas = &schema
        .claim_schemas
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "claim_schemas is None".to_string(),
        ))?;

    let mut paths: Vec<&str> = vec![];

    // check all claims have valid content
    for claim in claims {
        let claim_schema_id = claim.claim_schema_id;
        let schema = claim_schemas
            .iter()
            .find(|schema| schema.schema.id == claim_schema_id);

        match schema {
            None => return Err(BusinessLogicError::MissingClaimSchema { claim_schema_id }.into()),
            Some(schema) => {
                validate_path(claim, schema, claim_schemas)?;
                validate_array_value_non_empty(claim, schema)?;
                validate_object_value_non_empty(claim, schema)?;
                validate_value_non_empty(claim)?;

                validate_datatype_value(&claim.value, &schema.schema.data_type, &config.datatype)
                    .map_err(|err| ValidationError::InvalidDatatype {
                    value: claim.value.clone(),
                    datatype: schema.schema.data_type.clone(),
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
            let datatype = &claim_schema.schema.data_type;
            let config = config.datatype.get_fields(datatype)?;

            if claim_schema.required
                && !claim_schema.schema.metadata // Clients are not expected to submit _metadata_ claims.
                && config.r#type != DatatypeType::Object
            {
                claims
                    .iter()
                    .find(|claim| claim.claim_schema_id == claim_schema.schema.id)
                    .ok_or(ValidationError::CredentialMissingClaim {
                        claim_schema_id: claim_schema.schema.id,
                    })?;
            }
            Ok(())
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;

    Ok(())
}

pub(super) fn validate_redirect_uri(
    exchange: &str,
    redirect_uri: Option<&str>,
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    let fields = config.issuance_protocol.get_fields(exchange)?;
    let params = match fields.r#type {
        IssuanceProtocolType::OpenId4VciDraft13 => {
            let params = fields
                .deserialize::<OpenID4VCIDraft13Params>()
                .map_err(|source| ConfigValidationError::FieldsDeserialization {
                    key: exchange.to_string(),
                    source,
                })?;
            params.redirect_uri
        }
        IssuanceProtocolType::OpenId4VciDraft13Swiyu => {
            let params = fields
                .deserialize::<OpenID4VCISwiyuParams>()
                .map_err(|source| ConfigValidationError::FieldsDeserialization {
                    key: exchange.to_string(),
                    source,
                })?;
            params.redirect_uri
        }
        IssuanceProtocolType::OpenId4VciFinal1_0 => {
            let params = fields
                .deserialize::<OpenID4VCIFinal1Params>()
                .map_err(|source| ConfigValidationError::FieldsDeserialization {
                    key: exchange.to_string(),
                    source,
                })?;
            params.redirect_uri
        }
    };

    if let Some(redirect_uri) = redirect_uri {
        if !params.enabled {
            return Err(ValidationError::InvalidRedirectUri.into());
        }

        let url = Url::parse(redirect_uri).map_err(|_| ValidationError::InvalidRedirectUri)?;

        if !params.allowed_schemes.contains(&url.scheme().to_string()) {
            return Err(ValidationError::InvalidRedirectUri.into());
        }
    }

    Ok(())
}

struct PathNode {
    pub key: Option<String>,
    pub subnodes: Vec<PathNode>,
}

impl PathNode {
    fn insert(&mut self, path: &str) -> Result<(), ServiceError> {
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
                    let last = self
                        .subnodes
                        .last_mut()
                        .ok_or(ServiceError::MappingError("subnodes is empty".to_string()))?;
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
    ) -> Result<(), ServiceError> {
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
                let key = self.key.as_ref().ok_or(ServiceError::MappingError(format!(
                    "Missing subclaim key under {parent}"
                )))?;
                Some(format!("{parent}{NESTED_CLAIM_MARKER}{key}"))
            }
        };

        if let (Some(key), Some(array_claim_paths)) = (&key_path, &array_claim_paths) {
            let is_array = array_claim_paths.is_match(key);
            if is_array {
                if subkeys.first().is_some_and(|key| *key != "0") {
                    return Err(ServiceError::MappingError(
                        "Array indexes need to start at 0".to_string(),
                    ));
                }

                let indexes = subkeys
                    .iter()
                    .map(|index| {
                        index.parse::<u64>().map_err(|e| {
                            ServiceError::ConfigValidationError(
                                ConfigValidationError::DatatypeValidation(
                                    DatatypeValidationError::IndexParseFailure(e),
                                ),
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let continuous = indexes
                    .iter()
                    .tuple_windows()
                    .all(|(i1, i2)| i1 < i2 && i2 - i1 == 1);
                if !continuous {
                    return Err(ServiceError::MappingError(
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
    claim_schemas: &[CredentialSchemaClaim],
) -> Result<(), ServiceError> {
    let mut tree = PathNode {
        key: None,
        subnodes: vec![],
    };

    paths.iter().try_for_each(|path| tree.insert(path))?;

    let array_paths = claim_schemas
        .iter()
        .filter_map(|schema| {
            if schema.schema.array {
                Some(schema.schema.key.as_str())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let array_claim_paths = array_paths_to_claim_paths_regex(&array_paths)?;

    tree.check_continuity(&array_claim_paths, None)?;

    Ok(())
}

fn validate_value_non_empty(claim: &CredentialRequestClaimDTO) -> Result<(), ServiceError> {
    if claim.value.is_empty() {
        return Err(ValidationError::EmptyValueNotAllowed.into());
    }

    Ok(())
}

fn validate_object_value_non_empty(
    claim: &CredentialRequestClaimDTO,
    schema: &CredentialSchemaClaim,
) -> Result<(), ServiceError> {
    if claim.path.contains(NESTED_CLAIM_MARKER) && !schema.schema.array && claim.value.is_empty() {
        return Err(ValidationError::EmptyObjectNotAllowed.into());
    }

    Ok(())
}

fn validate_array_value_non_empty(
    claim: &CredentialRequestClaimDTO,
    schema: &CredentialSchemaClaim,
) -> Result<(), ServiceError> {
    if claim.value.is_empty() && schema.schema.array {
        return Err(ValidationError::EmptyArrayValueNotAllowed.into());
    }

    Ok(())
}

/// Converts set of array claim schema keys into a regex matching claim path
fn array_paths_to_claim_paths_regex(array_paths: &[&str]) -> Result<Option<Regex>, ServiceError> {
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
            .map_err(|e| ServiceError::Other(e.to_string()))?,
    ))
}

fn get_nth_segment_of_key(key: &str, index: usize) -> Result<&str, ServiceError> {
    key.split(NESTED_CLAIM_MARKER)
        .nth(index)
        .ok_or(ServiceError::MappingError(
            "wrong segment index".to_string(),
        ))
}

fn validate_path(
    claim: &CredentialRequestClaimDTO,
    schema: &CredentialSchemaClaim,
    claim_schemas: &[CredentialSchemaClaim],
) -> Result<(), ServiceError> {
    let related_claim_schemas = resolve_parent_claim_schemas(schema, claim_schemas)?;

    let segments = claim.path.split(NESTED_CLAIM_MARKER).collect::<Vec<&str>>();
    let expected_segments = related_claim_schemas
        .iter()
        .map(|schema| if schema.schema.array { 2 } else { 1 })
        .sum::<usize>();

    if segments.len() != expected_segments {
        return Err(ServiceError::MappingError(format!(
            "invalid segments [{} vs {expected_segments}]",
            segments.len()
        )));
    }

    let mut schema_index = 0;
    let mut segment_index = 0;
    loop {
        let related_schema = &related_claim_schemas[schema_index];
        let key_segment = get_nth_segment_of_key(&related_schema.schema.key, schema_index)?;
        if key_segment != segments[segment_index] {
            return Err(ServiceError::MappingError(format!(
                "expected: {key_segment}, found: {}",
                segments[segment_index]
            )));
        }

        if related_schema.schema.array {
            segment_index += 1;
            segments[segment_index].parse::<u64>().map_err(|e| {
                ServiceError::ConfigValidationError(ConfigValidationError::DatatypeValidation(
                    DatatypeValidationError::IndexParseFailure(e),
                ))
            })?;
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
    claim_schemas: &[CredentialSchemaClaim],
    claims: &[CredentialRequestClaimDTO],
    config: &CoreConfig,
) -> Result<Vec<CredentialSchemaClaim>, ServiceError> {
    let claims_with_names = claims
        .iter()
        .map(|claim| {
            let matching_claim_schema = claim_schemas
                .iter()
                .find(|claim_schema| claim_schema.schema.id == claim.claim_schema_id)
                .ok_or(ValidationError::CredentialSchemaMissingClaims)?;
            Ok((claim, matching_claim_schema.schema.key.to_owned()))
        })
        .collect::<Result<Vec<(&CredentialRequestClaimDTO, String)>, ValidationError>>()?;

    let mut result = claim_schemas.to_vec();
    claim_schemas.iter().try_for_each(|claim_schema| {
        let prefix = format!("{}/", claim_schema.schema.key);

        let is_parent_schema_of_provided_claim = claims_with_names
            .iter()
            .any(|(_, claim_name)| claim_name.starts_with(&prefix));

        let is_object = config
            .datatype
            .get_fields(&claim_schema.schema.data_type)?
            .r#type
            == DatatypeType::Object;

        let should_make_all_child_claims_non_required =
            !is_parent_schema_of_provided_claim && is_object && !claim_schema.required;

        if should_make_all_child_claims_non_required {
            result.iter_mut().for_each(|result_schema| {
                if result_schema.schema.key.starts_with(&prefix) {
                    result_schema.required = false;
                }
            });
        }

        Ok::<(), ServiceError>(())
    })?;

    Ok(result)
}

fn validate_format_and_exchange_protocol_compatibility(
    exchange: &str,
    formatter_capabilities: &FormatterCapabilities,
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    let exchange_protocol = config.issuance_protocol.get_fields(exchange)?;

    if !formatter_capabilities
        .issuance_exchange_protocols
        .contains(&exchange_protocol.r#type)
    {
        return Err(BusinessLogicError::IncompatibleIssuanceExchangeProtocol.into());
    }

    Ok(())
}

pub(crate) fn validate_format_and_did_method_compatibility(
    did_method: &str,
    formatter_capabilities: &FormatterCapabilities,
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    let did_method_type = config.did.get_fields(did_method)?.r#type;

    if !formatter_capabilities
        .issuance_did_methods
        .contains(&did_method_type)
    {
        return Err(BusinessLogicError::IncompatibleIssuanceDidMethod.into());
    }

    if !formatter_capabilities
        .issuance_identifier_types
        .contains(&IdentifierType::Did)
    {
        return Err(BusinessLogicError::IncompatibleIssuanceIdentifier.into());
    }

    Ok(())
}

fn resolve_parent_claim_schemas<'a>(
    schema: &'a CredentialSchemaClaim,
    claim_schemas: &'a [CredentialSchemaClaim],
) -> Result<Vec<&'a CredentialSchemaClaim>, ServiceError> {
    let splits = schema
        .schema
        .key
        .split(NESTED_CLAIM_MARKER)
        .collect::<Vec<&str>>();

    let mut result = vec![];

    let mut current_str = String::new();

    for split in splits {
        current_str += split;

        result.push(
            claim_schemas
                .iter()
                .find(|schema| schema.schema.key == current_str)
                .ok_or(ServiceError::BusinessLogic(
                    BusinessLogicError::MissingParentClaimSchema {
                        claim_schema_id: schema.schema.id,
                    },
                ))?,
        );

        current_str += &NESTED_CLAIM_MARKER.to_string();
    }

    Ok(result)
}

pub(super) fn verify_suspension_support(
    credential_schema: &CredentialSchema,
    revocation_state: &CredentialRevocationState,
) -> Result<(), ServiceError> {
    if !credential_schema.allow_suspension
        && matches!(
            revocation_state,
            CredentialRevocationState::Suspended { .. }
        )
    {
        return Err(BusinessLogicError::SuspensionNotAvailableForSelectedRevocationMethod.into());
    }
    Ok(())
}
