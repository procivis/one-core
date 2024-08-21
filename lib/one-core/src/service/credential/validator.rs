use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::config::validator::datatype::{validate_datatype_value, DatatypeValidationError};
use crate::config::validator::exchange::validate_exchange_type;
use crate::config::ConfigValidationError;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::provider::credential_formatter::FormatterCapabilities;
use crate::service::credential::dto::CredentialRequestClaimDTO;
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};
use itertools::Itertools;

pub(crate) async fn validate_create_request(
    did_method: &str,
    exchange: &str,
    claims: &[CredentialRequestClaimDTO],
    schema: &CredentialSchema,
    formatter_capabilities: &FormatterCapabilities,
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    validate_exchange_type(exchange, &config.exchange)?;
    validate_format_and_exchange_protocol_compatibility(exchange, formatter_capabilities, config)?;
    validate_format_and_did_method_compatibility(did_method, formatter_capabilities, config)?;

    // ONE-843: cannot create credential based on deleted schema
    if schema.deleted_at.is_some() {
        return Err(BusinessLogicError::MissingCredentialSchema.into());
    }

    let claim_schemas = &schema.claim_schemas.get().await?;

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

                validate_datatype_value(&claim.value, &schema.schema.data_type, &config.datatype)
                    .map_err(|err| ValidationError::InvalidDatatype {
                    value: claim.value.clone(),
                    datatype: schema.schema.data_type.clone(),
                    source: err,
                })?;
            }
        }
    }

    let paths = claims
        .iter()
        .map(|claim| claim.path.as_str())
        .collect::<Vec<&str>>();
    validate_continuity(&paths)?;

    let claim_schemas =
        adapt_required_state_based_on_claim_presence(claim_schemas, claims, config)?;

    // check all required claims are present
    claim_schemas
        .iter()
        .map(|claim_schema| {
            let datatype = &claim_schema.schema.data_type;
            let config = config.datatype.get_fields(datatype)?;

            if claim_schema.required && config.r#type != DatatypeType::Object {
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

struct PathNode {
    pub key: String,
    pub subnodes: Vec<PathNode>,
}

impl PathNode {
    fn insert(&mut self, path: &str) -> Result<(), ServiceError> {
        let (first, rest) = get_first_path_element(path);

        if rest.is_empty() {
            self.subnodes.push(PathNode {
                key: first.to_string(),
                subnodes: vec![],
            });
        } else {
            match self
                .subnodes
                .iter_mut()
                .find(|subnode| subnode.key == first)
            {
                None => {
                    self.subnodes.push(PathNode {
                        key: first.to_string(),
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

    fn check_continuity(&self) -> Result<(), ServiceError> {
        let keys = self
            .subnodes
            .iter()
            .map(|subnode| subnode.key.as_str())
            .collect::<Vec<&str>>();
        if keys.is_empty() {
            return Ok(());
        }

        let first = keys
            .first()
            .map(|index| {
                index.parse::<u64>().map_err(|e| {
                    ServiceError::ConfigValidationError(ConfigValidationError::DatatypeValidation(
                        DatatypeValidationError::IndexParseFailure(e),
                    ))
                })
            })
            .transpose();

        if let Ok(Some(value)) = first {
            if value != 0 {
                return Err(ServiceError::MappingError(
                    "indexes need to start at 0".to_string(),
                ));
            }

            let indexes = keys
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

        self.subnodes
            .iter()
            .try_for_each(|subnode| subnode.check_continuity())?;

        Ok(())
    }
}

fn get_first_path_element(path: &str) -> (&str, &str) {
    match path.find(NESTED_CLAIM_MARKER) {
        None => (path, ""),
        Some(value) => (&path[0..value], &path[value + 1..]),
    }
}

fn validate_continuity(paths: &[&str]) -> Result<(), ServiceError> {
    let mut tree = PathNode {
        key: "tree_root".to_string(),
        subnodes: vec![],
    };

    paths.iter().try_for_each(|path| tree.insert(path))?;

    tree.check_continuity()?;

    Ok(())
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
            "invalid segments [{} vs {expected_segments})",
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
    let exchange_protocol = config.exchange.get_fields(exchange)?;

    if !formatter_capabilities
        .issuance_exchange_protocols
        .contains(&exchange_protocol.r#type.to_string())
    {
        return Err(BusinessLogicError::IncompatibleIssuanceExchangeProtocol.into());
    }

    Ok(())
}

fn validate_format_and_did_method_compatibility(
    did_method: &str,
    formatter_capabilities: &FormatterCapabilities,
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    let did_method_type = config.did.get_fields(did_method)?.r#type;

    if !formatter_capabilities
        .issuance_did_methods
        .contains(&did_method_type.to_string())
    {
        return Err(BusinessLogicError::IncompatibleIssuanceDidMethod.into());
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
