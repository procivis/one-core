use std::collections::HashSet;

use itertools::Itertools;
use shared_types::OrganisationId;
use time::{Duration, OffsetDateTime};

use super::ProofSchemaImportError;
use super::dto::{
    CreateProofSchemaRequestDTO, ImportProofSchemaClaimSchemaDTO, ImportProofSchemaDTO,
    ProofInputSchemaRequestDTO,
};
use crate::config::core_config::{ConfigExt, CoreConfig, RevocationType};
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::{Features, SelectiveDisclosure};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::service::error::{
    BusinessLogicError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::proof_schema::mapper::create_unique_name_check_request;

pub async fn proof_schema_name_already_exists(
    repository: &dyn ProofSchemaRepository,
    name: &str,
    organisation_id: OrganisationId,
) -> Result<(), ServiceError> {
    let proof_schemas = repository
        .get_proof_schema_list(create_unique_name_check_request(name, organisation_id)?)
        .await?;
    if proof_schemas.total_items > 0 {
        return Err(BusinessLogicError::ProofSchemaAlreadyExists.into());
    }
    Ok(())
}

pub fn throw_if_validity_constraint_missing_for_lvvc(
    credential_schemas: &Vec<CredentialSchema>,
    request: &CreateProofSchemaRequestDTO,
    config: &CoreConfig,
) -> Result<(), ValidationError> {
    for credential_schema in credential_schemas {
        let input_schema = request
            .proof_input_schemas
            .iter()
            .find(|input| input.credential_schema_id == credential_schema.id)
            .ok_or(ValidationError::ProofSchemaMissingProofInputSchemas)?;

        let uses_lvvc_revocation = match &credential_schema.revocation_method {
            Some(method_id) => {
                let revocation_type = config.revocation.get_type(method_id).map_err(|e| {
                    ValidationError::InvalidFormatter(format!("Invalid revocation id: {e}"))
                })?;

                revocation_type == RevocationType::Lvvc
            }
            None => false,
        };

        if uses_lvvc_revocation && input_schema.validity_constraint.is_none() {
            return Err(ValidationError::ValidityConstraintMissingForLvvc);
        }
    }
    Ok(())
}

pub fn throw_if_invalid_credential_combination(
    schemas: &[CredentialSchema],
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<(), ServiceError> {
    if schemas.len() > 1 {
        for schema in schemas {
            let formatter = formatter_provider
                .get_credential_formatter(&schema.format)
                .ok_or(MissingProviderError::Formatter(schema.format.to_string()))?;

            if !formatter
                .get_capabilities()
                .features
                .contains(&Features::SupportsCombinedPresentation)
            {
                return Err(ValidationError::ProofSchemaInvalidCredentialCombination {
                    credential_format: schema.format.to_string(),
                }
                .into());
            }
        }
    }

    Ok(())
}

pub fn validate_create_request(
    request: &CreateProofSchemaRequestDTO,
) -> Result<(), ValidationError> {
    if request.proof_input_schemas.is_empty() {
        return Err(ValidationError::ProofSchemaMissingProofInputSchemas);
    }

    let mut uniq = HashSet::new();

    for proof_input in &request.proof_input_schemas {
        if proof_input.claim_schemas.is_empty() {
            return Err(ValidationError::ProofSchemaMissingClaims);
        }

        // at least one claim must be required
        if !proof_input.claim_schemas.iter().any(|claim| claim.required) {
            return Err(ValidationError::ProofSchemaNoRequiredClaim);
        }

        if !proof_input
            .claim_schemas
            .iter()
            .all(|claim| uniq.insert(claim.id))
        {
            return Err(ValidationError::ProofSchemaDuplicitClaim);
        }

        check_if_validity_constraint_is_correct(proof_input)?;
    }

    Ok(())
}

pub fn extract_claims_from_credential_schema(
    proof_input: &[ProofInputSchemaRequestDTO],
    schemas: &[CredentialSchema],
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<Vec<ClaimSchema>, ServiceError> {
    proof_input
        .iter()
        .map(|proof_input| {
            let credential_schema = schemas
                .iter()
                .find(|schema| schema.id == proof_input.credential_schema_id)
                .ok_or_else(|| ServiceError::MappingError("Missing credential schema".into()))?;

            let formatter = formatter_provider
                .get_credential_formatter(&credential_schema.format)
                .ok_or(MissingProviderError::Formatter(
                    credential_schema.format.to_string(),
                ))?;

            let claims = credential_schema.claim_schemas.as_ref().ok_or_else(|| {
                ServiceError::MappingError("Missing credential schema claims".into())
            })?;

            let arrays = collect_lists(claims);

            Ok::<_, ServiceError>(proof_input.claim_schemas.iter().map(move |proof_claim| {
                claims
                    .iter()
                    .find(|schema_claim| schema_claim.schema.id == proof_claim.id)
                    .map(|schema_claim| schema_claim.schema.clone())
                    .ok_or_else(|| {
                        ServiceError::BusinessLogic(BusinessLogicError::MissingClaimSchema {
                            claim_schema_id: proof_claim.id,
                        })
                    })
                    .and_then(|claim_schema| {
                        validate_proof_schema_nesting(&claim_schema, &*formatter)?;
                        validate_proof_schema_claim_not_in_array(&claim_schema.key, &arrays)?;
                        Ok(claim_schema)
                    })
            }))
        })
        .flatten_ok()
        .map(|r| r.and_then(std::convert::identity))
        .collect()
}

fn validate_proof_schema_claim_not_in_array(
    key: &str,
    arrays: &HashSet<String>,
) -> Result<(), ServiceError> {
    match key.rsplit_once(NESTED_CLAIM_MARKER) {
        Some((parent, _)) => {
            if arrays.contains(parent) {
                Err(ValidationError::NestedClaimInArrayRequested.into())
            } else {
                validate_proof_schema_claim_not_in_array(parent, arrays)
            }
        }
        None => Ok(()),
    }
}

fn collect_lists(claims: &[CredentialSchemaClaim]) -> HashSet<String> {
    claims
        .iter()
        .filter_map(|c| match c.schema.array {
            true => Some(c.schema.key.to_owned()),
            _ => None,
        })
        .collect()
}

pub(super) fn validate_proof_schema_nesting(
    claim_schema: &ClaimSchema,
    formatter: &dyn CredentialFormatter,
) -> Result<(), ServiceError> {
    let capabilities = formatter.get_capabilities();

    // Check disclosure level
    let valid_disclosure_level = match (
        capabilities
            .features
            .contains(&Features::SelectiveDisclosure),
        capabilities.selective_disclosure.first(),
    ) {
        (true, None) => false,     // Incompatible capabilities
        (false, Some(_)) => false, // Incompatible capabilities
        (false, None) => !claim_schema.key.contains('/'),
        (true, Some(SelectiveDisclosure::AnyLevel)) => true,
        (true, Some(SelectiveDisclosure::SecondLevel)) => {
            claim_schema.key.chars().filter(|&c| c == '/').count() <= 1
        }
    };

    if !valid_disclosure_level {
        return Err(ServiceError::BusinessLogic(
            BusinessLogicError::IncorrectDisclosureLevel,
        ));
    }
    Ok(())
}

pub(super) fn validate_imported_proof_schema(
    schema: &ImportProofSchemaDTO,
    config: &CoreConfig,
) -> Result<(), BusinessLogicError> {
    for schema in &schema.proof_input_schemas {
        let format = &schema.credential_schema.format;
        config
            .format
            .get_if_enabled(format)
            .map_err(|_| ProofSchemaImportError::UnsupportedFormat(format.to_string()))?;

        validate_imported_proof_schema_data_types(&schema.claim_schemas, config)?;
    }

    Ok(())
}

fn validate_imported_proof_schema_data_types(
    claim_schemas: &[ImportProofSchemaClaimSchemaDTO],
    config: &CoreConfig,
) -> Result<(), BusinessLogicError> {
    for claim_schema in claim_schemas {
        let datatype = &claim_schema.data_type;
        config
            .datatype
            .get_if_enabled(datatype)
            .map_err(|_| ProofSchemaImportError::UnsupportedDatatype(datatype.to_owned()))?;

        validate_imported_proof_schema_data_types(&claim_schema.claims, config)?;
    }

    Ok(())
}

fn check_if_validity_constraint_is_correct(
    input_schema: &ProofInputSchemaRequestDTO,
) -> Result<(), ValidationError> {
    let now = OffsetDateTime::now_utc();

    if let Some(validity_constraint) = input_schema.validity_constraint.as_ref()
        && (now
            .checked_sub(Duration::seconds(*validity_constraint))
            .is_none()
            || now
                .checked_add(Duration::seconds(*validity_constraint))
                .is_none())
    {
        return Err(ValidationError::ValidityConstraintOutOfRange);
    }

    Ok(())
}
