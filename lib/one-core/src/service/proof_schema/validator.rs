use std::collections::HashSet;

use super::dto::{CreateProofSchemaRequestDTO, ProofInputSchemaRequestDTO};
use super::error::ProofSchemaServiceError;
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::{Features, SelectiveDisclosure};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;

pub async fn throw_if_invalid_credential_combination(
    schemas: &[CredentialSchema],
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<(), ProofSchemaServiceError> {
    if schemas.len() > 1 {
        for schema in schemas {
            let schema_format = schema.format().await?;
            let formatter = formatter_provider.get_credential_formatter(&schema_format)?;

            if !formatter
                .get_capabilities()
                .features
                .contains(&Features::SupportsCombinedPresentation)
            {
                return Err(ProofSchemaServiceError::InvalidCredentialCombination {
                    credential_format: schema_format.to_string(),
                });
            }
        }
    }

    Ok(())
}

pub fn validate_create_request(
    request: &CreateProofSchemaRequestDTO,
) -> Result<(), ProofSchemaServiceError> {
    if request.proof_input_schemas.is_empty() {
        return Err(ProofSchemaServiceError::MissingProofInputSchemas);
    }

    let mut uniq = HashSet::new();

    for proof_input in &request.proof_input_schemas {
        if proof_input.claim_schemas.is_empty() {
            return Err(ProofSchemaServiceError::MissingClaims);
        }

        // at least one claim must be required
        if !proof_input.claim_schemas.iter().any(|claim| claim.required) {
            return Err(ProofSchemaServiceError::NoRequiredClaim);
        }

        if !proof_input
            .claim_schemas
            .iter()
            .all(|claim| uniq.insert(claim.id))
        {
            return Err(ProofSchemaServiceError::DuplicitClaim);
        }
    }

    Ok(())
}

pub(super) async fn extract_claims_from_credential_schema(
    proof_inputs: &[ProofInputSchemaRequestDTO],
    schemas: &[CredentialSchema],
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<Vec<ClaimSchema>, ProofSchemaServiceError> {
    let mut result = vec![];

    for proof_input in proof_inputs {
        let credential_schema = schemas
            .iter()
            .find(|schema| schema.id == proof_input.credential_schema_id)
            .ok_or(ProofSchemaServiceError::MissingCredentialSchema)?;

        let schema_format = credential_schema.format().await?;
        let formatter = formatter_provider.get_credential_formatter(&schema_format)?;

        let claims = credential_schema.claim_schemas.as_ref().await?;
        let arrays = collect_lists(&claims);

        for proof_claim in &proof_input.claim_schemas {
            let claim_schema = claims
                .iter()
                .find(|schema_claim| schema_claim.id == proof_claim.id)
                .ok_or(ProofSchemaServiceError::MissingClaimSchema(proof_claim.id))?;

            validate_proof_schema_nesting(claim_schema, &*formatter)?;
            validate_proof_schema_claim_not_in_array(&claim_schema.key, &arrays)?;
            result.push(claim_schema.to_owned());
        }
    }

    Ok(result)
}

fn validate_proof_schema_claim_not_in_array(
    key: &str,
    arrays: &HashSet<String>,
) -> Result<(), ProofSchemaServiceError> {
    match key.rsplit_once(NESTED_CLAIM_MARKER) {
        Some((parent, _)) => {
            if arrays.contains(parent) {
                Err(ProofSchemaServiceError::NestedClaimInArrayRequested)
            } else {
                validate_proof_schema_claim_not_in_array(parent, arrays)
            }
        }
        None => Ok(()),
    }
}

fn collect_lists(claims: &[ClaimSchema]) -> HashSet<String> {
    claims
        .iter()
        .filter_map(|c| match c.array {
            true => Some(c.key.to_owned()),
            _ => None,
        })
        .collect()
}

pub(super) fn validate_proof_schema_nesting(
    claim_schema: &ClaimSchema,
    formatter: &dyn CredentialFormatter,
) -> Result<(), ProofSchemaServiceError> {
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
        (false, None) => !claim_schema.key.contains(NESTED_CLAIM_MARKER),
        (true, Some(SelectiveDisclosure::AnyLevel)) => true,
        (true, Some(SelectiveDisclosure::FirstLevel)) => {
            !claim_schema.key.contains(NESTED_CLAIM_MARKER)
        }
    };

    if !valid_disclosure_level {
        return Err(ProofSchemaServiceError::IncorrectDisclosureLevel);
    }
    Ok(())
}
