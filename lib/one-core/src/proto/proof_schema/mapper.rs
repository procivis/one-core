use super::Error;
use crate::error::ContextWithErrorCode;
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::proof_schema::{ProofInputClaimSchema, ProofInputSchema};
use crate::service::proof_schema::dto::{
    ImportProofSchemaClaimSchemaDTO, ImportProofSchemaInputSchemaDTO,
};
use crate::validator::proof_schema::resolve_proof_input_formats;

pub(super) async fn proof_input_from_import_request(
    input_schema: ImportProofSchemaInputSchemaDTO,
    credential_schema: CredentialSchema,
) -> Result<ProofInputSchema, Error> {
    let formats = resolve_proof_input_formats(input_schema.formats, &credential_schema)
        .await
        .error_while("resolving imported proof input formats")?;
    let proof_input_claim_schemas = {
        let credential_schema_claims = credential_schema.claim_schemas.as_ref().await?;
        extract_proof_input_claim_schemas(input_schema.claim_schemas, &credential_schema_claims)?
    };

    Ok(ProofInputSchema {
        formats,
        claim_schemas: proof_input_claim_schemas.into(),
        credential_schema: credential_schema.into(),
    })
}

fn extract_proof_input_claim_schemas(
    proof_schema_claims: Vec<ImportProofSchemaClaimSchemaDTO>,
    credential_schema_claims: &[ClaimSchema],
) -> Result<Vec<ProofInputClaimSchema>, Error> {
    let proof_input_claim_schemas = extract_proof_input_claim_schemas_nested(
        proof_schema_claims,
        credential_schema_claims,
        None,
    )?;

    let result = proof_input_claim_schemas
        .into_iter()
        .enumerate()
        .map(|(i, input)| ProofInputClaimSchema {
            order: i as u32,
            ..input
        })
        .collect();

    Ok(result)
}

fn extract_proof_input_claim_schemas_nested(
    proof_schema_claims: Vec<ImportProofSchemaClaimSchemaDTO>,
    credential_schema_claims: &[ClaimSchema],
    parent_path_prefix: Option<String>,
) -> Result<Vec<ProofInputClaimSchema>, Error> {
    let mut result: Vec<ProofInputClaimSchema> = vec![];

    for proof_schema_claim in proof_schema_claims {
        let path = if let Some(parent_path) = &parent_path_prefix {
            format!(
                "{parent_path}{NESTED_CLAIM_MARKER}{}",
                proof_schema_claim.key
            )
        } else {
            proof_schema_claim.key
        };

        if proof_schema_claim.requested {
            let claim_schema = credential_schema_claims
                .iter()
                .find(|credential_schema_claim| credential_schema_claim.key == path)
                .ok_or_else(|| {
                    Error::MappingError(format!("claim_schema for path '{path}' missing"))
                })?;

            result.push(ProofInputClaimSchema {
                schema: claim_schema.to_owned(),
                required: proof_schema_claim.required,
                order: 0, // ordering is done once all claim schemas have been collected in `extract_proof_input_claim_schemas`
            });
        } else {
            result.extend(extract_proof_input_claim_schemas_nested(
                proof_schema_claim.claims,
                credential_schema_claims,
                Some(path),
            )?);
        }
    }

    Ok(result)
}
