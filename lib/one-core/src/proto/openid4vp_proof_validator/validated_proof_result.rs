use std::collections::HashMap;

use shared_types::{CredentialSchemaId, ProofId};

use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::proof::Proof;
use crate::model::proof_schema::{ProofInputClaimSchema, ProofSchema};
use crate::proto::openid4vp_proof_validator::ValidatedProofResult;
use crate::provider::credential_formatter::model::{CredentialClaim, DetailCredential};
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::mapper::extracted_credential_to_model;
use crate::provider::verification_protocol::openid4vp::model::ProvedCredential;

#[derive(Clone, Debug)]
pub(super) struct ValidatedProofClaimDTO {
    pub proof_input_claim: ProofInputClaimSchema,
    pub credential: DetailCredential,
    pub credential_schema: CredentialSchema,
    pub value: CredentialClaim,
}

impl ValidatedProofResult {
    pub(super) async fn new(
        proof: &Proof,
        proved_claims: Vec<ValidatedProofClaimDTO>,
    ) -> Result<Self, OpenID4VCError> {
        validate_proof(proof.to_owned(), proved_claims).await
    }

    pub(crate) fn into_credentials_and_claims(self) -> (Vec<ProvedCredential>, Vec<Claim>) {
        (self.proved_credentials, self.proved_claims)
    }
}

async fn validate_proof(
    proof: Proof,
    proved_claims: Vec<ValidatedProofClaimDTO>,
) -> Result<ValidatedProofResult, OpenID4VCError> {
    let proof_schema = proof
        .schema
        .as_ref()
        .ok_or(OpenID4VCError::MappingError(
            "proof schema is None".to_string(),
        ))?
        .as_ref()
        .await
        .map_err(|e| OpenID4VCError::MappingError(e.to_string()))?;
    validate_proof_completeness(&proof.id, &proof_schema, &proved_claims).await?;

    let input_schemas = proof_schema
        .input_schemas
        .as_ref()
        .await
        .map_err(|e| OpenID4VCError::MappingError(e.to_string()))?;

    let mut credential_schema_by_id = HashMap::new();
    for input_schema in &input_schemas {
        let credential_schema = input_schema
            .credential_schema
            .as_ref()
            .await
            .map_err(|e| OpenID4VCError::MappingError(e.to_string()))?;
        credential_schema_by_id
            .entry(credential_schema.id)
            .or_insert(credential_schema.to_owned());
    }

    #[derive(Debug)]
    struct ProvedClaim {
        claim_schema: ClaimSchema,
        value: CredentialClaim,
        credential: DetailCredential,
        credential_schema: CredentialSchema,
    }
    let proved_claims = proved_claims
        .into_iter()
        .map(|proved_claim| {
            Ok(ProvedClaim {
                value: proved_claim.value,
                credential: proved_claim.credential,
                credential_schema: proved_claim.credential_schema,
                claim_schema: proved_claim.proof_input_claim.schema,
            })
        })
        .collect::<Result<Vec<ProvedClaim>, OpenID4VCError>>()?;

    let mut claims_per_credential: HashMap<CredentialSchemaId, Vec<ProvedClaim>> = HashMap::new();
    for proved_claim in proved_claims {
        claims_per_credential
            .entry(proved_claim.credential_schema.id)
            .or_default()
            .push(proved_claim);
    }

    let mut proved_credentials = vec![];

    let mut proof_claims: Vec<Claim> = vec![];
    for (credential_schema_id, credential_claims) in claims_per_credential {
        let claims: Vec<(CredentialClaim, ClaimSchema)> = credential_claims
            .iter()
            .map(|claim| (claim.value.to_owned(), claim.claim_schema.to_owned()))
            .collect();

        let first_claim = credential_claims
            .first()
            .ok_or(OpenID4VCError::MappingError("claims are empty".to_string()))?;
        let credential = &first_claim.credential;

        let holder_details = credential
            .subject
            .as_ref()
            .ok_or(OpenID4VCError::MappingError(
                "credential subject is missing".to_string(),
            ))
            .map_err(|e| OpenID4VCError::MappingError(e.to_string()))?;

        let credential_schema = credential_schema_by_id
            .get(&credential_schema_id)
            .ok_or_else(|| {
                OpenID4VCError::MappingError(format!(
                    "credential schema {credential_schema_id} is missing"
                ))
            })?;
        let claim_schemas = credential_schema
            .claim_schemas
            .as_ref()
            .await
            .map_err(|e| OpenID4VCError::Other(e.to_string()))?;
        let formats = credential_schema
            .formats
            .as_ref()
            .await
            .map_err(|e| OpenID4VCError::Other(e.to_string()))?;
        let format = formats.first().ok_or(OpenID4VCError::MappingError(
            "formats are empty".to_string(),
        ))?;
        let mappings = format
            .claim_mappings
            .as_ref()
            .await
            .map_err(|e| OpenID4VCError::Other(e.to_string()))?;
        let mappings_map = mappings.iter().map(|m| (m.claim_schema_id, m)).collect();
        let proved_credential = extracted_credential_to_model(
            &claim_schemas,
            &mappings_map,
            first_claim.credential_schema.to_owned(),
            format,
            claims,
            credential.issuer.to_owned(),
            holder_details.to_owned(),
            &proof.protocol,
            &proof.profile,
            credential.issuance_date,
        )?;

        proof_claims.append(
            &mut proved_credential
                .credential
                .claims
                .as_ref()
                .await
                .map_err(|e| OpenID4VCError::Other(e.to_string()))?
                .to_owned(),
        );

        proved_credentials.push(proved_credential);
    }

    Ok(ValidatedProofResult {
        proved_credentials,
        proved_claims: proof_claims,
    })
}

async fn validate_proof_completeness(
    proof_id: &ProofId,
    proof_schema: &ProofSchema,
    proved_claims: &[ValidatedProofClaimDTO],
) -> Result<(), OpenID4VCError> {
    let input_schemas = proof_schema
        .input_schemas
        .as_ref()
        .await
        .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?;

    for input_schema in &input_schemas {
        let credential_schema_id = input_schema.credential_schema.id();
        for proof_claim_input_schema in &input_schema
            .claim_schemas
            .as_ref()
            .await
            .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?
        {
            if proof_claim_input_schema.required
                && !proved_claims.iter().any(|proved_claim| {
                    credential_schema_id == proved_claim.credential_schema.id
                        && proof_claim_input_schema.schema.id
                            == proved_claim.proof_input_claim.schema.id
                })
            {
                return Err(OpenID4VCError::ValidationError(format!(
                    "Claim `{}` (key `{}`) is required but not found in proof submission for proof `{}`",
                    proof_claim_input_schema.schema.id,
                    proof_claim_input_schema.schema.key,
                    proof_id
                )));
            }
        }
    }
    Ok(())
}
