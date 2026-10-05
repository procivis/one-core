use std::collections::HashMap;

use shared_types::{CredentialId, CredentialSchemaFormatId, CredentialSchemaId, ProofId};

use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::proof::{Proof, ProofClaim};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofSchema};
use crate::proto::openid4vp_proof_validator::ValidatedProofResult;
use crate::provider::credential_formatter::model::{CredentialClaim, DetailCredential};
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::mapper::extracted_credential_to_model;
use crate::provider::verification_protocol::openid4vp::model::ProvedCredential;

#[derive(Clone, Debug)]
pub(super) struct ValidatedProofClaimDTO {
    pub credential_instance_id: CredentialId,
    pub proof_input_claim: ProofInputClaimSchema,
    pub credential: DetailCredential,
    pub credential_schema: CredentialSchema,
    pub credential_schema_format: CredentialSchemaFormat,
    pub value: CredentialClaim,
}

impl ValidatedProofResult {
    pub(super) async fn new(
        proof: &Proof,
        proved_claims: Vec<ValidatedProofClaimDTO>,
    ) -> Result<Self, OpenID4VCError> {
        validate_proof(proof.to_owned(), proved_claims).await
    }

    pub(crate) fn into_credentials_and_claims(self) -> (Vec<ProvedCredential>, Vec<ProofClaim>) {
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

    let mut claims_per_credential: HashMap<
        (CredentialSchemaId, CredentialSchemaFormatId, CredentialId),
        Vec<ValidatedProofClaimDTO>,
    > = HashMap::new();
    for proved_claim in proved_claims {
        claims_per_credential
            .entry((
                proved_claim.credential_schema.id,
                proved_claim.credential_schema_format.id,
                proved_claim.credential_instance_id,
            ))
            .or_default()
            .push(proved_claim);
    }

    let mut proved_credentials = vec![];

    let mut proof_claims: Vec<ProofClaim> = vec![];
    for credential_claims in claims_per_credential.into_values() {
        let claims: Vec<(CredentialClaim, ClaimSchema)> = credential_claims
            .iter()
            .map(|claim| {
                (
                    claim.value.to_owned(),
                    claim.proof_input_claim.schema.to_owned(),
                )
            })
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

        let credential_schema = &first_claim.credential_schema;
        let claim_schemas = credential_schema
            .claim_schemas
            .as_ref()
            .await
            .map_err(|e| OpenID4VCError::Other(e.to_string()))?;
        let format = &first_claim.credential_schema_format;
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

        proof_claims.extend(
            proved_credential
                .credential
                .claims()
                .as_ref()
                .await
                .map_err(|e| OpenID4VCError::Other(e.to_string()))?
                .iter()
                .cloned()
                .map(|claim| ProofClaim {
                    credential: proved_credential.credential.clone().into(),
                    claim,
                }),
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
