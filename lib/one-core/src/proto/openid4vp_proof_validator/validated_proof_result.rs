use std::collections::HashMap;

use shared_types::{CredentialSchemaId, ProofId};

use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::proof::Proof;
use crate::model::proof_schema::{ProofInputClaimSchema, ProofSchema};
use crate::proto::openid4vp_proof_validator::ValidatedProofResult;
use crate::provider::credential_formatter::mdoc_formatter::util::MobileSecurityObject;
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
    pub mdoc_mso: Option<MobileSecurityObject>,
}

impl ValidatedProofResult {
    pub(super) fn new(
        proof: &Proof,
        proved_claims: Vec<ValidatedProofClaimDTO>,
    ) -> Result<Self, OpenID4VCError> {
        validate_proof(proof.to_owned(), proved_claims)
    }

    pub(crate) fn into_credentials_and_claims(self) -> (Vec<ProvedCredential>, Vec<Claim>) {
        (self.proved_credentials, self.proved_claims)
    }
}

fn validate_proof(
    proof: Proof,
    proved_claims: Vec<ValidatedProofClaimDTO>,
) -> Result<ValidatedProofResult, OpenID4VCError> {
    let proof_schema = proof.schema.ok_or(OpenID4VCError::MappingError(
        "proof schema is None".to_string(),
    ))?;
    validate_proof_completeness(&proof.id, &proof_schema, &proved_claims)?;

    let input_schemas = proof_schema
        .input_schemas
        .ok_or(OpenID4VCError::MappingError(
            "input schemas is None".to_string(),
        ))?;

    let mut claim_schemas_for_credential_schema = HashMap::new();
    for input_schema in input_schemas {
        let credential_schema =
            input_schema
                .credential_schema
                .ok_or(OpenID4VCError::MappingError(
                    "credential_schema is None".to_string(),
                ))?;

        let claim_schemas = credential_schema
            .claim_schemas
            .ok_or(OpenID4VCError::MappingError(
                "claim schemas is None".to_string(),
            ))?;

        claim_schemas_for_credential_schema
            .entry(credential_schema.id)
            .or_insert(vec![])
            .extend(claim_schemas);
    }

    #[derive(Debug)]
    struct ProvedClaim {
        claim_schema: ClaimSchema,
        value: CredentialClaim,
        credential: DetailCredential,
        credential_schema: CredentialSchema,
        mdoc_mso: Option<MobileSecurityObject>,
    }
    let proved_claims = proved_claims
        .into_iter()
        .map(|proved_claim| {
            Ok(ProvedClaim {
                value: proved_claim.value,
                credential: proved_claim.credential,
                credential_schema: proved_claim.credential_schema,
                claim_schema: proved_claim.proof_input_claim.schema,
                mdoc_mso: proved_claim.mdoc_mso,
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

        let claim_schemas = claim_schemas_for_credential_schema
            .get(&credential_schema_id)
            .ok_or_else(|| {
                OpenID4VCError::MappingError(format!(
                    "Claim schemas are missing for credential schema {credential_schema_id}"
                ))
            })?;
        let proved_credential = extracted_credential_to_model(
            claim_schemas,
            first_claim.credential_schema.to_owned(),
            claims,
            credential.issuer.to_owned(),
            holder_details.to_owned(),
            first_claim.mdoc_mso.to_owned(),
            &proof.protocol,
            &proof.profile,
            credential.issuance_date,
        )?;

        proof_claims.append(
            &mut proved_credential
                .credential
                .claims
                .as_ref()
                .ok_or(OpenID4VCError::MappingError("claims missing".to_string()))?
                .to_owned(),
        );

        proved_credentials.push(proved_credential);
    }

    Ok(ValidatedProofResult {
        proved_credentials,
        proved_claims: proof_claims,
    })
}

fn validate_proof_completeness(
    proof_id: &ProofId,
    proof_schema: &ProofSchema,
    proved_claims: &[ValidatedProofClaimDTO],
) -> Result<(), OpenID4VCError> {
    for input_schema in
        proof_schema
            .input_schemas
            .as_ref()
            .ok_or(OpenID4VCError::ValidationError(
                "Missing proof input schemas".to_string(),
            ))?
    {
        let credential_schema =
            input_schema
                .credential_schema
                .as_ref()
                .ok_or(OpenID4VCError::ValidationError(
                    "Missing credential schema".to_string(),
                ))?;
        for proof_claim_input_schema in
            input_schema
                .claim_schemas
                .as_ref()
                .ok_or(OpenID4VCError::ValidationError(
                    "Missing claim input schemas".to_string(),
                ))?
        {
            if proof_claim_input_schema.required
                && !proved_claims.iter().any(|proved_claim| {
                    credential_schema.id == proved_claim.credential_schema.id
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
