use super::dto::ValidatedProofClaimDTO;
use crate::{
    credential_formatter::CredentialFormatter,
    model::{
        claim_schema::ClaimSchemaId,
        credential_schema::{CredentialSchema, CredentialSchemaId},
        did::Did,
        proof_schema::ProofSchema,
    },
    service::error::ServiceError,
};
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};
use time::OffsetDateTime;
use uuid::Uuid;

pub(super) fn validate_proof(
    proof_schema: ProofSchema,
    holder_did: Did,
    presentation: &str,
    formatter: &(dyn CredentialFormatter + Send + Sync),
) -> Result<Vec<ValidatedProofClaimDTO>, ServiceError> {
    // TODO Check if the signature of the ProofSubmitRequestDTO(JWT) is signed with did of the issuer property (holder did)
    // Add when key management introduced. For now we use the same pair of keys for everything.
    // If it's extracted - it's properly signed
    // This will change when we started using external signature providers
    let presentation = formatter.extract_presentation(presentation)?;

    // Check if presentation is expired
    validate_issuance_time(presentation.issued_at)?;
    validate_expiration_time(presentation.expires_at)?;

    let proof_schema_claims = proof_schema
        .claim_schemas
        .ok_or(ServiceError::MappingError(
            "claim_schemas is None".to_string(),
        ))?;

    let requested_cred_schema_ids = proof_schema_claims
        .iter()
        .map(|claim| {
            claim
                .credential_schema
                .as_ref()
                .map(|schema| schema.id)
                .ok_or(ServiceError::MappingError(
                    "credential_schema is None".to_string(),
                ))
        })
        .collect::<Result<HashSet<CredentialSchemaId>, ServiceError>>()?;

    let claim_schema_ids_with_cred_schemas = proof_schema_claims
        .iter()
        .map(|claim| {
            claim
                .credential_schema
                .as_ref()
                .map(|credential_schema| (claim.schema.id, credential_schema.to_owned()))
                .ok_or(ServiceError::MappingError(
                    "credential_schema is None".to_string(),
                ))
        })
        .collect::<Result<Vec<(ClaimSchemaId, CredentialSchema)>, ServiceError>>()?;

    let mut remaining_requested_claims: HashMap<CredentialSchemaId, Vec<ClaimSchemaId>> =
        HashMap::new();
    for credential_schema_id in requested_cred_schema_ids {
        remaining_requested_claims.insert(
            credential_schema_id,
            claim_schema_ids_with_cred_schemas
                .iter()
                .filter(|(_, credential_schema)| credential_schema.id == credential_schema_id)
                .map(|(claim_schema_id, _)| claim_schema_id.to_owned())
                .collect(),
        );
    }

    let mut proved_credentials: HashMap<CredentialSchemaId, Vec<ValidatedProofClaimDTO>> =
        HashMap::new();

    for credential in presentation.credentials {
        let claim = formatter.extract_credentials(&credential)?;

        // Check if “nbf” attribute of VCs and VP are valid. || Check if VCs are expired.
        validate_issuance_time(claim.invalid_before)?;
        validate_expiration_time(claim.expires_at)?;

        // Check if all subjects of the submitted VCs is matching the holder did.
        let claim_subject = match claim.subject {
            None => {
                return Err(ServiceError::ValidationError(
                    "Claim Holder DID missing".to_owned(),
                ));
            }
            Some(did) => did,
        };
        if claim_subject != holder_did.did {
            return Err(ServiceError::ValidationError(
                "Holder DID doesn't match.".to_owned(),
            ));
        }

        // check if this credential was requested
        let credential_schema_id = Uuid::from_str(&claim.claims.one_credential_schema.id)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;
        let requested_claims: Result<Vec<ClaimSchemaId>, ServiceError> =
            match remaining_requested_claims.remove_entry(&credential_schema_id) {
                None => {
                    if proved_credentials.contains_key(&credential_schema_id) {
                        Err(ServiceError::ValidationError(format!(
                            "Duplicit credential for schema '{credential_schema_id}' received"
                        )))
                    } else {
                        Err(ServiceError::ValidationError(format!(
                            "Credential for schema '{credential_schema_id}' not requested"
                        )))
                    }
                }
                Some((.., value)) => Ok(value),
            };

        let mut collected_proved_claims: Vec<ValidatedProofClaimDTO> = vec![];
        for requested_claim_schema_id in requested_claims? {
            let claim_schema = proof_schema_claims
                .iter()
                .find(|schema| schema.schema.id == requested_claim_schema_id)
                .ok_or(ServiceError::GeneralRuntimeError(
                    "Missing claim schema".to_owned(),
                ))?;

            let value = claim.claims.values.get(&claim_schema.schema.key).ok_or(
                ServiceError::ValidationError(format!(
                    "Credential key '{}' missing",
                    &claim_schema.schema.key
                )),
            )?;

            collected_proved_claims.push(ValidatedProofClaimDTO {
                claim_schema_id: requested_claim_schema_id,
                value: value.to_owned(),
            });
        }

        // TODO Validate collected_proved_claims when validators are ready

        proved_credentials.insert(credential_schema_id, collected_proved_claims);
    }

    if !remaining_requested_claims.is_empty() {
        return Err(ServiceError::ValidationError(
            "Not all requested claims fulfilled".to_owned(),
        ));
    }

    Ok(proved_credentials
        .into_iter()
        .flat_map(|(.., claims)| claims)
        .collect())
}

fn validate_issuance_time(issued_at: Option<OffsetDateTime>) -> Result<(), ServiceError> {
    let now = OffsetDateTime::now_utc();
    let issued = issued_at.ok_or(ServiceError::ValidationError(
        "Missing issuance date".to_owned(),
    ))?;

    if issued > now {
        return Err(ServiceError::ValidationError("Issued in future".to_owned()));
    }

    Ok(())
}

fn validate_expiration_time(expires_at: Option<OffsetDateTime>) -> Result<(), ServiceError> {
    let now = OffsetDateTime::now_utc();
    let expires = expires_at.ok_or(ServiceError::ValidationError(
        "Missing expiration date".to_owned(),
    ))?;

    if expires < now {
        return Err(ServiceError::ValidationError("Expired".to_owned()));
    }

    Ok(())
}
