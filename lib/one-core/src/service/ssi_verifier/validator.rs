use super::dto::ValidatedProofClaimDTO;
use crate::{
    config::data_structure::CoreConfig,
    crypto::Crypto,
    model::{
        credential_schema::{CredentialSchema, CredentialSchemaId},
        did::Did,
        proof_schema::{ProofSchema, ProofSchemaClaim},
    },
    provider::{
        credential_formatter::{model::DetailCredential, CredentialFormatter},
        did_method::provider::DidMethodProvider,
        revocation::provider::RevocationMethodProvider,
    },
    service::error::ServiceError,
    util::key_verification::KeyVerification,
};
use std::ops::{Add, Sub};
use std::time::Duration;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use time::OffsetDateTime;
use uuid::Uuid;

#[allow(clippy::too_many_arguments)]
pub(super) async fn validate_proof(
    proof_schema: ProofSchema,
    holder_did: Did,
    presentation: &str,
    formatter: &(dyn CredentialFormatter + Send + Sync),
    crypto: Arc<Crypto>,
    config: Arc<CoreConfig>,
    did_method_provider: Arc<dyn DidMethodProvider + Send + Sync>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider + Send + Sync>,
) -> Result<Vec<ValidatedProofClaimDTO>, ServiceError> {
    let key_verification = Box::new(KeyVerification {
        config: config.clone(),
        crypto: crypto.clone(),
        did_method_provider: did_method_provider.clone(),
    });

    let presentation = formatter
        .extract_presentation(presentation, key_verification.clone())
        .await?;

    // Check if presentation is expired
    validate_issuance_time(presentation.issued_at, formatter.get_leeway())?;
    validate_expiration_time(presentation.expires_at, formatter.get_leeway())?;

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

    let claim_schemas_with_cred_schemas = proof_schema_claims
        .iter()
        .map(|claim| {
            claim
                .credential_schema
                .as_ref()
                .map(|credential_schema| (claim.to_owned(), credential_schema.to_owned()))
                .ok_or(ServiceError::MappingError(
                    "credential_schema is None".to_string(),
                ))
        })
        .collect::<Result<Vec<(ProofSchemaClaim, CredentialSchema)>, ServiceError>>()?;

    let mut remaining_requested_claims: HashMap<CredentialSchemaId, Vec<ProofSchemaClaim>> =
        HashMap::new();
    for credential_schema_id in requested_cred_schema_ids {
        remaining_requested_claims.insert(
            credential_schema_id,
            claim_schemas_with_cred_schemas
                .iter()
                .filter(|(_, credential_schema)| credential_schema.id == credential_schema_id)
                .map(|(proof_claim_schema, _)| proof_claim_schema.to_owned())
                .collect(),
        );
    }

    let mut proved_credentials: HashMap<CredentialSchemaId, Vec<ValidatedProofClaimDTO>> =
        HashMap::new();

    for credential in presentation.credentials {
        // Credential tokens are being verified here
        let credential = formatter
            .extract_credentials(&credential, key_verification.clone())
            .await?;

        let credential_schema_id = find_matching_schema(&credential, &remaining_requested_claims)?;

        // Check if “nbf” attribute of VCs and VP are valid. || Check if VCs are expired.
        validate_issuance_time(credential.invalid_before, formatter.get_leeway())?;
        validate_expiration_time(credential.expires_at, formatter.get_leeway())?;

        if let Some(credential_status) = credential.status {
            let revocation_method = revocation_method_provider
                .get_revocation_method_by_status_type(&credential_status.r#type)?;

            let issuer_did = credential.issuer_did.ok_or(ServiceError::ValidationError(
                "Issuer DID missing".to_owned(),
            ))?;

            if revocation_method
                .check_credential_revocation_status(&credential_status, &issuer_did)
                .await?
            {
                return Err(ServiceError::ValidationError(
                    "Submitted credential revoked".to_owned(),
                ));
            }
        }

        // Check if all subjects of the submitted VCs is matching the holder did.
        let claim_subject = match credential.subject {
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
        let requested_proof_claims: Result<Vec<ProofSchemaClaim>, ServiceError> =
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
        for requested_proof_claim in requested_proof_claims? {
            let value = credential
                .claims
                .values
                .get(&requested_proof_claim.schema.key);

            // missing optional claim
            if !requested_proof_claim.required && value.is_none() {
                continue;
            }

            let value = value.ok_or(ServiceError::ValidationError(format!(
                "Credential key '{}' missing",
                &requested_proof_claim.schema.key
            )))?;

            collected_proved_claims.push(ValidatedProofClaimDTO {
                claim_schema_id: requested_proof_claim.schema.id,
                value: value.to_owned(),
            });
        }

        // TODO Validate collected_proved_claims when validators are ready

        proved_credentials.insert(credential_schema_id, collected_proved_claims);
    }

    if remaining_requested_claims
        .iter()
        .any(|(_, claims)| claims.iter().any(|claim| claim.required))
    {
        return Err(ServiceError::ValidationError(
            "Not all required claims fulfilled".to_owned(),
        ));
    }

    Ok(proved_credentials
        .into_iter()
        .flat_map(|(.., claims)| claims)
        .collect())
}

fn find_matching_schema(
    credential: &DetailCredential,
    remaining_requested_claims: &HashMap<Uuid, Vec<ProofSchemaClaim>>,
) -> Result<Uuid, ServiceError> {
    for (schema_id, claim_schemas) in remaining_requested_claims {
        if credential.claims.values.keys().all(|key| {
            claim_schemas
                .iter()
                .any(|claim_schema| claim_schema.schema.key.eq(key))
        }) {
            return Ok(schema_id.to_owned());
        }
    }
    Err(ServiceError::ValidationError(
        "Could not find matching credential schema".to_owned(),
    ))
}

fn validate_issuance_time(
    issued_at: Option<OffsetDateTime>,
    leeway: u64,
) -> Result<(), ServiceError> {
    let now = OffsetDateTime::now_utc();
    let issued = issued_at.ok_or(ServiceError::ValidationError(
        "Missing issuance date".to_owned(),
    ))?;

    if issued > now.add(Duration::from_secs(leeway)) {
        return Err(ServiceError::ValidationError("Issued in future".to_owned()));
    }

    Ok(())
}

fn validate_expiration_time(
    expires_at: Option<OffsetDateTime>,
    leeway: u64,
) -> Result<(), ServiceError> {
    let now = OffsetDateTime::now_utc();
    let expires = expires_at.ok_or(ServiceError::ValidationError(
        "Missing expiration date".to_owned(),
    ))?;

    if expires < now.sub(Duration::from_secs(leeway)) {
        return Err(ServiceError::ValidationError("Expired".to_owned()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::*;

    #[test]
    fn test_validate_issuance_time() {
        let leeway = 5u64;

        let correctly_issued = validate_issuance_time(Some(OffsetDateTime::now_utc()), leeway);
        assert!(correctly_issued.is_ok());

        let now_plus_minute = OffsetDateTime::now_utc().add(Duration::from_secs(60));
        let issued_in_future = validate_issuance_time(Some(now_plus_minute), leeway);
        assert!(issued_in_future.is_err());
    }

    #[test]
    fn test_validate_expiration_time() {
        let leeway = 5u64;

        let correctly_issued = validate_expiration_time(Some(OffsetDateTime::now_utc()), leeway);
        assert!(correctly_issued.is_ok());

        let now_minus_minute = OffsetDateTime::now_utc().sub(Duration::from_secs(60));
        let issued_in_future = validate_expiration_time(Some(now_minus_minute), leeway);
        assert!(issued_in_future.is_err());
    }
}
