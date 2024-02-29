use super::dto::ValidatedProofClaimDTO;
use crate::{
    common_validator::{validate_expiration_time, validate_issuance_time},
    model::{
        credential_schema::{CredentialSchema, CredentialSchemaId},
        did::{Did, KeyRole},
        proof_schema::{ProofSchema, ProofSchemaClaim},
    },
    provider::{
        credential_formatter::{model::DetailCredential, provider::CredentialFormatterProvider},
        did_method::provider::DidMethodProvider,
        key_algorithm::provider::KeyAlgorithmProvider,
        revocation::provider::RevocationMethodProvider,
    },
    service::error::{MissingProviderError, ServiceError},
    util::{key_verification::KeyVerification, oidc::map_from_oidc_format_to_core_real},
};

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

#[allow(clippy::too_many_arguments)]
pub(super) async fn validate_proof(
    proof_schema: &ProofSchema,
    holder_did: &Did,
    presentation: &str,
    formatter_provider: &(dyn CredentialFormatterProvider),
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
) -> Result<Vec<ValidatedProofClaimDTO>, ServiceError> {
    let key_verification_presentation = Box::new(KeyVerification {
        key_algorithm_provider: key_algorithm_provider.clone(),
        did_method_provider: did_method_provider.clone(),
        key_role: KeyRole::Authentication,
    });

    let key_verification_credentials = Box::new(KeyVerification {
        key_algorithm_provider,
        did_method_provider,
        key_role: KeyRole::AssertionMethod,
    });

    // presentation envelope only JWT for now
    let formatter = "JWT";
    let presentation_formatter = formatter_provider
        .get_formatter(formatter)
        .ok_or(MissingProviderError::Formatter(formatter.to_owned()))?;

    let presentation = presentation_formatter
        .extract_presentation(presentation, key_verification_presentation.clone())
        .await?;

    // Check if presentation is expired
    validate_issuance_time(&presentation.issued_at, presentation_formatter.get_leeway())?;
    validate_expiration_time(
        &presentation.expires_at,
        presentation_formatter.get_leeway(),
    )?;

    let proof_schema_claims =
        proof_schema
            .claim_schemas
            .as_ref()
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
        // Workaround credential format detection
        let format = if credential.starts_with('{') {
            map_from_oidc_format_to_core_real("ldp_vc", &credential)
                .map_err(|_| ServiceError::Other("Credential format not resolved".to_owned()))?
        } else if credential.contains('~') {
            "SDJWT".to_owned()
        } else {
            "JWT".to_owned()
        };

        let credential_formatter = formatter_provider
            .get_formatter(&format)
            .ok_or(MissingProviderError::Formatter(format.to_owned()))?;

        let credential = credential_formatter
            .extract_credentials(&credential, key_verification_credentials.clone())
            .await?;

        let (credential_schema_id, requested_proof_claims) =
            extract_matching_requested_schema(&credential, &mut remaining_requested_claims)?;

        // Check if “nbf” attribute of VCs and VP are valid. || Check if VCs are expired.
        validate_issuance_time(
            &credential.invalid_before,
            credential_formatter.get_leeway(),
        )?;
        validate_expiration_time(&credential.expires_at, credential_formatter.get_leeway())?;

        if let Some(credential_status) = &credential.status {
            let (revocation_method, _) = revocation_method_provider
                .get_revocation_method_by_status_type(&credential_status.r#type)
                .ok_or(MissingProviderError::RevocationMethod(
                    credential_status.r#type.clone(),
                ))?;

            let issuer_did =
                credential
                    .issuer_did
                    .as_ref()
                    .ok_or(ServiceError::ValidationError(
                        "Issuer DID missing".to_owned(),
                    ))?;

            if revocation_method
                .check_credential_revocation_status(credential_status, issuer_did)
                .await?
            {
                return Err(ServiceError::ValidationError(
                    "Submitted credential revoked".to_owned(),
                ));
            }
        }

        // Check if all subjects of the submitted VCs is matching the holder did.
        let claim_subject = match &credential.subject {
            None => {
                return Err(ServiceError::ValidationError(
                    "Claim Holder DID missing".to_owned(),
                ));
            }
            Some(did) => did,
        };

        if *claim_subject != holder_did.did {
            return Err(ServiceError::ValidationError(
                "Holder DID doesn't match.".to_owned(),
            ));
        }

        let mut collected_proved_claims: Vec<ValidatedProofClaimDTO> = vec![];
        for requested_proof_claim in requested_proof_claims {
            let value = credential
                .claims
                .values
                .get(&requested_proof_claim.schema.key);

            // missing optional claim
            if !requested_proof_claim.required && value.is_none() {
                continue;
            }

            let value = value
                .ok_or(ServiceError::ValidationError(format!(
                    "Required credential key '{}' missing",
                    &requested_proof_claim.schema.key
                )))?
                .to_owned();

            collected_proved_claims.push(ValidatedProofClaimDTO {
                claim_schema_id: requested_proof_claim.schema.id,
                credential: credential.to_owned(),
                value,
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

fn extract_matching_requested_schema(
    received_credential: &DetailCredential,
    remaining_requested_claims: &mut HashMap<CredentialSchemaId, Vec<ProofSchemaClaim>>,
) -> Result<(CredentialSchemaId, Vec<ProofSchemaClaim>), ServiceError> {
    let (matching_credential_schema_id, matching_claim_schemas) = remaining_requested_claims
        .iter()
        .find(|(_, requested_claim_schemas)| {
            requested_claim_schemas
                .iter()
                .filter(|schema| schema.required)
                .all(|required_claim_schema| {
                    received_credential
                        .claims
                        .values
                        .keys()
                        .any(|key| key == &required_claim_schema.schema.key)
                })
        })
        .ok_or(ServiceError::ValidationError(
            "Could not find matching requested credential schema".to_owned(),
        ))?;

    let result = (
        matching_credential_schema_id.to_owned(),
        matching_claim_schemas.to_owned(),
    );
    remaining_requested_claims.remove(&result.0);
    Ok(result)
}
