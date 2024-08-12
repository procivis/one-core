use super::dto::ValidatedProofClaimDTO;
use crate::{
    common_validator::{is_lvvc, validate_expiration_time, validate_issuance_time},
    model::{
        credential_schema::CredentialSchema,
        did::{Did, KeyRole},
        proof_schema::{ProofInputClaimSchema, ProofSchema},
    },
    service::error::{BusinessLogicError, MissingProviderError, ServiceError},
    util::{key_verification::KeyVerification, oidc::map_from_oidc_format_to_core_detailed},
};

use one_providers::revocation::model::{
    CredentialDataByRole, CredentialRevocationState, VerifierCredentialData,
};
use one_providers::revocation::provider::RevocationMethodProvider;
use one_providers::{
    credential_formatter::model::{DetailCredential, ExtractPresentationCtx},
    key_algorithm::provider::KeyAlgorithmProvider,
};
use one_providers::{
    credential_formatter::provider::CredentialFormatterProvider, did::provider::DidMethodProvider,
};
use shared_types::CredentialSchemaId;
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
        .extract_presentation(
            presentation,
            key_verification_presentation.clone(),
            ExtractPresentationCtx::default(),
        )
        .await?;

    // Check if presentation is expired
    validate_issuance_time(&presentation.issued_at, presentation_formatter.get_leeway())?;
    validate_expiration_time(
        &presentation.expires_at,
        presentation_formatter.get_leeway(),
    )?;

    let input_schemas = proof_schema
        .input_schemas
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "claim_schemas is None".to_string(),
        ))?;

    let (requested_cred_schema_ids, claim_schemas_with_cred_schemas) =
        match proof_schema.input_schemas.as_ref() {
            Some(input_schemas) if !input_schemas.is_empty() => {
                let requested_cred_schema_ids = input_schemas
                    .iter()
                    .map(|input| {
                        input
                            .credential_schema
                            .as_ref()
                            .map(|schema| schema.id)
                            .ok_or(ServiceError::MappingError(
                                "credential_schema is None".to_string(),
                            ))
                    })
                    .collect::<Result<HashSet<CredentialSchemaId>, ServiceError>>()?;

                let mut claim_schemas_with_cred_schemas: Vec<(
                    ProofInputClaimSchema,
                    CredentialSchema,
                )> = Vec::new();

                for input in input_schemas {
                    let proof_input_claim_schemas =
                        input
                            .claim_schemas
                            .as_ref()
                            .ok_or(ServiceError::MappingError(
                                "claim_schemas is None".to_string(),
                            ))?;

                    for proof_input_claim_schema in proof_input_claim_schemas {
                        let credential_schema =
                            input
                                .credential_schema
                                .as_ref()
                                .ok_or(ServiceError::MappingError(
                                    "credential schema is None".to_string(),
                                ))?;
                        claim_schemas_with_cred_schemas.push((
                            proof_input_claim_schema.to_owned(),
                            credential_schema.to_owned(),
                        ))
                    }
                }

                (requested_cred_schema_ids, claim_schemas_with_cred_schemas)
            }
            _ => {
                return Err(ServiceError::MappingError(
                    "input_schemas are missing".to_string(),
                ));
            }
        };

    let mut remaining_requested_claims: HashMap<CredentialSchemaId, Vec<ProofInputClaimSchema>> =
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

    let extracted_lvvcs = extract_lvvcs(&presentation.credentials, formatter_provider).await?;

    for credential in presentation.credentials {
        // Workaround credential format detection
        let format = if credential.starts_with('{') {
            map_from_oidc_format_to_core_detailed("ldp_vc", Some(&credential))
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

        // Check if “nbf” attribute of VCs and VP are valid. || Check if VCs are expired.
        validate_issuance_time(
            &credential.invalid_before,
            credential_formatter.get_leeway(),
        )?;
        validate_expiration_time(&credential.expires_at, credential_formatter.get_leeway())?;

        if is_lvvc(&credential) {
            continue;
        }

        let (credential_schema_id, requested_proof_claims) =
            extract_matching_requested_schema(&credential, &mut remaining_requested_claims)?;

        let issuer_did = credential
            .issuer_did
            .as_ref()
            .ok_or(ServiceError::ValidationError(
                "Issuer DID missing".to_owned(),
            ))?;

        for credential_status in credential.status.iter() {
            let (revocation_method, _) = revocation_method_provider
                .get_revocation_method_by_status_type(&credential_status.r#type)
                .ok_or(MissingProviderError::RevocationMethod(
                    credential_status.r#type.clone(),
                ))?;

            let proof_input = input_schemas
                .iter()
                .find(|input_schema| {
                    input_schema.credential_schema.as_ref().map(|cs| cs.id)
                        == Some(credential_schema_id)
                })
                .ok_or(ServiceError::ValidationError(
                    "Missing matching input schema".to_owned(),
                ))?
                .clone();

            match revocation_method
                .check_credential_revocation_status(
                    credential_status,
                    issuer_did,
                    Some(CredentialDataByRole::Verifier(Box::new(
                        VerifierCredentialData {
                            credential: credential.to_owned(),
                            extracted_lvvcs: extracted_lvvcs.to_owned(),
                            proof_input: proof_input.into(),
                        },
                    ))),
                )
                .await?
            {
                CredentialRevocationState::Valid => {}
                CredentialRevocationState::Revoked
                | CredentialRevocationState::Suspended { .. } => {
                    return Err(BusinessLogicError::CredentialIsRevokedOrSuspended.into());
                }
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

        if Into::<String>::into(claim_subject.to_string())
            != Into::<String>::into(holder_did.did.to_string())
        {
            return Err(ServiceError::ValidationError(
                "Holder DID doesn't match.".to_owned(),
            ));
        }

        let mut collected_proved_claims: Vec<ValidatedProofClaimDTO> = vec![];
        for requested_proof_claim in requested_proof_claims {
            let found = credential
                .claims
                .values
                .get(&requested_proof_claim.schema.key);

            // missing optional claim
            if !requested_proof_claim.required && found.is_none() {
                continue;
            }

            let value = found.ok_or(ServiceError::ValidationError(format!(
                "Required credential key '{}' missing",
                &requested_proof_claim.schema.key
            )))?;

            collected_proved_claims.push(ValidatedProofClaimDTO {
                claim_schema_id: requested_proof_claim.schema.id,
                credential: credential.to_owned(),
                value: (
                    requested_proof_claim.schema.key.to_owned(),
                    value.to_owned(),
                ),
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
    remaining_requested_claims: &mut HashMap<CredentialSchemaId, Vec<ProofInputClaimSchema>>,
) -> Result<(CredentialSchemaId, Vec<ProofInputClaimSchema>), ServiceError> {
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
                        .iter()
                        .any(|(key, _)| key == &required_claim_schema.schema.key)
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

async fn extract_lvvcs(
    presentation_credentials: &[String],
    formatter_provider: &(dyn CredentialFormatterProvider),
) -> Result<Vec<DetailCredential>, ServiceError> {
    let mut result = vec![];

    for credential in presentation_credentials {
        // Workaround credential format detection
        let format = if credential.starts_with('{') {
            map_from_oidc_format_to_core_detailed("ldp_vc", Some(credential))
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
            .extract_credentials_unverified(credential)
            .await?;
        if is_lvvc(&credential) {
            result.push(credential);
        }
    }

    Ok(result)
}
