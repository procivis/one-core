use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use shared_types::{ClaimSchemaId, CredentialSchemaId, DidValue};
use time::OffsetDateTime;

use super::common::to_cbor;
use crate::common_mapper::{extracted_credential_to_model, get_or_create_did};
use crate::common_validator::{validate_expiration_time, validate_issuance_time};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::KeyRole;
use crate::model::proof::{Proof, ProofState, ProofStateEnum};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofSchema};
use crate::provider::credential_formatter::mdoc_formatter::mdoc::SessionTranscript;
use crate::provider::credential_formatter::model::{DetailCredential, ExtractPresentationCtx};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::{MissingProviderError, ServiceError};
use crate::util::key_verification::KeyVerification;

#[derive(Clone, Debug)]
pub struct ValidatedProofClaimDTO {
    pub claim_schema_id: ClaimSchemaId,
    pub credential: DetailCredential,
    pub value: (String, serde_json::Value),
}

// copied from lib/one-core/src/service/ssi_verifier/validator.rs
// just adapted to always use MDOC
#[allow(clippy::too_many_arguments)]
pub async fn validate_proof(
    proof_schema: &ProofSchema,
    presentation: &str,
    session_transcript: SessionTranscript,
    formatter_provider: &dyn CredentialFormatterProvider,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
) -> Result<(DidValue, Vec<ValidatedProofClaimDTO>), ServiceError> {
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

    let format = "MDOC";
    let formatter = formatter_provider
        .get_formatter(format)
        .ok_or(MissingProviderError::Formatter(format.to_owned()))?;

    let presentation = formatter
        .extract_presentation(
            presentation,
            key_verification_presentation,
            ExtractPresentationCtx {
                mdoc_session_transcript: Some(to_cbor(&session_transcript)?),
                ..Default::default()
            },
        )
        .await?;

    let holder_did = presentation
        .issuer_did
        .ok_or(ServiceError::MappingError("issuer_did is None".to_string()))?;

    // Check if presentation is expired
    let leeway = formatter.get_leeway();
    validate_issuance_time(&presentation.issued_at, leeway)?;
    validate_expiration_time(&presentation.expires_at, leeway)?;

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

    for credential in presentation.credentials {
        let credential = formatter
            .extract_credentials(&credential, key_verification_credentials.clone())
            .await?;

        // Check if “nbf” attribute of VCs and VP are valid. || Check if VCs are expired.
        validate_issuance_time(&credential.invalid_before, leeway)?;
        validate_expiration_time(&credential.valid_until, leeway)?;

        let (credential_schema_id, requested_proof_claims) =
            extract_matching_requested_schema(&credential, &mut remaining_requested_claims)?;

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
            != Into::<String>::into(holder_did.to_string())
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

    Ok((
        holder_did,
        proved_credentials
            .into_iter()
            .flat_map(|(.., claims)| claims)
            .collect(),
    ))
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

pub async fn accept_proof(
    proof: Proof,
    proved_claims: Vec<ValidatedProofClaimDTO>,
    holder_did: DidValue,
    did_repository: &dyn DidRepository,
    credential_repository: &dyn CredentialRepository,
    proof_repository: &dyn ProofRepository,
) -> Result<(), ServiceError> {
    let proof_schema = proof.schema.as_ref().ok_or(ServiceError::MappingError(
        "proof schema is None".to_string(),
    ))?;

    let claim_schemas_with_cred_schemas = match proof_schema.input_schemas.as_ref() {
        Some(input_schemas) if !input_schemas.is_empty() => {
            let mut res: Vec<(ProofInputClaimSchema, CredentialSchema)> = Vec::new();

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
                    res.push((
                        proof_input_claim_schema.to_owned(),
                        credential_schema.to_owned(),
                    ))
                }
            }

            res
        }

        _ => {
            return Err(ServiceError::MappingError(
                "proof input schemas are missing".to_string(),
            ))
        }
    };

    struct ProvedClaim {
        claim_schema: ClaimSchema,
        value: (String, serde_json::Value),
        credential: DetailCredential,
        credential_schema: CredentialSchema,
    }
    let proved_claims = proved_claims
        .into_iter()
        .map(|proved_claim| {
            let (claim_schema, credential_schema) = claim_schemas_with_cred_schemas
                .iter()
                .find(|(claim_schema, _)| claim_schema.schema.id == proved_claim.claim_schema_id)
                .ok_or(ServiceError::MappingError(
                    "Couldn't find matching proof claim schema".to_string(),
                ))?
                .to_owned();
            Ok(ProvedClaim {
                value: proved_claim.value,
                credential: proved_claim.credential,
                credential_schema,
                claim_schema: claim_schema.schema,
            })
        })
        .collect::<Result<Vec<ProvedClaim>, ServiceError>>()?;

    let mut claims_per_credential: HashMap<CredentialSchemaId, Vec<ProvedClaim>> = HashMap::new();
    for proved_claim in proved_claims {
        claims_per_credential
            .entry(proved_claim.credential_schema.id)
            .or_default()
            .push(proved_claim);
    }

    let holder_did =
        get_or_create_did(did_repository, &proof_schema.organisation, &holder_did).await?;

    let mut proof_claims: Vec<Claim> = vec![];
    for (_, credential_claims) in claims_per_credential {
        let claims: Vec<(serde_json::Value, ClaimSchema)> = credential_claims
            .iter()
            .map(|claim| Ok((claim.value.1.to_owned(), claim.claim_schema.to_owned())))
            .collect::<Result<Vec<_>, ServiceError>>()?;

        let first_claim = credential_claims
            .first()
            .ok_or(ServiceError::MappingError("claims are empty".to_string()))?;
        let issuer_did =
            first_claim
                .credential
                .issuer_did
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "issuer_did is missing".to_string(),
                ))?;
        let issuer_did =
            get_or_create_did(did_repository, &proof_schema.organisation, issuer_did).await?;

        let credential_schema = &first_claim.credential_schema;
        let claim_schemas =
            credential_schema
                .claim_schemas
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "claim_schemas missing".to_string(),
                ))?;

        let credential = extracted_credential_to_model(
            claim_schemas,
            credential_schema.to_owned(),
            claims,
            issuer_did,
            Some(holder_did.clone()),
            proof.exchange.to_owned(),
        )?;

        proof_claims.append(
            &mut credential
                .claims
                .as_ref()
                .ok_or(ServiceError::MappingError("claims missing".to_string()))?
                .to_owned(),
        );

        credential_repository.create_credential(credential).await?;
    }

    proof_repository
        .set_proof_holder_did(&proof.id, holder_did)
        .await?;

    proof_repository
        .set_proof_claims(&proof.id, proof_claims)
        .await?;

    let now = OffsetDateTime::now_utc();
    proof_repository
        .set_proof_state(
            &proof.id,
            ProofState {
                created_date: now,
                last_modified: now,
                state: ProofStateEnum::Accepted,
            },
        )
        .await
        .map_err(ServiceError::from)
}
