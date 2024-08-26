use std::collections::HashMap;

use one_providers::credential_formatter::model::DetailCredential;
use shared_types::CredentialSchemaId;
use time::OffsetDateTime;

use super::dto::ValidatedProofClaimDTO;
use crate::common_mapper::{extracted_credential_to_model, get_or_create_did};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::Did;
use crate::model::proof::{Proof, ProofState, ProofStateEnum};
use crate::model::proof_schema::ProofInputClaimSchema;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::ServiceError;

pub async fn accept_proof(
    proof: Proof,
    proved_claims: Vec<ValidatedProofClaimDTO>,
    holder_did: Did,
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

            let input_schemas =
                proof_schema
                    .input_schemas
                    .as_ref()
                    .ok_or(ServiceError::MappingError(
                        "claim_schemas is None".to_string(),
                    ))?;

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
        let issuer_did = get_or_create_did(
            did_repository,
            &proof_schema.organisation,
            &issuer_did.clone().into(),
        )
        .await?;

        let credential = extracted_credential_to_model(
            &[],
            first_claim.credential_schema.to_owned(),
            claims,
            issuer_did,
            Some(holder_did.clone()),
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
