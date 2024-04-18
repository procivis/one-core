use super::dto::{
    CreateProofRequestDTO, ProofClaimDTO, ProofDetailResponseDTO, ProofInputDTO,
    ProofListItemResponseDTO,
};
use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::model::credential_schema::{CredentialSchemaClaim, CredentialSchemaId};
use crate::model::key::Key;
use crate::model::proof_schema::ProofInputClaimSchema;
use crate::service::credential::dto::CredentialDetailResponseDTO;
use crate::{
    model::{
        did::Did,
        history::{History, HistoryAction, HistoryEntityType},
        proof::{self, Proof, ProofStateEnum},
        proof_schema::ProofSchema,
    },
    service::error::ServiceError,
};
use dto_mapper::convert_inner;
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

fn get_or_create_proof_claim<'a>(
    proof_claims: &'a mut Vec<ProofClaimDTO>,
    key: &str,
    credential_claim_schemas: &Vec<CredentialSchemaClaim>,
) -> Result<&'a mut ProofClaimDTO, ServiceError> {
    match key.rsplit_once(NESTED_CLAIM_MARKER) {
        // It's a nested claim
        Some((prefix, suffix)) => {
            let parent_claim =
                get_or_create_proof_claim(proof_claims, prefix, credential_claim_schemas)?;

            if let Some(i) = parent_claim
                .claims
                .iter()
                .position(|claim: &ProofClaimDTO| claim.schema.key == suffix)
            {
                Ok(&mut parent_claim.claims[i])
            } else {
                parent_claim.claims.push(ProofClaimDTO {
                    schema: credential_claim_schemas
                        .iter()
                        .find(|claim_schema| claim_schema.schema.key == key)
                        .cloned()
                        .map(|mut claim_schema| {
                            claim_schema.schema.key = suffix.into();
                            claim_schema
                        })
                        .ok_or(ServiceError::MappingError(
                            "nested claim is not found by key".into(),
                        ))?
                        .into(),
                    value: None,
                    claims: vec![],
                });
                Ok(parent_claim.claims.last_mut().unwrap())
            }
        }
        // It's a root
        None => {
            if let Some(i) = proof_claims
                .iter()
                .position(|claim| claim.schema.key == key)
            {
                Ok(&mut proof_claims[i])
            } else {
                proof_claims.push(ProofClaimDTO {
                    schema: credential_claim_schemas
                        .iter()
                        .find(|claim_schema| claim_schema.schema.key == key)
                        .cloned()
                        .map(|mut claim_schema| {
                            claim_schema.schema.key = key.into();
                            claim_schema
                        })
                        .ok_or(ServiceError::MappingError(
                            "root claim is not found by key".into(),
                        ))?
                        .into(),
                    value: None,
                    claims: vec![],
                });
                Ok(proof_claims.last_mut().unwrap())
            }
        }
    }
}

impl TryFrom<Proof> for ProofListItemResponseDTO {
    type Error = ServiceError;

    fn try_from(value: Proof) -> Result<Self, Self::Error> {
        let states = value
            .state
            .ok_or(ServiceError::MappingError("state is None".to_string()))?;
        let latest_state = states
            .first()
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?;
        let requested_date = states
            .iter()
            .find(|state| state.state == ProofStateEnum::Requested)
            .map(|state| state.created_date);

        let completed_date = states
            .iter()
            .find(|state| {
                state.state == ProofStateEnum::Accepted || state.state == ProofStateEnum::Rejected
            })
            .map(|state| state.created_date);

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            issuance_date: value.issuance_date,
            requested_date,
            completed_date,
            verifier_did: convert_inner(value.verifier_did),
            transport: value.transport,
            state: latest_state.state.clone(),
            schema: value.schema.map(|schema| schema.into()),
        })
    }
}

pub fn get_verifier_proof_detail(proof: Proof) -> Result<ProofDetailResponseDTO, ServiceError> {
    let holder_did_id = proof.holder_did.as_ref().map(|did| did.id);

    let schema = proof
        .schema
        .as_ref()
        .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

    let claims = proof
        .claims
        .as_ref()
        .ok_or(ServiceError::MappingError("claims is None".to_string()))?;

    let organisation_id = schema
        .organisation
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "organisation is None".to_string(),
        ))?
        .id;

    let credential_for_credential_schema: HashMap<CredentialSchemaId, CredentialDetailResponseDTO> =
        claims
            .iter()
            .map(|proof_claim| {
                let credential = proof_claim.credential.clone().ok_or_else(|| {
                    ServiceError::MappingError(format!(
                        "Missing credential for proof claim {}",
                        proof_claim.claim.id
                    ))
                })?;
                let credential_schema = credential.schema.clone().ok_or_else(|| {
                    ServiceError::MappingError(format!(
                        "Missing credential schema for credential {}",
                        credential.id
                    ))
                })?;
                let credential = CredentialDetailResponseDTO::try_from(credential)?;

                Ok::<_, ServiceError>((credential_schema.id, credential))
            })
            .collect::<Result<_, _>>()?;

    let proof_inputs = match schema.input_schemas.as_ref() {
        Some(proof_input_schemas) if !proof_input_schemas.is_empty() => {
            let mut proof_inputs = vec![];

            for input_schema in proof_input_schemas {
                let mut input_claim_schemas = input_schema
                    .claim_schemas
                    .as_ref()
                    .ok_or(ServiceError::MappingError(
                        "Missing claims schemas in input_schema".to_string(),
                    ))?
                    .clone();

                let credential_schema =
                    input_schema
                        .credential_schema
                        .as_ref()
                        .ok_or(ServiceError::MappingError(
                            "Missing credential schema in input_schema".to_string(),
                        ))?;

                let credential_claim_schemas = credential_schema.claim_schemas.as_ref().unwrap();

                let mut object_nested_claims: Vec<ProofInputClaimSchema> = Vec::new();
                input_claim_schemas.iter().for_each(|claim| {
                    if claim.schema.data_type == "OBJECT" {
                        let nested_claims: Vec<_> = credential_claim_schemas
                            .iter()
                            .enumerate()
                            .filter(|(_, c)| {
                                c.schema.key.starts_with(&format!(
                                    "{}{NESTED_CLAIM_MARKER}",
                                    claim.schema.key
                                ))
                            })
                            .map(|(i, c)| ProofInputClaimSchema {
                                schema: c.schema.clone(),
                                required: c.required,
                                order: i as u32,
                            })
                            .collect();
                        object_nested_claims.extend(nested_claims);
                    }
                });

                input_claim_schemas.extend(object_nested_claims);
                let mut proof_input_claims: Vec<ProofClaimDTO> = Vec::new();

                input_claim_schemas
                    .iter()
                    .filter_map(|claim_schema| {
                        claim_schema
                            .schema
                            .key
                            .rsplit_once(NESTED_CLAIM_MARKER)
                            .map(|(parent_path, name)| (parent_path, name, claim_schema))
                    })
                    .try_for_each(|(parent_path, name, claim_schema)| {
                        let claim = claims.iter().find(|c| {
                            c.claim
                                .schema
                                .as_ref()
                                .is_some_and(|s| s.id == claim_schema.schema.id)
                        });

                        let parent_proof_claim = get_or_create_proof_claim(
                            &mut proof_input_claims,
                            parent_path,
                            credential_claim_schemas,
                        )?;

                        let mut claim_schema = claim_schema.clone();
                        claim_schema.schema.key = name.into();

                        // Filter out duplicates
                        if !parent_proof_claim
                            .claims
                            .iter()
                            .any(|c| c.schema.key == claim_schema.schema.key)
                        {
                            parent_proof_claim.claims.push(ProofClaimDTO {
                                schema: claim_schema.into(),
                                value: claim.map(|c| c.claim.value.to_string()),
                                claims: vec![],
                            });
                        }

                        Ok::<_, ServiceError>(())
                    })?;

                proof_inputs.push(ProofInputDTO {
                    claims: proof_input_claims,
                    credential: credential_for_credential_schema
                        .get(&credential_schema.id)
                        .cloned(),
                    credential_schema: credential_schema.clone().into(),
                    validity_constraint: input_schema.validity_constraint,
                })
            }

            proof_inputs
        }

        _ => {
            return Err(ServiceError::MappingError(
                "input_schemas are missing".to_string(),
            ));
        }
    };

    let redirect_uri = proof.redirect_uri.to_owned();
    let list_item_response: ProofListItemResponseDTO = proof.try_into()?;

    Ok(ProofDetailResponseDTO {
        id: list_item_response.id,
        created_date: list_item_response.created_date,
        last_modified: list_item_response.last_modified,
        issuance_date: list_item_response.issuance_date,
        requested_date: list_item_response.requested_date,
        completed_date: list_item_response.completed_date,
        verifier_did: list_item_response.verifier_did,
        holder_did_id,
        transport: list_item_response.transport,
        state: list_item_response.state,
        organisation_id: Some(organisation_id),
        schema: list_item_response.schema,
        redirect_uri,
        proof_inputs,
    })
}

pub fn get_holder_proof_detail(value: Proof) -> Result<ProofDetailResponseDTO, ServiceError> {
    let organisation_id = value
        .holder_did
        .as_ref()
        .and_then(|did| did.organisation.as_ref().map(|o| o.id));

    let holder_did_id = value.holder_did.as_ref().map(|did| did.id);

    let redirect_uri = value.redirect_uri.to_owned();

    let mut proof_inputs = vec![];
    for claim in value.claims.iter().flatten() {
        let Some(credential) = &claim.credential else {
            continue;
        };
        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError(format!(
                "Missing credential schema for credential: {}",
                credential.id
            )))?;

        proof_inputs.push(ProofInputDTO {
            claims: vec![],
            credential: Some(CredentialDetailResponseDTO::try_from(credential.clone())?),
            credential_schema: credential_schema.clone().into(),
            validity_constraint: None,
        });
    }

    let list_item_response: ProofListItemResponseDTO = value.try_into()?;

    Ok(ProofDetailResponseDTO {
        id: list_item_response.id,
        created_date: list_item_response.created_date,
        last_modified: list_item_response.last_modified,
        issuance_date: list_item_response.issuance_date,
        requested_date: list_item_response.requested_date,
        completed_date: list_item_response.completed_date,
        verifier_did: list_item_response.verifier_did,
        holder_did_id,
        transport: list_item_response.transport,
        state: list_item_response.state,
        organisation_id,
        schema: list_item_response.schema,
        redirect_uri,
        proof_inputs,
    })
}

pub fn proof_from_create_request(
    request: CreateProofRequestDTO,
    now: OffsetDateTime,
    schema: ProofSchema,
    verifier_did: Did,
    verifier_key: Option<Key>,
) -> Proof {
    Proof {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        issuance_date: now,
        transport: request.transport,
        redirect_uri: request.redirect_uri,
        state: Some(vec![proof::ProofState {
            created_date: now,
            last_modified: now,
            state: ProofStateEnum::Created,
        }]),
        schema: Some(schema),
        claims: None,
        verifier_did: Some(verifier_did),
        holder_did: None,
        verifier_key,
        interaction: None,
    }
}

pub(super) fn proof_requested_history_event(proof: Proof) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Requested,
        entity_id: Some(proof.id.into()),
        entity_type: HistoryEntityType::Proof,
        metadata: None,
        organisation: proof.schema.and_then(|s| s.organisation),
    }
}
