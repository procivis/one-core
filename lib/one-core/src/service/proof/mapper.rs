use std::collections::hash_map::Entry;
use std::collections::HashMap;

use dto_mapper::convert_inner;
use shared_types::{CredentialId, CredentialSchemaId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateProofRequestDTO, ProofClaimDTO, ProofClaimValueDTO, ProofDetailResponseDTO,
    ProofInputDTO, ProofListItemResponseDTO,
};
use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::DatatypeType;
use crate::model::credential_schema::CredentialSchemaClaim;
use crate::model::did::Did;
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::key::Key;
use crate::model::proof::{self, Proof, ProofStateEnum};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofSchema};
use crate::service::credential::dto::CredentialDetailResponseDTO;
use crate::service::credential_schema::dto::CredentialSchemaListItemResponseDTO;
use crate::service::error::ServiceError;
use crate::service::proof_schema::dto::ProofClaimSchemaResponseDTO;

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

            match &mut parent_claim.value {
                Some(ProofClaimValueDTO::Claims(claims)) => {
                    if let Some(i) = claims
                        .iter()
                        .position(|claim: &ProofClaimDTO| claim.schema.key == suffix)
                    {
                        Ok(&mut claims[i])
                    } else {
                        claims.push(ProofClaimDTO {
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
                            value: Some(ProofClaimValueDTO::Claims(vec![])),
                        });
                        Ok(claims.last_mut().unwrap())
                    }
                }
                None | Some(ProofClaimValueDTO::Value(_)) => Err(ServiceError::MappingError(
                    "Parent claim can not have a text value or be empty".into(),
                )),
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
                    value: Some(ProofClaimValueDTO::Claims(vec![])),
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
            exchange: value.exchange,
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
                let mut proof_input_claims: Vec<_> = input_claim_schemas
                    .iter()
                    .filter(|claim_schema| !claim_schema.schema.key.contains(NESTED_CLAIM_MARKER))
                    .map(|claim_schema| {
                        let claim = claims.iter().find(|c| {
                            c.claim
                                .schema
                                .as_ref()
                                .is_some_and(|s| s.id == claim_schema.schema.id)
                        });

                        ProofClaimDTO {
                            schema: claim_schema.clone().into(),
                            value: claim
                                .map(|c| ProofClaimValueDTO::Value(c.claim.value.to_string())),
                        }
                    })
                    .collect();

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

                        if parent_proof_claim.value.is_none() {
                            parent_proof_claim.value = Some(ProofClaimValueDTO::Claims(vec![]));
                        }

                        if let Some(ProofClaimValueDTO::Claims(claims)) =
                            &mut parent_proof_claim.value
                        {
                            // Filter out duplicates
                            if !claims
                                .iter()
                                .any(|c| c.schema.key == claim_schema.schema.key)
                            {
                                claims.push(ProofClaimDTO {
                                    schema: claim_schema.into(),
                                    value: claim.map(|c| {
                                        ProofClaimValueDTO::Value(c.claim.value.to_owned())
                                    }),
                                });
                            }
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
        exchange: list_item_response.exchange,
        state: list_item_response.state,
        organisation_id: Some(organisation_id),
        schema: list_item_response.schema,
        redirect_uri,
        proof_inputs,
    })
}

fn renest_proof_claims(claims: Vec<ProofClaimDTO>) -> Vec<ProofClaimDTO> {
    let mut result: Vec<ProofClaimDTO> = vec![];
    let mut nested_grouped_by_root: HashMap<String, Vec<ProofClaimDTO>> = HashMap::new();

    for mut claim in claims {
        let claim_key = claim.schema.key.clone();
        if let Some((root_claim, remaining_path)) = claim_key.split_once(NESTED_CLAIM_MARKER) {
            remaining_path.clone_into(&mut claim.schema.key);
            nested_grouped_by_root
                .entry(root_claim.to_owned())
                .or_default()
                .push(claim);
        } else {
            result.push(claim);
        }
    }

    for (root_key, inner_claims) in nested_grouped_by_root {
        result.push(ProofClaimDTO {
            schema: ProofClaimSchemaResponseDTO {
                id: Uuid::new_v4().into(),
                required: true,
                key: root_key,
                data_type: DatatypeType::Object.to_string(),
                claims: vec![],
                array: false,
            },
            value: Some(ProofClaimValueDTO::Claims(renest_proof_claims(
                inner_claims,
            ))),
        })
    }

    result
}

pub fn get_holder_proof_detail(value: Proof) -> Result<ProofDetailResponseDTO, ServiceError> {
    let organisation_id = value
        .holder_did
        .as_ref()
        .and_then(|did| did.organisation.as_ref().map(|o| o.id));

    let holder_did_id = value.holder_did.as_ref().map(|did| did.id);

    let redirect_uri = value.redirect_uri.to_owned();

    let mut proof_inputs = vec![];

    let mut submitted_credentials: HashMap<
        CredentialId,
        (
            Vec<ProofClaimDTO>,
            CredentialDetailResponseDTO,
            CredentialSchemaListItemResponseDTO,
        ),
    > = HashMap::new();

    for proof_claim in value.claims.iter().flatten() {
        let credential = proof_claim
            .credential
            .as_ref()
            .ok_or(ServiceError::MappingError(format!(
                "Missing credential for claim: {}",
                proof_claim.claim.id
            )))?;

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError(format!(
                "Missing credential schema for credential: {}",
                credential.id
            )))?;

        let claim_schema = proof_claim
            .claim
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError(format!(
                "Missing claim schema for claim: {}",
                proof_claim.claim.id
            )))?;

        let claim = ProofClaimDTO {
            schema: ProofClaimSchemaResponseDTO {
                id: claim_schema.id,
                required: true,
                key: claim_schema.key.clone(),
                data_type: claim_schema.data_type.clone(),
                claims: vec![],
                array: claim_schema.array,
            },
            value: Some(ProofClaimValueDTO::Value(
                proof_claim.claim.value.to_string(),
            )),
        };

        match submitted_credentials.entry(credential.id) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().0.push(claim);
            }
            Entry::Vacant(entry) => {
                entry.insert((
                    vec![claim],
                    CredentialDetailResponseDTO::try_from(credential.clone())?,
                    credential_schema.clone().into(),
                ));
            }
        }
    }

    for (claims, credential, credential_schema) in submitted_credentials.into_values() {
        proof_inputs.push(ProofInputDTO {
            claims: renest_proof_claims(claims),
            credential: Some(credential),
            credential_schema,
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
        exchange: list_item_response.exchange,
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
        exchange: request.exchange,
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
