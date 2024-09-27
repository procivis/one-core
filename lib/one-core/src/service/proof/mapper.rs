use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::time::Duration;

use one_dto_mapper::convert_inner;
use shared_types::{CredentialId, CredentialSchemaId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateProofRequestDTO, ProofClaimDTO, ProofClaimValueDTO, ProofDetailResponseDTO,
    ProofInputDTO, ProofListItemResponseDTO,
};
use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::model::credential_schema::CredentialSchemaClaim;
use crate::model::did::Did;
use crate::model::history::History;
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::proof::{self, Proof, ProofStateEnum};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofSchema};
use crate::service::credential::dto::CredentialDetailResponseDTO;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::credential_schema::dto::CredentialSchemaListItemResponseDTO;
use crate::service::error::ServiceError;
use crate::service::proof_schema::dto::ProofClaimSchemaResponseDTO;

fn build_claim_from_credential_claims(
    claims: &[CredentialSchemaClaim],
    key: String,
    suffix: String,
) -> Result<ProofClaimDTO, ServiceError> {
    Ok(ProofClaimDTO {
        schema: claims
            .iter()
            .find(|claim_schema| claim_schema.schema.key == key)
            .cloned()
            .map(|mut claim_schema| {
                claim_schema.schema.key = suffix;
                claim_schema
            })
            .ok_or(ServiceError::MappingError(
                "nested claim is not found by key".into(),
            ))?
            .into(),
        path: key.to_string(),
        value: Some(ProofClaimValueDTO::Claims(vec![])),
    })
}

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
                        claims.push(build_claim_from_credential_claims(
                            credential_claim_schemas,
                            key.into(),
                            suffix.into(),
                        )?);
                        let last = claims.len() - 1;
                        Ok(&mut claims[last])
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
                proof_claims.push(build_claim_from_credential_claims(
                    credential_claim_schemas,
                    key.into(),
                    key.into(),
                )?);
                let last = proof_claims.len() - 1;
                Ok(&mut proof_claims[last])
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

        let retain_until_date = match (completed_date, &value.schema) {
            (Some(completed_date), Some(schema)) if schema.expire_duration != 0 => {
                Some(completed_date + Duration::from_secs(schema.expire_duration as _))
            }
            _ => None,
        };

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            issuance_date: value.issuance_date,
            requested_date,
            retain_until_date,
            transport: value.transport,
            completed_date,
            verifier_did: convert_inner(value.verifier_did),
            exchange: value.exchange,
            state: latest_state.state.clone(),
            schema: value.schema.map(|schema| schema.into()),
        })
    }
}

pub fn get_verifier_proof_detail(
    proof: Proof,
    config: &CoreConfig,
    claims_removed_event: Option<History>,
) -> Result<ProofDetailResponseDTO, ServiceError> {
    let holder_did_id = proof.holder_did.as_ref().map(|did| did.id);

    let schema = proof
        .schema
        .as_ref()
        .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

    let claims = proof
        .claims
        .as_ref()
        .ok_or(ServiceError::MappingError("claims is None".to_string()))?;

    let organisation = schema
        .organisation
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "organisation is None".to_string(),
        ))?;

    let organisation_id = organisation.id;

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
                let credential = credential_detail_response_from_model(credential, config)?;

                Ok((credential_schema.id, credential))
            })
            .collect::<Result<_, ServiceError>>()?;

    let proof_input_schemas = match schema.input_schemas.as_ref() {
        Some(proof_input_schemas) if !proof_input_schemas.is_empty() => proof_input_schemas,
        _ => {
            return Err(ServiceError::MappingError(
                "input_schemas are missing".to_string(),
            ));
        }
    };

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

        let credential_claim_schemas =
            credential_schema
                .claim_schemas
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "Missing claim schema in credential_schema".to_string(),
                ))?;

        let object_nested_claims = input_claim_schemas
            .iter()
            .map(|claim| {
                config
                    .datatype
                    .get_fields(&claim.schema.data_type)
                    .map(|field| (claim, field.r#type))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|(_, r#type)| r#type == &DatatypeType::Object)
            .flat_map(|(claim, _)| {
                credential_claim_schemas
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| {
                        c.schema
                            .key
                            .starts_with(&format!("{}{NESTED_CLAIM_MARKER}", claim.schema.key))
                    })
                    .map(|(i, c)| ProofInputClaimSchema {
                        schema: c.schema.clone(),
                        required: c.required,
                        order: i as u32,
                    })
            })
            .collect::<Vec<_>>();

        input_claim_schemas.extend(object_nested_claims);
        let mut proof_input_claims: Vec<_> = input_claim_schemas
            .iter()
            .filter(|claim_schema| !claim_schema.schema.key.contains(NESTED_CLAIM_MARKER))
            .map(|claim_schema| {
                let claims = claims.iter().filter(|c| {
                    c.claim
                        .schema
                        .as_ref()
                        .is_some_and(|s| s.id == claim_schema.schema.id)
                });

                if claim_schema.schema.array {
                    return ProofClaimDTO {
                        schema: claim_schema.clone().into(),
                        value: Some(ProofClaimValueDTO::Claims(
                            claims
                                .map(|c| {
                                    let mut claim_schema = claim_schema.clone();
                                    claim_schema.schema.array = false;
                                    ProofClaimDTO {
                                        schema: claim_schema.into(),
                                        path: c.claim.path.to_string(),
                                        value: Some(ProofClaimValueDTO::Value(
                                            c.claim.value.to_owned(),
                                        )),
                                    }
                                })
                                .collect(),
                        )),
                        path: claim_schema.schema.key.to_string(),
                    };
                }
                match claims.last() {
                    Some(claim) => ProofClaimDTO {
                        schema: claim_schema.clone().into(),
                        path: claim.claim.path.to_string(),
                        value: Some(ProofClaimValueDTO::Value(claim.claim.value.to_owned())),
                    },
                    None => ProofClaimDTO {
                        schema: claim_schema.clone().into(),
                        path: claim_schema.schema.key.to_string(),
                        value: Some(ProofClaimValueDTO::Claims(vec![])),
                    },
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
                let filtered_claims = claims.iter().filter(|c| {
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

                if let Some(ProofClaimValueDTO::Claims(claims)) = &mut parent_proof_claim.value {
                    // Filter out duplicates
                    if claims
                        .iter()
                        .any(|c| c.schema.key == claim_schema.schema.key)
                    {
                        return Ok::<_, ServiceError>(());
                    }

                    if parent_proof_claim.schema.array {
                        claims.extend(filtered_claims.into_iter().map(|c| {
                            let mut claim_schema = claim_schema.clone();
                            claim_schema.schema.array = false;
                            ProofClaimDTO {
                                schema: claim_schema.into(),
                                path: c.claim.path.to_string(),
                                value: Some(ProofClaimValueDTO::Value(c.claim.value.to_owned())),
                            }
                        }));
                    } else if claim_schema.schema.array {
                        let mut claim_schema = claim_schema.clone();
                        claim_schema.schema.array = true;

                        claims.push(ProofClaimDTO {
                            schema: claim_schema.clone().into(),
                            path: format!(
                                "{}{}{}",
                                parent_proof_claim.path,
                                NESTED_CLAIM_MARKER,
                                claim_schema.schema.key
                            ),
                            value: Some(ProofClaimValueDTO::Claims(
                                filtered_claims
                                    .into_iter()
                                    .map(|c| {
                                        let mut claim_schema = claim_schema.clone();
                                        claim_schema.schema.array = false;
                                        ProofClaimDTO {
                                            schema: claim_schema.into(),
                                            path: c.claim.path.to_string(),
                                            value: Some(ProofClaimValueDTO::Value(
                                                c.claim.value.to_owned(),
                                            )),
                                        }
                                    })
                                    .collect(),
                            )),
                        });
                    } else {
                        let claim = filtered_claims.last();
                        claims.push(ProofClaimDTO {
                            schema: claim_schema.clone().into(),
                            path: claim
                                .map(|claim| claim.claim.path.to_string())
                                .unwrap_or_else(|| claim_schema.schema.key.to_string()),
                            value: claim.map(|claim| {
                                ProofClaimValueDTO::Value(claim.claim.value.to_owned())
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

    let redirect_uri = proof.redirect_uri.to_owned();
    let list_item_response: ProofListItemResponseDTO = proof.try_into()?;

    Ok(ProofDetailResponseDTO {
        id: list_item_response.id,
        created_date: list_item_response.created_date,
        last_modified: list_item_response.last_modified,
        issuance_date: list_item_response.issuance_date,
        requested_date: list_item_response.requested_date,
        retain_until_date: list_item_response.retain_until_date,
        completed_date: list_item_response.completed_date,
        verifier_did: list_item_response.verifier_did,
        holder_did_id,
        transport: list_item_response.transport,
        exchange: list_item_response.exchange,
        state: list_item_response.state,
        organisation_id: Some(organisation_id),
        schema: list_item_response.schema,
        redirect_uri,
        proof_inputs,
        claims_removed_at: claims_removed_event.map(|event| event.created_date),
    })
}

fn renest_proof_claims(claims: Vec<ProofClaimDTO>, prefix: &str) -> Vec<ProofClaimDTO> {
    let mut result: Vec<ProofClaimDTO> = vec![];
    let mut nested_grouped_by_root: HashMap<String, Vec<ProofClaimDTO>> = HashMap::new();
    let mut arrays_grouped_by_root: HashMap<String, Vec<ProofClaimDTO>> = HashMap::new();

    for mut claim in claims {
        let claim_key = claim.schema.key.clone();
        if claim.schema.array && !claim_key.contains(NESTED_CLAIM_MARKER) {
            arrays_grouped_by_root
                .entry(claim_key.to_owned())
                .or_default()
                .push(claim);
        } else if let Some((root_claim, remaining_path)) = claim_key.split_once(NESTED_CLAIM_MARKER)
        {
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
        let path = if prefix.is_empty() {
            root_key.clone()
        } else {
            format!("{}{}{}", prefix, NESTED_CLAIM_MARKER, root_key)
        };

        result.push(ProofClaimDTO {
            schema: ProofClaimSchemaResponseDTO {
                id: Uuid::new_v4().into(),
                required: true,
                key: root_key.to_string(),
                data_type: DatatypeType::Object.to_string(),
                claims: vec![],
                array: false,
            },
            path: path.clone(),
            value: Some(ProofClaimValueDTO::Claims(renest_proof_claims(
                inner_claims,
                &path,
            ))),
        })
    }

    for (root_key, inner_claims) in arrays_grouped_by_root {
        let path = if prefix.is_empty() {
            root_key.clone()
        } else {
            format!("{}{}{}", prefix, NESTED_CLAIM_MARKER, root_key)
        };

        result.push(ProofClaimDTO {
            schema: ProofClaimSchemaResponseDTO {
                id: Uuid::new_v4().into(),
                required: true,
                key: root_key.to_string(),
                data_type: DatatypeType::Object.to_string(),
                claims: vec![],
                array: true,
            },
            path,
            value: Some(ProofClaimValueDTO::Claims(inner_claims)),
        })
    }

    result
}

pub fn get_holder_proof_detail(
    value: Proof,
    config: &CoreConfig,
    claims_removed_event: Option<History>,
) -> Result<ProofDetailResponseDTO, ServiceError> {
    let organisation_id = value
        .holder_did
        .as_ref()
        .and_then(|did| did.organisation.as_ref().map(|o| o.id));

    let holder_did_id = value.holder_did.as_ref().map(|did| did.id);

    let redirect_uri = value.redirect_uri.to_owned();

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
            path: proof_claim.claim.path.to_string(),
        };

        match submitted_credentials.entry(credential.id) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().0.push(claim);
            }
            Entry::Vacant(entry) => {
                entry.insert((
                    vec![claim],
                    credential_detail_response_from_model(credential.clone(), config)?,
                    credential_schema.clone().into(),
                ));
            }
        }
    }

    let proof_inputs = submitted_credentials
        .into_values()
        .map(|(claims, credential, credential_schema)| ProofInputDTO {
            claims: renest_proof_claims(claims, ""),
            credential: Some(credential),
            credential_schema,
            validity_constraint: None,
        })
        .collect();

    let list_item_response: ProofListItemResponseDTO = value.try_into()?;

    Ok(ProofDetailResponseDTO {
        id: list_item_response.id,
        created_date: list_item_response.created_date,
        last_modified: list_item_response.last_modified,
        issuance_date: list_item_response.issuance_date,
        requested_date: list_item_response.requested_date,
        retain_until_date: list_item_response.retain_until_date,
        completed_date: list_item_response.completed_date,
        verifier_did: list_item_response.verifier_did,
        holder_did_id,
        transport: list_item_response.transport,
        exchange: list_item_response.exchange,
        state: list_item_response.state,
        organisation_id,
        schema: list_item_response.schema,
        redirect_uri,
        proof_inputs,
        claims_removed_at: claims_removed_event.map(|event| event.created_date),
    })
}

pub fn proof_from_create_request(
    request: CreateProofRequestDTO,
    now: OffsetDateTime,
    schema: ProofSchema,
    transport: &str,
    verifier_did: Did,
    verifier_key: Option<Key>,
) -> Proof {
    Proof {
        id: Uuid::new_v4().into(),
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
        transport: transport.to_owned(),
        claims: None,
        verifier_did: Some(verifier_did),
        holder_did: None,
        verifier_key,
        interaction: None,
    }
}

pub fn proof_for_scan_to_verify(
    exchange: &str,
    schema: ProofSchema,
    transport: &str,
    interaction_data: Vec<u8>,
) -> Proof {
    let now = OffsetDateTime::now_utc();
    Proof {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        issuance_date: now,
        exchange: exchange.to_owned(),
        redirect_uri: None,
        state: Some(vec![proof::ProofState {
            created_date: now,
            last_modified: now,
            state: ProofStateEnum::Created,
        }]),
        schema: Some(schema),
        transport: transport.to_owned(),
        claims: None,
        verifier_did: None,
        holder_did: None,
        verifier_key: None,
        interaction: Some(Interaction {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            host: None,
            data: Some(interaction_data),
        }),
    }
}
