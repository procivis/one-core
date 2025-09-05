use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::time::Duration;

use itertools::Itertools;
use one_dto_mapper::convert_inner;
use shared_types::{CredentialId, CredentialSchemaId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateProofRequestDTO, ProofClaimDTO, ProofClaimValueDTO, ProofDetailResponseDTO,
    ProofInputDTO, ProofListItemResponseDTO,
};
use crate::common_mapper::{NESTED_CLAIM_MARKER, NESTED_CLAIM_MARKER_STR};
use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::model::certificate::Certificate;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::model::history::History;
use crate::model::identifier::Identifier;
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::proof::{Proof, ProofClaim, ProofRole, ProofStateEnum};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofSchema};
use crate::model::validity_credential::ValidityCredentialType;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::credential::dto::CredentialDetailResponseDTO;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::error::ServiceError;
use crate::service::proof_schema::dto::ProofClaimSchemaResponseDTO;

fn build_claim_from_credential_claims(
    claims: &[CredentialSchemaClaim],
    key: &str,
    path: String,
    required: bool,
) -> Result<ProofClaimDTO, ServiceError> {
    let claim_schema = &claims
        .iter()
        .find(|claim_schema| claim_schema.schema.key == key)
        .ok_or(ServiceError::MappingError(
            "nested claim is not found by key".into(),
        ))?
        .schema;
    Ok(ProofClaimDTO {
        schema: ProofClaimSchemaResponseDTO {
            id: claim_schema.id,
            requested: true,
            required,
            key: claim_schema.key.to_owned(),
            data_type: claim_schema.data_type.to_owned(),
            claims: vec![],
            array: claim_schema.array,
        },
        path,
        value: Some(ProofClaimValueDTO::Claims(vec![])),
    })
}

fn get_or_insert_proof_container_claim<'a>(
    proof_claims: &'a mut Vec<ProofClaimDTO>,
    path: &str,
    original_key: &str,
    credential_claim_schemas: &[CredentialSchemaClaim],
    required: bool,
) -> Result<&'a mut ProofClaimDTO, ServiceError> {
    match path.rsplit_once(NESTED_CLAIM_MARKER) {
        // It's a nested claim
        Some((prefix, _)) => {
            let parent_claim = get_or_insert_proof_container_claim(
                proof_claims,
                prefix,
                original_key,
                credential_claim_schemas,
                required,
            )?;

            let Some(ProofClaimValueDTO::Claims(claims)) = &mut parent_claim.value else {
                return Err(ServiceError::MappingError(
                    "Parent claim can not have a text value or be empty".into(),
                ));
            };

            if let Some(i) = claims.iter().position(|claim| claim.path == path) {
                Ok(&mut claims[i])
            } else {
                let key = from_path_to_key(path, original_key);
                let mut claim = build_claim_from_credential_claims(
                    credential_claim_schemas,
                    &key,
                    path.into(),
                    required,
                )?;

                // Individual array elements should not have the array flag in nested representation.
                // This adjustment is consistent with the adjustment on the credential detail endpoint.
                if parent_claim.schema.array {
                    claim.schema.array = false;
                }

                claims.push(claim);
                let last = claims.len() - 1;
                Ok(&mut claims[last])
            }
        }
        // It's a root
        None => {
            if let Some(i) = proof_claims
                .iter()
                .position(|claim| claim.schema.key == path)
            {
                Ok(&mut proof_claims[i])
            } else {
                proof_claims.push(build_claim_from_credential_claims(
                    credential_claim_schemas,
                    path,
                    path.into(),
                    required,
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
        let retain_until_date = match (value.completed_date, &value.schema) {
            (Some(completed_date), Some(schema)) if schema.expire_duration != 0 => {
                Some(completed_date + Duration::from_secs(schema.expire_duration as _))
            }
            _ => None,
        };

        Ok(ProofListItemResponseDTO {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            requested_date: value.requested_date,
            retain_until_date,
            transport: value.transport,
            completed_date: value.completed_date,
            verifier: convert_inner(value.verifier_identifier),
            protocol: value.protocol,
            state: value.state,
            role: value.role,
            schema: value.schema.map(|schema| schema.into()),
            profile: value.profile,
        })
    }
}

pub(super) async fn get_verifier_proof_detail(
    proof: Proof,
    config: &CoreConfig,
    claims_removed_event: Option<History>,
    validity_credential_repository: &dyn ValidityCredentialRepository,
) -> Result<ProofDetailResponseDTO, ServiceError> {
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

    let mut credential_for_credential_schema: HashMap<
        CredentialSchemaId,
        CredentialDetailResponseDTO,
    > = HashMap::new();

    for proof_claim in claims.iter() {
        let credential = match proof_claim.credential.clone() {
            Some(cred) => cred,
            None => {
                return Err(ServiceError::MappingError(format!(
                    "Missing credential for proof claim {}",
                    proof_claim.claim.id
                )));
            }
        };

        let credential_schema = match credential.schema.clone() {
            Some(schema) => schema,
            None => {
                return Err(ServiceError::MappingError(format!(
                    "Missing credential schema for credential {}",
                    credential.id
                )));
            }
        };

        let mdoc_validity_credentials = match &credential.schema {
            Some(schema) if schema.format == "MDOC" => {
                validity_credential_repository
                    .get_latest_by_credential_id(credential.id, ValidityCredentialType::Mdoc)
                    .await?
            }
            _ => None,
        };

        let credential_detail =
            credential_detail_response_from_model(credential, config, mdoc_validity_credentials)?;

        credential_for_credential_schema.insert(credential_schema.id, credential_detail);
    }

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

        // construct generated proof input claim schemas that are nested children of explicit input_claim_schemas
        // in order to have all inputs available later to map to particular shared claims
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
            // only object claim schemas can have nested claim schemas
            .filter(|(_, r#type)| r#type == &DatatypeType::Object)
            .flat_map(|(parent_input_claim, _)| {
                credential_claim_schemas
                    .iter()
                    .filter(|c| {
                        c.schema.key.starts_with(&format!(
                            "{}{NESTED_CLAIM_MARKER}",
                            parent_input_claim.schema.key
                        ))
                    })
                    .enumerate()
                    .map(|(i, c)| {
                        // nested claims are required if the explicitly requested object parent is required
                        // and all parents on the path to the requested object are mandatory in the credential schema
                        let required = parent_input_claim.required
                            && c.required
                            && credential_claim_schemas
                                .iter()
                                .filter(|claim_in_between| {
                                    claim_in_between.schema.key.starts_with(&format!(
                                        "{}{NESTED_CLAIM_MARKER}",
                                        parent_input_claim.schema.key
                                    )) && c.schema.key.starts_with(&format!(
                                        "{}{NESTED_CLAIM_MARKER}",
                                        claim_in_between.schema.key
                                    ))
                                })
                                .all(|claim_in_between| claim_in_between.required);

                        ProofInputClaimSchema {
                            schema: c.schema.clone(),
                            required,
                            order: i as u32,
                        }
                    })
            })
            .collect::<Vec<_>>();

        input_claim_schemas.extend(object_nested_claims);

        let mut proof_input_claims =
            nest_proof_claims(claims, credential_claim_schemas, Some(&input_claim_schemas))?;

        input_claim_schemas
            .iter()
            .filter(|input_claim| {
                !input_claim_schemas.iter().any(|other_input_claim| {
                    input_claim.schema.key.starts_with(&format!(
                        "{}{NESTED_CLAIM_MARKER}",
                        other_input_claim.schema.key
                    )) && other_input_claim.schema.array
                })
            })
            .try_for_each(|input_claim| {
                match input_claim.schema.key.rsplit_once(NESTED_CLAIM_MARKER) {
                    Some((prefix, _)) => {
                        let parent_proof_claim = get_or_insert_proof_container_claim(
                            &mut proof_input_claims,
                            prefix,
                            &input_claim.schema.key,
                            credential_claim_schemas,
                            input_claim.required,
                        )?;

                        if parent_proof_claim.value.is_none() {
                            parent_proof_claim.value = Some(ProofClaimValueDTO::Claims(vec![]));
                        }

                        let Some(ProofClaimValueDTO::Claims(parent_proof_claims)) =
                            &mut parent_proof_claim.value
                        else {
                            return Err(ServiceError::MappingError(
                                "Parent claim can not have a text value or be empty".to_string(),
                            ));
                        };

                        if parent_proof_claims
                            .iter()
                            .any(|claim| claim.schema.id == input_claim.schema.id)
                        {
                            return Ok(());
                        }

                        parent_proof_claims.push(ProofClaimDTO {
                            schema: input_claim.clone().into(),
                            path: input_claim.schema.key.clone(),
                            value: None,
                        });
                    }
                    None => {
                        if proof_input_claims
                            .iter()
                            .any(|claim| claim.schema.id == input_claim.schema.id)
                        {
                            return Ok(());
                        }

                        proof_input_claims.push(ProofClaimDTO {
                            schema: input_claim.clone().into(),
                            path: input_claim.schema.key.clone(),
                            value: None,
                        })
                    }
                };

                Ok(())
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

    let holder = convert_inner(proof.holder_identifier.to_owned());

    let verifier_certificate = proof
        .verifier_certificate
        .clone()
        .map(TryInto::try_into)
        .transpose()?;

    let list_item_response: ProofListItemResponseDTO = proof.try_into()?;

    Ok(ProofDetailResponseDTO {
        id: list_item_response.id,
        created_date: list_item_response.created_date,
        last_modified: list_item_response.last_modified,
        requested_date: list_item_response.requested_date,
        retain_until_date: list_item_response.retain_until_date,
        completed_date: list_item_response.completed_date,
        verifier: list_item_response.verifier,
        verifier_certificate,
        holder,
        transport: list_item_response.transport,
        protocol: list_item_response.protocol,
        state: list_item_response.state,
        role: list_item_response.role,
        organisation_id,
        schema: list_item_response.schema,
        redirect_uri,
        proof_inputs,
        claims_removed_at: claims_removed_event.map(|event| event.created_date),
        profile: list_item_response.profile,
    })
}

fn nest_proof_claims(
    flat_claims: &[ProofClaim],
    credential_claim_schemas: &[CredentialSchemaClaim],
    input_claim_schemas: Option<&[ProofInputClaimSchema]>,
) -> Result<Vec<ProofClaimDTO>, ServiceError> {
    let mut proof_input_claims = vec![];

    flat_claims.iter().try_for_each(|proof_claim| {
        let claim_schema = proof_claim
            .claim
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "Missing schema in proof_claim".to_string(),
            ))?;

        let mut schema = if let Some(input_claim_schemas) = input_claim_schemas {
            let Some(input_claim_schema) = input_claim_schemas
                .iter()
                .find(|input_claim_schema| input_claim_schema.schema.id == claim_schema.id)
                .cloned()
            else {
                return Ok(());
            };
            ProofClaimSchemaResponseDTO::from(input_claim_schema)
        } else {
            let credential_schema_claim = credential_claim_schemas
                .iter()
                .find(|schema| schema.schema.id == claim_schema.id)
                .ok_or(ServiceError::MappingError(format!(
                    "missing credential claim schema with id {}",
                    claim_schema.id
                )))?;

            ProofClaimSchemaResponseDTO {
                id: credential_schema_claim.schema.id,
                key: credential_schema_claim.schema.key.to_owned(),
                data_type: credential_schema_claim.schema.data_type.to_owned(),
                claims: vec![],
                array: credential_schema_claim.schema.array,
                // we don't have that information on holder side, so guessing flags here
                requested: true,
                required: credential_schema_claim.required,
            }
        };

        match (
            proof_claim.claim.path.rsplit_once(NESTED_CLAIM_MARKER),
            &proof_claim.claim.value,
        ) {
            (Some((prefix, _)), Some(_)) => {
                let parent_proof_claim = get_or_insert_proof_container_claim(
                    &mut proof_input_claims,
                    prefix,
                    &claim_schema.key,
                    credential_claim_schemas,
                    schema.required,
                )?;

                let Some(ProofClaimValueDTO::Claims(parent_proof_claims)) =
                    &mut parent_proof_claim.value
                else {
                    return Err(ServiceError::MappingError(
                        "Parent claim can not have a text value or be empty".to_string(),
                    ));
                };

                // Individual array elements should not have the array flag in nested representation.
                // This adjustment is consistent with the adjustment on the credential detail endpoint.
                if parent_proof_claim.schema.array {
                    schema.array = false;
                }

                parent_proof_claims.push(map_to_proof_claim_value_dto(proof_claim, schema)?);
            }
            (None, Some(_)) => {
                proof_input_claims.push(map_to_proof_claim_value_dto(proof_claim, schema)?)
            }
            (_, None) => {
                // No value -> insert container claims recursively up to the root
                get_or_insert_proof_container_claim(
                    &mut proof_input_claims,
                    &proof_claim.claim.path,
                    &claim_schema.key,
                    credential_claim_schemas,
                    schema.required,
                )?;
            }
        };

        Ok(())
    })?;
    Ok(proof_input_claims)
}

fn map_to_proof_claim_value_dto(
    proof_claim: &ProofClaim,
    schema: ProofClaimSchemaResponseDTO,
) -> Result<ProofClaimDTO, ServiceError> {
    Ok(ProofClaimDTO {
        schema,
        path: proof_claim.claim.path.clone(),
        value: Some(ProofClaimValueDTO::Value(
            proof_claim
                .claim
                .value
                .as_ref()
                .ok_or(ServiceError::MappingError(format!(
                    "Expected proof claim {} to have value",
                    proof_claim.claim.id
                )))?
                .clone(),
        )),
    })
}

pub(super) async fn get_holder_proof_detail(
    proof: Proof,
    config: &CoreConfig,
    claims_removed_event: Option<History>,
    validity_credential_repository: &dyn ValidityCredentialRepository,
) -> Result<ProofDetailResponseDTO, ServiceError> {
    let organisation_id = [
        proof
            .holder_identifier
            .as_ref()
            .and_then(|identifier| identifier.organisation.as_ref()),
        proof
            .verifier_identifier
            .as_ref()
            .and_then(|identifier| identifier.organisation.as_ref()),
        proof
            .interaction
            .as_ref()
            .and_then(|identifier| identifier.organisation.as_ref()),
    ]
    .into_iter()
    .find(|org| org.is_some())
    .flatten()
    .ok_or(ServiceError::MappingError(
        "Missing organisation".to_string(),
    ))?
    .id;

    let redirect_uri = proof.redirect_uri.to_owned();

    let mut submitted_credentials: HashMap<
        CredentialId,
        (
            Vec<ProofClaim>,
            CredentialDetailResponseDTO,
            CredentialSchema,
        ),
    > = HashMap::new();

    for proof_claim in proof.claims.iter().flatten() {
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

        match submitted_credentials.entry(credential.id) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().0.push(proof_claim.clone());
            }
            Entry::Vacant(entry) => {
                let mdoc_validity_credentials = match &credential.schema {
                    Some(schema) if schema.format == "MDOC" => {
                        validity_credential_repository
                            .get_latest_by_credential_id(
                                credential.id,
                                ValidityCredentialType::Mdoc,
                            )
                            .await?
                    }
                    _ => None,
                };
                entry.insert((
                    vec![proof_claim.clone()],
                    credential_detail_response_from_model(
                        credential.clone(),
                        config,
                        mdoc_validity_credentials,
                    )?,
                    credential_schema.clone(),
                ));
            }
        }
    }

    let proof_inputs = submitted_credentials
        .into_values()
        .map(|(claims, credential, credential_schema)| {
            let credential_claim_schemas =
                credential_schema
                    .claim_schemas
                    .as_ref()
                    .ok_or(ServiceError::MappingError(format!(
                        "Missing claim schemas for credentials schema: {}",
                        credential_schema.id
                    )))?;
            Ok(ProofInputDTO {
                claims: nest_proof_claims(&claims, credential_claim_schemas, None)?,
                credential: Some(credential),
                credential_schema: credential_schema.into(),
                validity_constraint: None,
            })
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;

    let holder = convert_inner(proof.holder_identifier.to_owned());

    let verifier_certificate = proof
        .verifier_certificate
        .clone()
        .map(TryInto::try_into)
        .transpose()?;

    let list_item_response: ProofListItemResponseDTO = proof.try_into()?;

    Ok(ProofDetailResponseDTO {
        id: list_item_response.id,
        created_date: list_item_response.created_date,
        last_modified: list_item_response.last_modified,
        requested_date: list_item_response.requested_date,
        retain_until_date: list_item_response.retain_until_date,
        completed_date: list_item_response.completed_date,
        verifier: list_item_response.verifier,
        verifier_certificate,
        holder,
        transport: list_item_response.transport,
        protocol: list_item_response.protocol,
        state: list_item_response.state,
        role: list_item_response.role,
        organisation_id,
        schema: list_item_response.schema,
        redirect_uri,
        proof_inputs,
        claims_removed_at: claims_removed_event.map(|event| event.created_date),
        profile: list_item_response.profile,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn proof_from_create_request(
    request: CreateProofRequestDTO,
    now: OffsetDateTime,
    schema: ProofSchema,
    transport: String,
    verifier_identifier: Identifier,
    verifier_key: Key,
    verifier_certificate: Option<Certificate>,
    interaction: Option<Interaction>,
) -> Proof {
    Proof {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        protocol: request.protocol,
        redirect_uri: request.redirect_uri,
        state: ProofStateEnum::Created,
        role: ProofRole::Verifier,
        requested_date: None,
        completed_date: None,
        profile: request.profile,
        schema: Some(schema),
        transport,
        claims: None,
        verifier_identifier: Some(verifier_identifier),
        holder_identifier: None,
        verifier_key: Some(verifier_key),
        verifier_certificate,
        interaction,
        proof_blob_id: None,
        engagement: request.engagement,
    }
}

pub fn proof_for_scan_to_verify(
    exchange: &str,
    schema: ProofSchema,
    transport: &str,
    interaction_data: Vec<u8>,
    profile: Option<String>,
) -> Proof {
    let now = OffsetDateTime::now_utc();
    Proof {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        protocol: exchange.to_owned(),
        redirect_uri: None,
        state: ProofStateEnum::Created,
        role: ProofRole::Verifier,
        requested_date: None,
        completed_date: None,
        profile,
        schema: Some(schema.clone()),
        transport: transport.to_owned(),
        claims: None,
        verifier_identifier: None,
        holder_identifier: None,
        verifier_key: None,
        verifier_certificate: None,
        interaction: Some(Interaction {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            host: None,
            data: Some(interaction_data),
            organisation: schema.organisation,
        }),
        proof_blob_id: None,
        engagement: None,
    }
}

fn from_path_to_key(path: &str, original_key: &str) -> String {
    let mut key_parts = original_key.split(NESTED_CLAIM_MARKER).peekable();

    path.split(NESTED_CLAIM_MARKER)
        .filter(move |part| {
            if Some(part) == key_parts.peek() {
                key_parts.next();
                true
            } else {
                false
            }
        })
        .join(NESTED_CLAIM_MARKER_STR)
}
