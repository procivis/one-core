use super::dto::{
    CreateProofRequestDTO, PresentationDefinitionResponseDTO, ProofClaimDTO,
    ProofDetailResponseDTO, ProofListItemResponseDTO,
};
use crate::model::credential::Credential;
use crate::service::credential::dto::CredentialDetailResponseDTO;
use crate::service::proof::dto::{
    PresentationDefinitionFieldDTO, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionRuleDTO,
    PresentationDefinitionRuleTypeEnum,
};
use crate::{
    model::{
        claim::Claim,
        claim_schema::ClaimSchema,
        credential_schema::CredentialSchema,
        did::Did,
        proof::{self, Proof, ProofStateEnum},
        proof_schema::{ProofSchema, ProofSchemaClaim},
    },
    service::error::ServiceError,
    transport_protocol::dto::ProofClaimSchema,
};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use time::OffsetDateTime;
use uuid::Uuid;

impl TryFrom<Proof> for ProofListItemResponseDTO {
    type Error = ServiceError;

    fn try_from(value: Proof) -> Result<Self, Self::Error> {
        let states = value
            .state
            .ok_or(ServiceError::MappingError("state is None".to_string()))?;
        let latest_state = states
            .get(0)
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?;
        let requested_date = states
            .iter()
            .find(|state| state.state == ProofStateEnum::Offered)
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
            verifier_did: value
                .verifier_did
                .ok_or(ServiceError::MappingError(
                    "verifier_did is None".to_string(),
                ))?
                .did,
            transport: value.transport,
            state: latest_state.state.clone(),
            schema: value.schema.map(|schema| schema.into()),
        })
    }
}

pub fn create_presentation_definition_field(
    claim_schema: &ProofClaimSchema,
    credentials: &Vec<Credential>,
    index: usize,
) -> Result<PresentationDefinitionFieldDTO, ServiceError> {
    let mut key_map: HashMap<String, String> = HashMap::new();
    for credential in credentials {
        for claim in credential
            .claims
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "credential claims is None".to_string(),
            ))?
        {
            if claim
                .schema
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "claim schema is None".to_string(),
                ))?
                .key
                == claim_schema.key
            {
                key_map.insert(credential.id.to_string(), claim_schema.key.to_string());
            }
        }
    }
    Ok(PresentationDefinitionFieldDTO {
        id: claim_schema.id.to_string(),
        name: Some(format!("claim_{}", index)),
        purpose: None,
        required: Some(claim_schema.required),
        key_map,
    })
}

pub fn create_requested_credential(
    claim_schemas: &[ProofClaimSchema],
    credentials: &[Credential],
    index: usize,
    credential_schema_id: &String,
) -> Result<PresentationDefinitionRequestedCredentialResponseDTO, ServiceError> {
    let credentials: Vec<_> = credentials
        .iter()
        .filter(|credential| {
            if let Some(schema) = &credential.schema {
                schema.id.to_string() == *credential_schema_id.to_string()
            } else {
                false
            }
        })
        .cloned()
        .collect();

    Ok(PresentationDefinitionRequestedCredentialResponseDTO {
        id: format!("input_{}", index),
        name: None,
        purpose: None,
        fields: claim_schemas
            .iter()
            .enumerate()
            .map(|(index, claim_schema)| {
                create_presentation_definition_field(claim_schema, credentials.as_ref(), index)
            })
            .collect::<Result<Vec<_>, ServiceError>>()?,
        applicable_credentials: credentials
            .iter()
            .map(|credential| credential.id.to_string())
            .collect(),
    })
}

pub fn presentation_definition_from_proof(
    proof: Proof,
    credentials: Vec<Credential>,
    claim_schemas: Vec<ProofClaimSchema>,
) -> Result<PresentationDefinitionResponseDTO, ServiceError> {
    let mut credential_schema_ids: HashSet<String> = HashSet::new();
    for credential in &credentials {
        credential_schema_ids.insert(
            credential
                .schema
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "credential schema is None".to_string(),
                ))?
                .id
                .to_string(),
        );
    }

    // If no match is found we need to create a dummy entry in order to generate one empty requestedCredentials
    if credential_schema_ids.is_empty() {
        credential_schema_ids.insert("dummy-credential-schema-id".to_string());
    }

    Ok(PresentationDefinitionResponseDTO {
        request_groups: vec![PresentationDefinitionRequestGroupResponseDTO {
            id: proof.id.to_string(),
            name: None,
            purpose: None,
            rule: PresentationDefinitionRuleDTO {
                r#type: PresentationDefinitionRuleTypeEnum::All,
                min: None,
                max: None,
                count: None,
            },
            requested_credentials: credential_schema_ids
                .iter()
                .enumerate()
                .map(|(index, credential_schema)| {
                    create_requested_credential(
                        &claim_schemas,
                        &credentials,
                        index,
                        credential_schema,
                    )
                })
                .collect::<Result<Vec<_>, ServiceError>>()?,
        }],
        credentials: credentials
            .into_iter()
            .map(|credential| credential.try_into())
            .collect::<Result<Vec<CredentialDetailResponseDTO>, _>>()?,
    })
}

pub fn get_verifier_proof_detail(value: Proof) -> Result<ProofDetailResponseDTO, ServiceError> {
    let holder_did_id = value.holder_did.as_ref().map(|did| did.id).to_owned();
    let schema = value
        .schema
        .as_ref()
        .ok_or(ServiceError::MappingError("schema is None".to_string()))?;
    let claims = value
        .claims
        .as_ref()
        .ok_or(ServiceError::MappingError("claims is None".to_string()))?;
    let proof_claim_schemas = schema
        .claim_schemas
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "claim_schemas is None".to_string(),
        ))?;
    let organisation_id = schema
        .organisation
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "organisation is None".to_string(),
        ))?
        .id;
    let claims = proof_claim_schemas
        .iter()
        .map(|proof_claim_schema| {
            let claim = claims
                .iter()
                .find(|c| {
                    c.schema
                        .as_ref()
                        .is_some_and(|s| s.id == proof_claim_schema.schema.id)
                })
                .cloned();
            proof_claim_from_claim(proof_claim_schema.clone(), claim)
        })
        .collect::<Result<Vec<ProofClaimDTO>, ServiceError>>()?;

    let list_item_response: ProofListItemResponseDTO = value.try_into()?;
    Ok(ProofDetailResponseDTO {
        claims,
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
    })
}

pub fn get_proof_claim_schemas_from_proof(
    value: &Proof,
) -> Result<Vec<ProofClaimSchema>, ServiceError> {
    let interaction_data = value
        .interaction
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "interaction is None".to_string(),
        ))?
        .data
        .to_owned()
        .ok_or(ServiceError::MappingError(
            "interaction data is missing".to_string(),
        ))?;
    let json_data = String::from_utf8(interaction_data)
        .map_err(|e| ServiceError::MappingError(e.to_string()))?;

    let proof_claim_schemas: Vec<ProofClaimSchema> =
        serde_json::from_str(&json_data).map_err(|e| ServiceError::MappingError(e.to_string()))?;
    Ok(proof_claim_schemas)
}

pub fn get_holder_proof_detail(value: Proof) -> Result<ProofDetailResponseDTO, ServiceError> {
    let organisation_id = value
        .holder_did
        .as_ref()
        .ok_or(ServiceError::MappingError("holder_did is None".to_string()))?
        .organisation
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "organisation is None".to_string(),
        ))?
        .id;

    let holder_did_id = value.holder_did.as_ref().map(|did| did.id).to_owned();

    let claims = value
        .claims
        .as_ref()
        .ok_or(ServiceError::MappingError("claims is None".to_string()))?;

    let proof_claim_schemas: Vec<ProofClaimSchema> = get_proof_claim_schemas_from_proof(&value)?;

    let claims = claims
        .iter()
        .map(|claim| -> Result<ProofClaimDTO, ServiceError> {
            let proof_claim_schema = proof_claim_schemas
                .iter()
                .find(|c| {
                    claim
                        .schema
                        .as_ref()
                        .is_some_and(|s| s.id.to_string() == c.id)
                })
                .ok_or(ServiceError::MappingError(
                    "proof claim not found".to_string(),
                ))?
                .to_owned();

            proof_claim_from_claim(proof_claim_schema.try_into()?, Some(claim.to_owned()))
        })
        .collect::<Result<Vec<ProofClaimDTO>, ServiceError>>()?;

    let list_item_response: ProofListItemResponseDTO = value.try_into()?;
    Ok(ProofDetailResponseDTO {
        claims,
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
    })
}

pub fn proof_claim_from_claim(
    proof_schema_claim: ProofSchemaClaim,
    claim: Option<Claim>,
) -> Result<ProofClaimDTO, ServiceError> {
    Ok(ProofClaimDTO {
        schema: proof_schema_claim.try_into()?,
        value: claim.map(|c| c.value),
    })
}

pub fn proof_from_create_request(
    request: CreateProofRequestDTO,
    now: OffsetDateTime,
    schema: ProofSchema,
    verifier_did: Did,
) -> Proof {
    Proof {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        issuance_date: now,
        transport: request.transport,
        state: Some(vec![proof::ProofState {
            created_date: now,
            last_modified: now,
            state: ProofStateEnum::Created,
        }]),
        schema: Some(schema),
        claims: None,
        verifier_did: Some(verifier_did),
        holder_did: None,
        interaction: None,
    }
}

impl TryFrom<ProofClaimSchema> for ProofSchemaClaim {
    type Error = ServiceError;

    fn try_from(value: ProofClaimSchema) -> Result<Self, Self::Error> {
        let id =
            Uuid::from_str(&value.id).map_err(|e| ServiceError::MappingError(e.to_string()))?;

        let credential_schema_id = Uuid::from_str(&value.credential_schema.id)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;

        Ok(Self {
            schema: ClaimSchema {
                id,
                key: value.key,
                data_type: value.datatype,
                created_date: value.created_date,
                last_modified: value.last_modified,
            },
            required: value.required,
            credential_schema: Some(CredentialSchema {
                id: credential_schema_id,
                deleted_at: None,
                created_date: value.credential_schema.created_date,
                last_modified: value.credential_schema.last_modified,
                name: value.credential_schema.name,
                format: value.credential_schema.format,
                revocation_method: value.credential_schema.revocation_method,
                claim_schemas: None,
                organisation: None,
            }),
        })
    }
}
