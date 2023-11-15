use super::dto::{
    CreateProofRequestDTO, ProofClaimDTO, ProofDetailResponseDTO, ProofListItemResponseDTO,
};
use crate::common_mapper::get_proof_claim_schemas_from_proof;
use crate::{
    model::{
        claim::Claim,
        claim_schema::ClaimSchema,
        credential_schema::CredentialSchema,
        did::Did,
        proof::{self, Proof, ProofStateEnum},
        proof_schema::{ProofSchema, ProofSchemaClaim},
    },
    provider::transport_protocol::dto::ProofClaimSchema,
    service::error::ServiceError,
};
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

pub fn get_verifier_proof_detail(value: Proof) -> Result<ProofDetailResponseDTO, ServiceError> {
    let holder_did_id = value.holder_did.as_ref().map(|did| did.id.clone());
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

    let holder_did_id = value.holder_did.as_ref().map(|did| did.id.clone());

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
