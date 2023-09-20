use super::dto::{
    CreateProofRequestDTO, ProofClaimDTO, ProofDetailResponseDTO, ProofListItemResponseDTO,
};
use crate::{
    model::{
        claim::Claim,
        did::Did,
        proof::{self, Proof, ProofStateEnum},
        proof_schema::{ProofSchema, ProofSchemaClaim},
    },
    service::error::ServiceError,
};
use time::OffsetDateTime;
use uuid::Uuid;

impl TryFrom<Proof> for ProofListItemResponseDTO {
    type Error = ServiceError;

    fn try_from(value: Proof) -> Result<Self, Self::Error> {
        let schema = value
            .schema
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

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
            schema: schema.into(),
        })
    }
}

impl TryFrom<Proof> for ProofDetailResponseDTO {
    type Error = ServiceError;

    fn try_from(value: Proof) -> Result<Self, Self::Error> {
        let holder_did_id = value.holder_did.as_ref().map(|did| did.id).to_owned();
        let schema = value
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?;
        let claims = value
            .claims
            .as_ref()
            .ok_or(ServiceError::MappingError("claims is None".to_string()))?;
        let proof_claim_schemas =
            schema
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
        Ok(Self {
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
