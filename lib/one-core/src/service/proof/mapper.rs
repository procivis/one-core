use super::dto::{
    CreateProofRequestDTO, ProofClaimDTO, ProofDetailResponseDTO, ProofListItemResponseDTO,
};
use crate::model::key::Key;
use crate::{
    model::{
        claim_schema::ClaimSchema,
        credential_schema::CredentialSchema,
        did::Did,
        history::{History, HistoryAction, HistoryEntityType},
        proof::{self, Proof, ProofStateEnum},
        proof_schema::{ProofSchema, ProofSchemaClaim},
    },
    provider::transport_protocol::dto::ProofClaimSchema,
    service::error::ServiceError,
};
use dto_mapper::convert_inner;
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

pub fn get_verifier_proof_detail(value: Proof) -> Result<ProofDetailResponseDTO, ServiceError> {
    let holder_did_id = value.holder_did.as_ref().map(|did| did.id);
    let schema = value
        .schema
        .as_ref()
        .ok_or(ServiceError::MappingError("schema is None".to_string()))?;
    let claims = value
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

    let credentials = value
        .claims
        .iter()
        .flatten()
        .filter_map(|claim| claim.credential.clone())
        .map(TryInto::try_into)
        .collect::<Result<_, _>>()?;

    let claims = match (schema.input_schemas.as_ref(), schema.claim_schemas.as_ref()) {
        (Some(input_schemas), _) if !input_schemas.is_empty() => input_schemas
            .iter()
            .filter_map(|input_schema| input_schema.claim_schemas.as_ref())
            .flatten()
            .map(|proof_claim_schema| {
                let claim = claims
                    .iter()
                    .find(|c| {
                        c.claim
                            .schema
                            .as_ref()
                            .is_some_and(|s| s.id == proof_claim_schema.schema.id)
                    })
                    .map(|c| &c.claim)
                    .cloned();

                ProofClaimDTO {
                    schema: proof_claim_schema.clone().into(),
                    value: claim.map(|c| c.value),
                }
            })
            .collect(),
        // TODO: ONE-1733
        (_, Some(proof_claim_schemas)) if !proof_claim_schemas.is_empty() => proof_claim_schemas
            .iter()
            .map(|proof_claim_schema| {
                let claim = claims
                    .iter()
                    .find(|c| {
                        c.claim
                            .schema
                            .as_ref()
                            .is_some_and(|s| s.id == proof_claim_schema.schema.id)
                    })
                    .map(|c| &c.claim)
                    .cloned();

                ProofClaimDTO {
                    schema: proof_claim_schema.clone().into(),
                    value: claim.map(|c| c.value),
                }
            })
            .collect(),
        (_, _) => {
            // TODO: ONE-1733
            return Err(ServiceError::MappingError(
                "input_schemas or proof claim_schemas is missing".to_string(),
            ));
        }
    };

    let redirect_uri = value.redirect_uri.to_owned();
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
        redirect_uri,
        credentials,
    })
}

pub fn get_holder_proof_detail(value: Proof) -> Result<ProofDetailResponseDTO, ServiceError> {
    let holder_did = value
        .holder_did
        .as_ref()
        .ok_or(ServiceError::MappingError("holder_did is None".to_string()))?;

    let organisation_id = holder_did
        .organisation
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "organisation is None".to_string(),
        ))?
        .id;

    let holder_did_id = holder_did.id.to_owned();

    let redirect_uri = value.redirect_uri.to_owned();
    let credentials = value
        .claims
        .iter()
        .flatten()
        .filter_map(|claim| claim.credential.clone())
        .map(TryInto::try_into)
        .collect::<Result<_, _>>()?;

    let list_item_response: ProofListItemResponseDTO = value.try_into()?;

    Ok(ProofDetailResponseDTO {
        // TODO: properly reconstruct claims when proof submitted
        claims: vec![],
        id: list_item_response.id,
        created_date: list_item_response.created_date,
        last_modified: list_item_response.last_modified,
        issuance_date: list_item_response.issuance_date,
        requested_date: list_item_response.requested_date,
        completed_date: list_item_response.completed_date,
        verifier_did: list_item_response.verifier_did,
        holder_did_id: Some(holder_did_id),
        transport: list_item_response.transport,
        state: list_item_response.state,
        organisation_id,
        schema: list_item_response.schema,
        redirect_uri,
        credentials,
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

impl TryFrom<ProofClaimSchema> for ProofSchemaClaim {
    type Error = ServiceError;

    fn try_from(value: ProofClaimSchema) -> Result<Self, Self::Error> {
        let id = Uuid::from_str(&value.id)?.into();
        let credential_schema_id = Uuid::from_str(&value.credential_schema.id)?;

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
                wallet_storage_type: value.credential_schema.wallet_storage_type,
                format: value.credential_schema.format,
                revocation_method: value.credential_schema.revocation_method,
                claim_schemas: None,
                organisation: None,
            }),
        })
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
