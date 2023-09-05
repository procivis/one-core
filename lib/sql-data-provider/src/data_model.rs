use one_core::{
    model::common::SortDirection,
    repository::{
        data_provider::{
            CredentialClaimSchemaResponse, CredentialState, DetailCredentialClaimResponse,
            DetailCredentialResponse, DetailProofClaim, DetailProofClaimSchema, DetailProofSchema,
            GetDidDetailsResponse, ListCredentialSchemaResponse, ProofDetailsResponse,
            ProofRequestState, ProofsDetailResponse,
        },
        error::DataLayerError,
    },
};
use sea_orm::{FromQueryResult, Order};

use time::OffsetDateTime;

use crate::entity;

use super::entity::{
    claim, claim_schema, credential_schema, credential_state, did, proof, proof_schema, proof_state,
};

pub fn order_from_sort_direction(direction: SortDirection) -> Order {
    match direction {
        SortDirection::Ascending => Order::Asc,
        SortDirection::Descending => Order::Desc,
    }
}

#[derive(Clone, Debug)]
pub struct GetListQueryParams<SortableColumn> {
    // pagination
    pub page: u32,
    pub page_size: u32,

    // sorting
    pub sort: Option<SortableColumn>,
    pub sort_direction: Option<SortDirection>,

    // filtering
    pub name: Option<String>,
    pub organisation_id: String,
}

#[derive(Debug, Clone, FromQueryResult)]
pub(crate) struct CredentialSchemaClaimSchemaCombined {
    pub id: String,
    pub datatype: String,
}

impl From<did::Model> for GetDidDetailsResponse {
    fn from(value: did::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id: value.organisation_id,
            did: value.did,
            did_type: value.type_field.into(),
            did_method: value.method,
        }
    }
}

pub fn convert_credential_state(
    state: entity::credential_state::CredentialState,
) -> CredentialState {
    match state {
        entity::credential_state::CredentialState::Created => CredentialState::Created,
        entity::credential_state::CredentialState::Pending => CredentialState::Pending,
        entity::credential_state::CredentialState::Offered => CredentialState::Offered,
        entity::credential_state::CredentialState::Accepted => CredentialState::Accepted,
        entity::credential_state::CredentialState::Rejected => CredentialState::Rejected,
        entity::credential_state::CredentialState::Revoked => CredentialState::Revoked,
        entity::credential_state::CredentialState::Error => CredentialState::Error,
    }
}

impl From<CredentialState> for entity::credential_state::CredentialState {
    fn from(value: CredentialState) -> Self {
        match value {
            CredentialState::Created => entity::credential_state::CredentialState::Created,
            CredentialState::Pending => entity::credential_state::CredentialState::Pending,
            CredentialState::Offered => entity::credential_state::CredentialState::Offered,
            CredentialState::Accepted => entity::credential_state::CredentialState::Accepted,
            CredentialState::Rejected => entity::credential_state::CredentialState::Rejected,
            CredentialState::Revoked => entity::credential_state::CredentialState::Revoked,
            CredentialState::Error => entity::credential_state::CredentialState::Error,
        }
    }
}

pub fn convert_proof_state(state: entity::proof_state::ProofRequestState) -> ProofRequestState {
    match state {
        entity::proof_state::ProofRequestState::Created => ProofRequestState::Created,
        entity::proof_state::ProofRequestState::Pending => ProofRequestState::Pending,
        entity::proof_state::ProofRequestState::Offered => ProofRequestState::Offered,
        entity::proof_state::ProofRequestState::Accepted => ProofRequestState::Accepted,
        entity::proof_state::ProofRequestState::Rejected => ProofRequestState::Rejected,
        entity::proof_state::ProofRequestState::Error => ProofRequestState::Error,
    }
}

impl From<ProofRequestState> for entity::proof_state::ProofRequestState {
    fn from(value: ProofRequestState) -> Self {
        match value {
            ProofRequestState::Created => entity::proof_state::ProofRequestState::Created,
            ProofRequestState::Pending => entity::proof_state::ProofRequestState::Pending,
            ProofRequestState::Offered => entity::proof_state::ProofRequestState::Offered,
            ProofRequestState::Accepted => entity::proof_state::ProofRequestState::Accepted,
            ProofRequestState::Rejected => entity::proof_state::ProofRequestState::Rejected,
            ProofRequestState::Error => entity::proof_state::ProofRequestState::Error,
        }
    }
}

pub(crate) fn detail_credential_claim_response_from_model(
    value: ClaimClaimSchemaCombined,
) -> DetailCredentialClaimResponse {
    DetailCredentialClaimResponse {
        schema: CredentialClaimSchemaResponse {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key,
            datatype: value.datatype,
        },
        value: value.value,
    }
}

#[derive(Debug, FromQueryResult, Clone)]
pub(crate) struct CredentialDidCredentialSchemaCombined {
    // credential table
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub credential: Vec<u8>,

    // did table
    pub did: Option<String>,

    // credential_state table
    pub state: credential_state::CredentialState,

    // credential_schema table
    pub schema_id: String,
    pub schema_name: String,
    pub schema_format: String,
    pub schema_revocation_method: String,
    pub schema_organisation_id: String,
    pub schema_created_date: OffsetDateTime,
    pub schema_last_modified: OffsetDateTime,
}

fn list_credential_schema_response_from_model_combined(
    value: CredentialDidCredentialSchemaCombined,
) -> ListCredentialSchemaResponse {
    ListCredentialSchemaResponse {
        id: value.schema_id,
        created_date: value.schema_created_date,
        last_modified: value.schema_last_modified,
        name: value.schema_name,
        format: value.schema_format,
        revocation_method: value.schema_revocation_method,
        organisation_id: value.schema_organisation_id,
    }
}

fn list_credential_schema_response_from_model(
    value: credential_schema::Model,
) -> ListCredentialSchemaResponse {
    ListCredentialSchemaResponse {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
        format: value.format,
        revocation_method: value.revocation_method,
        organisation_id: value.organisation_id,
    }
}

#[derive(Debug, Clone, FromQueryResult)]
pub(crate) struct ClaimClaimSchemaCombined {
    pub credential_id: String,
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub value: String,
    pub key: String,
    pub datatype: String,
}

pub(super) fn proof_detail_response_from_models_with_claims(
    proof: proof::Model,
    verifier_did: did::Model,
    history: Vec<proof_state::Model>,
    proof_schema: proof_schema::Model,
    claims: Vec<(
        Option<claim::Model>,
        claim_schema::Model,
        credential_schema::Model,
    )>,
) -> ProofDetailsResponse {
    ProofDetailsResponse {
        id: proof.id,
        created_date: proof.created_date,
        last_modified: proof.last_modified,
        issuance_date: proof.issuance_date,
        requested_date: get_proof_requested_date(&history),
        completed_date: get_proof_completed_date(&history),
        organisation_id: proof_schema.organisation_id.clone(),
        state: get_current_proof_state(&history),
        verifier_did: verifier_did.did,
        transport: proof.transport,
        receiver_did_id: proof.receiver_did_id,
        schema: DetailProofSchema {
            id: proof_schema.id,
            name: proof_schema.name,
            created_date: proof_schema.created_date,
            last_modified: proof_schema.last_modified,
            organisation_id: proof_schema.organisation_id,
        },
        claims: claims
            .into_iter()
            .map(proof_detail_claim_from_models)
            .collect(),
    }
}

// impl DetailProofClaim {
//     pub(crate) fn from_models(
//         (claim, claim_schema, credential_schema): (
//             claim::Model,
//             claim_schema::Model,
//             credential_schema::Model,
//         ),
//     ) -> Self {
//         Self {
//             schema: DetailProofClaimSchema::from_models(claim_schema, credential_schema),
//             value: claim.value,
//         }
//     }
// }

// impl DetailProofClaimSchema {
//     fn from_models(
//         claim_schema: claim_schema::Model,
//         credential_schema: credential_schema::Model,
//     ) -> Self {
//         Self {
//             id: claim_schema.id,
//             key: claim_schema.key,
//             datatype: claim_schema.datatype,
//             created_date: claim_schema.created_date,
//             last_modified: claim_schema.last_modified,
//             credential_schema: credential_schema.into(),
//         }
//     }
// }

#[derive(Debug, Clone, FromQueryResult)]
pub(crate) struct ProofsCombined {
    // proof
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub organisation_id: String,
    pub transport: String,

    // state
    pub state: entity::proof_state::ProofRequestState,

    // did
    pub verifier_did: String,

    // proof schema
    pub schema_id: String,
    pub schema_name: String,
    pub schema_created_date: OffsetDateTime,
    pub schema_last_modified: OffsetDateTime,
}

pub(super) fn proof_detail_response_from_models(
    (value, history): (ProofsCombined, Vec<proof_state::Model>),
) -> ProofsDetailResponse {
    ProofsDetailResponse {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        issuance_date: value.issuance_date,
        requested_date: get_proof_requested_date(&history),
        completed_date: get_proof_completed_date(&history),
        state: convert_proof_state(value.state),
        organisation_id: value.organisation_id.clone(),
        verifier_did: value.verifier_did,
        schema: DetailProofSchema {
            id: value.schema_id,
            name: value.schema_name,
            created_date: value.schema_created_date,
            last_modified: value.schema_last_modified,
            organisation_id: value.organisation_id,
        },
    }
}

pub(crate) fn detail_credential_from_combined_credential_did_and_credential_schema(
    value: CredentialDidCredentialSchemaCombined,
    claims: &[ClaimClaimSchemaCombined],
) -> Result<DetailCredentialResponse, DataLayerError> {
    Ok(DetailCredentialResponse {
        id: value.id.to_owned(),
        created_date: value.created_date,
        issuance_date: value.issuance_date,
        state: convert_credential_state(value.state),
        last_modified: value.last_modified,
        issuer_did: value.did.to_owned(),
        claims: claims
            .iter()
            .filter(|claim| claim.credential_id == value.id)
            .cloned()
            .map(detail_credential_claim_response_from_model)
            .collect(),
        schema: list_credential_schema_response_from_model_combined(value.clone()),
        credential: value.credential,
    })
}

pub(crate) fn proof_detail_claim_from_models(
    (claim, claim_schema, credential_schema): (
        Option<claim::Model>,
        claim_schema::Model,
        credential_schema::Model,
    ),
) -> DetailProofClaim {
    DetailProofClaim {
        schema: detail_proof_claim_schema_from_models(claim_schema, credential_schema),
        value: claim.map(|c| c.value),
    }
}

fn detail_proof_claim_schema_from_models(
    claim_schema: claim_schema::Model,
    credential_schema: credential_schema::Model,
) -> DetailProofClaimSchema {
    DetailProofClaimSchema {
        id: claim_schema.id,
        key: claim_schema.key,
        datatype: claim_schema.datatype,
        created_date: claim_schema.created_date,
        last_modified: claim_schema.last_modified,
        credential_schema: list_credential_schema_response_from_model(credential_schema),
    }
}

fn get_current_proof_state(history: &[proof_state::Model]) -> ProofRequestState {
    history
        .iter()
        .max_by_key(|status_entry| status_entry.created_date)
        .map(|entry| convert_proof_state(entry.state.clone()))
        .unwrap_or(ProofRequestState::Error)
}

fn get_proof_requested_date(history: &[proof_state::Model]) -> Option<OffsetDateTime> {
    history
        .iter()
        .find(|entry| entry.state == proof_state::ProofRequestState::Offered)
        .map(|entry| entry.created_date)
}

fn get_proof_completed_date(history: &[proof_state::Model]) -> Option<OffsetDateTime> {
    history
        .iter()
        .find(|entry| {
            [
                proof_state::ProofRequestState::Accepted,
                proof_state::ProofRequestState::Rejected,
                proof_state::ProofRequestState::Error,
            ]
            .contains(&entry.state)
        })
        .map(|entry| entry.created_date)
}

impl From<&ProofsCombined> for proof::Model {
    fn from(value: &ProofsCombined) -> Self {
        Self {
            id: value.id.clone(),
            created_date: value.created_date,
            last_modified: value.last_modified,
            issuance_date: value.issuance_date,
            transport: value.transport.clone(),
            verifier_did_id: value.verifier_did.clone(),
            receiver_did_id: None,
            proof_schema_id: value.schema_id.clone(),
        }
    }
}
