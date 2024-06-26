use std::collections::HashMap;

use migration::IntoCondition;
use one_core::model::claim::Claim;
use one_core::model::did::Did;
use one_core::model::proof::{GetProofList, Proof, ProofState, SortableProofColumn};
use one_core::model::proof_schema::ProofSchema;
use one_core::repository::error::DataLayerError;
use one_core::service::proof::dto::ProofFilterValue;
use sea_orm::sea_query::SimpleExpr;
use sea_orm::{ColumnTrait, IntoSimpleExpr, Set};
use shared_types::ProofId;

use super::model::ProofListItemModel;
use crate::common::calculate_pages_count;
use crate::entity::proof_state::ProofRequestState;
use crate::entity::{did, proof, proof_claim, proof_schema, proof_state};
use crate::list_query::GetEntityColumn;
use crate::list_query_generic::{
    get_equals_condition, get_string_match_condition, IntoFilterCondition, IntoSortingColumn,
};

impl IntoSortingColumn for SortableProofColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::CreatedDate => proof::Column::CreatedDate.into_simple_expr(),
            Self::SchemaName => proof_schema::Column::Name.into_simple_expr(),
            Self::VerifierDid => did::Column::Id.into_simple_expr(),
            Self::State => proof_state::Column::State.into_simple_expr(),
        }
    }
}

impl IntoFilterCondition for ProofFilterValue {
    fn get_condition(self) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(proof_schema::Column::Name, string_match)
            }
            Self::OrganisationId(organisation_id) => {
                get_equals_condition(proof_schema::Column::OrganisationId, organisation_id)
            }
            Self::ProofStates(states) => proof_state::Column::State
                .is_in(states.into_iter().map(ProofRequestState::from))
                .into_condition(),
            Self::ProofSchemaIds(ids) => proof_schema::Column::Id.is_in(ids).into_condition(),
            Self::ProofIds(ids) => proof::Column::Id.is_in(ids).into_condition(),
        }
    }
}

impl TryFrom<ProofListItemModel> for Proof {
    type Error = DataLayerError;

    fn try_from(value: ProofListItemModel) -> Result<Self, Self::Error> {
        let verifier_did = match value.verifier_did_id {
            None => None,
            Some(verifier_did_id) => Some(Did {
                id: verifier_did_id,
                created_date: value
                    .verifier_did_created_date
                    .ok_or(DataLayerError::MappingError)?,
                last_modified: value
                    .verifier_did_last_modified
                    .ok_or(DataLayerError::MappingError)?,
                name: value
                    .verifier_did_name
                    .ok_or(DataLayerError::MappingError)?,
                did: value.verifier_did.ok_or(DataLayerError::MappingError)?,
                did_type: value
                    .verifier_did_type
                    .ok_or(DataLayerError::MappingError)?
                    .into(),
                did_method: value
                    .verifier_did_method
                    .ok_or(DataLayerError::MappingError)?,
                organisation: None,
                keys: None,
                deactivated: false,
            }),
        };

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            issuance_date: value.issuance_date,
            exchange: value.exchange,
            transport: value.transport,
            redirect_uri: value.redirect_uri,
            state: None,
            schema: Some(ProofSchema {
                id: value.schema_id,
                created_date: value.schema_created_date,
                last_modified: value.schema_last_modified,
                deleted_at: None,
                name: value.schema_name,
                expire_duration: value.expire_duration,
                organisation: None,
                input_schemas: None,
            }),
            claims: None,
            verifier_did,
            holder_did: None,
            verifier_key: None,
            interaction: None,
        })
    }
}

impl From<proof::Model> for Proof {
    fn from(value: proof::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            issuance_date: value.issuance_date,
            exchange: value.exchange,
            transport: value.transport,
            redirect_uri: value.redirect_uri,
            state: None,
            schema: None,
            claims: None,
            verifier_did: None,
            holder_did: None,
            verifier_key: None,
            interaction: None,
        }
    }
}

impl TryFrom<Proof> for proof::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: Proof) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            transport: Set(value.transport),
            issuance_date: Set(value.issuance_date),
            redirect_uri: Set(value.redirect_uri),
            exchange: Set(value.exchange),
            verifier_did_id: Set(value.verifier_did.map(|did| did.id)),
            holder_did_id: Set(value.holder_did.map(|did| did.id)),
            proof_schema_id: Set(value.schema.map(|schema| schema.id)),
            verifier_key_id: Set(value.verifier_key.map(|key| key.id)),
            interaction_id: Set(value
                .interaction
                .map(|interaction| interaction.id.to_string())),
        })
    }
}

impl GetEntityColumn for SortableProofColumn {
    fn get_simple_expr(&self) -> SimpleExpr {
        match self {
            SortableProofColumn::CreatedDate => proof::Column::CreatedDate.into_simple_expr(),
            SortableProofColumn::SchemaName => proof_schema::Column::Name.into_simple_expr(),
            SortableProofColumn::VerifierDid => did::Column::Did.into_simple_expr(),
            SortableProofColumn::State => proof_state::Column::State.into_simple_expr(),
        }
    }
}

pub(super) fn create_list_response(
    proofs: Vec<ProofListItemModel>,
    proof_states_map: HashMap<ProofId, Vec<ProofState>>,
    limit: u64,
    items_count: u64,
) -> Result<GetProofList, DataLayerError> {
    let values = proofs
        .into_iter()
        .map(move |proof| {
            let mut proof = Proof::try_from(proof)?;
            if let Some(states) = proof_states_map.get(&proof.id) {
                proof.state = Some(states.to_owned());
            } else {
                return Err(DataLayerError::MissingProofState { proof: proof.id });
            }

            Ok(proof)
        })
        .collect::<Result<Vec<Proof>, DataLayerError>>()?;

    Ok(GetProofList {
        values,
        total_pages: calculate_pages_count(items_count, limit),
        total_items: items_count,
    })
}

pub(super) fn get_proof_state_active_model(
    proof_id: &ProofId,
    state: ProofState,
) -> proof_state::ActiveModel {
    proof_state::ActiveModel {
        proof_id: Set(*proof_id),
        created_date: Set(state.created_date),
        last_modified: Set(state.last_modified),
        state: Set(state.state.into()),
    }
}

pub(super) fn get_proof_claim_active_model(
    proof_id: &ProofId,
    claim: &Claim,
) -> proof_claim::ActiveModel {
    proof_claim::ActiveModel {
        proof_id: Set(proof_id.to_string()),
        claim_id: Set(claim.id.to_string()),
    }
}
