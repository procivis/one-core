use std::{collections::HashMap, str::FromStr};

use one_core::{
    model::{
        claim::Claim,
        did::Did,
        proof::{GetProofList, Proof, ProofId, ProofState, SortableProofColumn},
        proof_schema::ProofSchema,
    },
    repository::error::DataLayerError,
};
use sea_orm::{sea_query::SimpleExpr, IntoSimpleExpr, Set};
use shared_types::DidId;
use uuid::Uuid;

use super::model::ProofListItemModel;
use crate::{
    common::calculate_pages_count,
    entity::{
        did, proof, proof_claim, proof_schema,
        proof_state::{self},
    },
    list_query::GetEntityColumn,
};

impl TryFrom<ProofListItemModel> for Proof {
    type Error = DataLayerError;

    fn try_from(value: ProofListItemModel) -> Result<Self, Self::Error> {
        let id = Uuid::from_str(&value.id)?;
        let schema_id = Uuid::from_str(&value.schema_id)?;
        let verifier_did_id = value
            .verifier_did_id
            .map(|did_id| Uuid::from_str(&did_id).map(DidId::from))
            .transpose()?;
        let verifier_did = match verifier_did_id {
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
            id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            issuance_date: value.issuance_date,
            transport: value.transport,
            state: None,
            schema: Some(ProofSchema {
                id: schema_id,
                created_date: value.schema_created_date,
                last_modified: value.schema_last_modified,
                deleted_at: None,
                name: value.schema_name,
                expire_duration: value.expire_duration,
                claim_schemas: None,
                organisation: None,
            }),
            claims: None,
            verifier_did,
            holder_did: None,
            interaction: None,
        })
    }
}

impl TryFrom<proof::Model> for Proof {
    type Error = DataLayerError;

    fn try_from(value: proof::Model) -> Result<Self, Self::Error> {
        let id = Uuid::from_str(&value.id)?;

        Ok(Self {
            id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            issuance_date: value.issuance_date,
            transport: value.transport,
            state: None,
            schema: None,
            claims: None,
            verifier_did: None,
            holder_did: None,
            interaction: None,
        })
    }
}

impl TryFrom<Proof> for proof::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: Proof) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Set(value.id.to_string()),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            issuance_date: Set(value.issuance_date),
            transport: Set(value.transport),
            verifier_did_id: Set(value.verifier_did.map(|did| did.id)),
            holder_did_id: Set(value.holder_did.map(|did| did.id)),
            proof_schema_id: Set(value.schema.map(|schema| schema.id.to_string())),
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
                return Err(DataLayerError::RecordNotFound);
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
        proof_id: Set(proof_id.to_string()),
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
