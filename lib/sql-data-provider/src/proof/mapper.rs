use one_core::model::claim::Claim;
use one_core::model::did::Did;
use one_core::model::proof::{GetProofList, Proof, SortableProofColumn};
use one_core::model::proof_schema::ProofSchema;
use one_core::repository::error::DataLayerError;
use one_core::service::proof::dto::ProofFilterValue;
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::{ColumnTrait, IntoSimpleExpr, Set};
use shared_types::ProofId;

use super::model::ProofListItemModel;
use crate::common::calculate_pages_count;
use crate::entity::proof::{ProofRequestState, ProofRole};
use crate::entity::{did, interaction, proof, proof_claim, proof_schema};
use crate::list_query_generic::{
    get_string_match_condition, IntoFilterCondition, IntoSortingColumn,
};

impl IntoSortingColumn for SortableProofColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::CreatedDate => proof::Column::CreatedDate.into_simple_expr(),
            Self::SchemaName => proof_schema::Column::Name.into_simple_expr(),
            Self::VerifierDid => did::Column::Id.into_simple_expr(),
            Self::State => proof::Column::State.into_simple_expr(),
        }
    }
}

impl IntoFilterCondition for ProofFilterValue {
    fn get_condition(self) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(proof_schema::Column::Name, string_match)
            }
            Self::OrganisationId(organisation_id) => proof_schema::Column::OrganisationId
                .eq(organisation_id)
                .or(interaction::Column::OrganisationId.eq(organisation_id))
                .into_condition(),
            Self::ProofStates(states) => proof::Column::State
                .is_in(states.into_iter().map(ProofRequestState::from))
                .into_condition(),
            Self::ProofRoles(roles) => proof::Column::Role
                .is_in(roles.into_iter().map(ProofRole::from))
                .into_condition(),
            Self::ProofSchemaIds(ids) => proof_schema::Column::Id.is_in(ids).into_condition(),
            Self::ProofIds(ids) => proof::Column::Id.is_in(ids).into_condition(),
            Self::ProofIdsNot(ids) => proof::Column::Id.is_not_in(ids).into_condition(),
            Self::ValidForDeletion => proof_schema::Column::ExpireDuration.gt(0).into_condition(),
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

        let schema = match value.schema_id {
            None => None,
            Some(schema_id) => Some(ProofSchema {
                id: schema_id,
                created_date: value
                    .schema_created_date
                    .ok_or(DataLayerError::MappingError)?,
                last_modified: value
                    .schema_last_modified
                    .ok_or(DataLayerError::MappingError)?,
                deleted_at: None,
                name: value.schema_name.ok_or(DataLayerError::MappingError)?,
                expire_duration: value
                    .schema_expire_duration
                    .ok_or(DataLayerError::MappingError)?,
                imported_source_url: value.schema_imported_source_url,
                organisation: None,
                input_schemas: None,
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
            state: value.state.into(),
            role: value.role.into(),
            requested_date: value.requested_date,
            completed_date: value.completed_date,
            schema,
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
            state: value.state.into(),
            role: value.role.into(),
            requested_date: value.requested_date,
            completed_date: value.completed_date,
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
            state: Set(value.state.into()),
            role: Set(value.role.into()),
            requested_date: Set(value.requested_date),
            completed_date: Set(value.completed_date),
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

pub(super) fn create_list_response(
    proofs: Vec<ProofListItemModel>,
    limit: u64,
    items_count: u64,
) -> Result<GetProofList, DataLayerError> {
    let values = proofs
        .into_iter()
        .map(Proof::try_from)
        .collect::<Result<Vec<Proof>, DataLayerError>>()?;

    Ok(GetProofList {
        values,
        total_pages: calculate_pages_count(items_count, limit),
        total_items: items_count,
    })
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
