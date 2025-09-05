use one_core::model::claim::Claim;
use one_core::model::identifier::Identifier;
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::proof::{GetProofList, Proof, SortableProofColumn};
use one_core::model::proof_schema::ProofSchema;
use one_core::repository::error::DataLayerError;
use one_core::service::proof::dto::ProofFilterValue;
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::{ColumnTrait, IntoSimpleExpr, Set};
use shared_types::{OrganisationId, ProofId};

use super::model::ProofListItemModel;
use crate::common::calculate_pages_count;
use crate::entity::proof::{ProofRequestState, ProofRole};
use crate::entity::{identifier, interaction, proof, proof_claim, proof_schema};
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_comparison_condition, get_string_match_condition,
};

impl IntoSortingColumn for SortableProofColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::CreatedDate => proof::Column::CreatedDate.into_simple_expr(),
            Self::SchemaName => proof_schema::Column::Name.into_simple_expr(),
            Self::Verifier => identifier::Column::Name.into_simple_expr(),
            Self::State => proof::Column::State.into_simple_expr(),
        }
    }
}

/// Decides whether to SQL-JOIN related interactions (which we need to filter by organisation on the holder side)
pub(super) fn needs_interaction_table_for_filter(
    filter: Option<&ListFilterCondition<ProofFilterValue>>,
) -> bool {
    let Some(filter) = filter else {
        return false;
    };

    let has_organisation_filter =
        filter.contains(&|fv| matches!(fv, ProofFilterValue::OrganisationId(_)));

    let has_verifier_only_role_filter = filter.contains(&|fv| {
        let ProofFilterValue::ProofRoles(roles) = fv else {
            return false;
        };

        roles
            .iter()
            .all(|role| role == &one_core::model::proof::ProofRole::Verifier)
    });

    has_organisation_filter && !has_verifier_only_role_filter
}

impl IntoFilterCondition for ProofFilterValue {
    fn get_condition(self, entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(proof_schema::Column::Name, string_match)
            }
            Self::OrganisationId(organisation_id) => {
                if needs_interaction_table_for_filter(Some(entire_filter)) {
                    proof_schema::Column::OrganisationId
                        .eq(organisation_id)
                        .or(interaction::Column::OrganisationId.eq(organisation_id))
                } else {
                    proof_schema::Column::OrganisationId.eq(organisation_id)
                }
                .into_condition()
            }
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
            Self::Profile(string_match) => {
                get_string_match_condition(proof::Column::Profile, string_match)
            }
            Self::CreatedDate(value) => get_comparison_condition(proof::Column::CreatedDate, value),
            Self::LastModified(value) => {
                get_comparison_condition(proof::Column::LastModified, value)
            }
            Self::RequestedDate(value) => {
                get_comparison_condition(proof::Column::RequestedDate, value)
            }
            Self::CompletedDate(value) => {
                get_comparison_condition(proof::Column::CompletedDate, value)
            }
        }
    }
}

impl TryFrom<ProofListItemModel> for Proof {
    type Error = DataLayerError;

    fn try_from(value: ProofListItemModel) -> Result<Self, Self::Error> {
        let verifier_identifier = match value.verifier_identifier_id {
            None => None,
            Some(verifier_identifier_id) => Some(Identifier {
                id: verifier_identifier_id,
                created_date: value
                    .verifier_identifier_created_date
                    .ok_or(DataLayerError::MappingError)?,
                last_modified: value
                    .verifier_identifier_last_modified
                    .ok_or(DataLayerError::MappingError)?,
                name: value
                    .verifier_identifier_name
                    .ok_or(DataLayerError::MappingError)?,
                did: None,
                key: None,
                certificates: None,
                organisation: None,
                r#type: value
                    .verifier_identifier_type
                    .ok_or(DataLayerError::MappingError)?
                    .into(),
                is_remote: value
                    .verifier_identifier_is_remote
                    .ok_or(DataLayerError::MappingError)?,
                state: value
                    .verifier_identifier_state
                    .ok_or(DataLayerError::MappingError)?
                    .into(),
                deleted_at: None,
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
            protocol: value.protocol,
            transport: value.transport,
            redirect_uri: value.redirect_uri,
            state: value.state.into(),
            role: value.role.into(),
            requested_date: value.requested_date,
            completed_date: value.completed_date,
            profile: value.profile,
            schema,
            claims: None,
            verifier_identifier,
            holder_identifier: None,
            verifier_key: None,
            verifier_certificate: None,
            interaction: None,
            proof_blob_id: value.proof_blob_id,
            engagement: value.engagement,
        })
    }
}

impl From<proof::Model> for Proof {
    fn from(value: proof::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            protocol: value.protocol,
            transport: value.transport,
            redirect_uri: value.redirect_uri,
            state: value.state.into(),
            role: value.role.into(),
            requested_date: value.requested_date,
            completed_date: value.completed_date,
            profile: value.profile,
            proof_blob_id: value.proof_blob_id,
            engagement: value.engagement,
            schema: None,
            claims: None,
            verifier_identifier: None,
            holder_identifier: None,
            verifier_key: None,
            verifier_certificate: None,
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
            redirect_uri: Set(value.redirect_uri),
            protocol: Set(value.protocol),
            state: Set(value.state.into()),
            role: Set(value.role.into()),
            requested_date: Set(value.requested_date),
            completed_date: Set(value.completed_date),
            verifier_identifier_id: Set(value.verifier_identifier.map(|identifier| identifier.id)),
            holder_identifier_id: Set(value.holder_identifier.map(|identifier| identifier.id)),
            proof_schema_id: Set(value.schema.map(|schema| schema.id)),
            verifier_key_id: Set(value.verifier_key.map(|key| key.id)),
            verifier_certificate_id: Set(value
                .verifier_certificate
                .map(|certificate| certificate.id)),
            interaction_id: Set(value
                .interaction
                .map(|interaction| interaction.id.to_string())),
            profile: Set(value.profile),
            proof_blob_id: Set(value.proof_blob_id),
            engagement: Set(value.engagement),
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

pub(crate) fn organisation_id_from_proof(proof: &Proof) -> Result<OrganisationId, DataLayerError> {
    if let Some(organisation) = proof
        .schema
        .as_ref()
        .and_then(|schema| schema.organisation.as_ref())
    {
        Ok(organisation.id)
    } else if let Some(organisation) = proof
        .interaction
        .as_ref()
        .and_then(|interaction| interaction.organisation.as_ref())
    {
        Ok(organisation.id)
    } else {
        Err(anyhow::anyhow!("organisation is None").into())
    }
}

pub(crate) fn target_from_proof(proof: &Proof) -> Option<String> {
    use one_core::model::proof::ProofRole as Role;
    match proof.role {
        Role::Holder => proof
            .verifier_identifier
            .as_ref()
            .map(|identifier| identifier.id.to_string()),
        Role::Verifier => proof
            .holder_identifier
            .as_ref()
            .map(|identifier| identifier.id.to_string()),
    }
}
