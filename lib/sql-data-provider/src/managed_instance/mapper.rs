use std::sync::Arc;

use one_core::model::list_filter::ListFilterCondition;
use one_core::model::managed_instance::{
    ManagedInstance, ManagedInstanceFilterValue, ManagedInstanceOs, SortableManagedInstanceColumn,
};
use one_core::model::relation::{Related, RelatedVec};
use one_core::repository::error::DataLayerError;
use one_core::repository::managed_instance_attestation_repository::{
    ManagedInstanceAttestationRepository, ManagedInstanceAttestationsLoader,
};
use one_core::repository::organisation_repository::OrganisationRepository;
use one_dto_mapper::convert_inner;
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::query::IntoCondition;
use sea_orm::sea_query::{ColumnRef, Query};
use sea_orm::{ColumnTrait, Condition};
use shared_types::RevocationListEntryId;

use crate::entity::managed_instance::VerifierSignatures;
use crate::entity::{instance, managed_instance, managed_instance_attestation};
use crate::list_query_generic::{
    ColumnSortingBehavior, IntoFilterCondition, IntoJoinRelations, IntoSortingColumn, JoinRelation,
    get_comparison_condition, get_equals_condition, get_string_match_condition,
};

pub(super) fn managed_instance_from_model(
    value: managed_instance::Model,
    organisation_repository: &Arc<dyn OrganisationRepository>,
    managed_instance_repository: &Arc<dyn ManagedInstanceAttestationRepository>,
) -> Result<ManagedInstance, DataLayerError> {
    Ok(ManagedInstance {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        os: ManagedInstanceOs::from(value.os),
        status: value.status.into(),
        provider: value.provider,
        role: value.role.into(),
        authentication_key_jwk: value
            .authentication_key_jwk
            .map(|jwk| serde_json::from_str(&jwk))
            .transpose()
            .map_err(|_| DataLayerError::MappingError)?,
        last_issuance: value.last_issuance,
        name: value.name,
        organisation: Related::new(value.organisation_id, organisation_repository.clone()),
        nonce: value.nonce,
        user_nonce: value.user_nonce,
        user_sub: value.user_sub,
        verifier_csr: value.verifier_csr,
        verifier_signature_ids: convert_inner(value.verifier_signature_ids),
        attestations: RelatedVec::new(ManagedInstanceAttestationsLoader {
            id: value.id,
            managed_instance_repository: managed_instance_repository.clone(),
        }),
    })
}

impl From<VerifierSignatures> for Vec<RevocationListEntryId> {
    fn from(value: VerifierSignatures) -> Self {
        value.signatures
    }
}

impl From<Vec<RevocationListEntryId>> for VerifierSignatures {
    fn from(value: Vec<RevocationListEntryId>) -> Self {
        Self { signatures: value }
    }
}

impl TryFrom<ManagedInstance> for managed_instance::ActiveModel {
    type Error = DataLayerError;
    fn try_from(wallet_unit: ManagedInstance) -> Result<Self, Self::Error> {
        let authentication_key_jwk = wallet_unit
            .authentication_key_jwk
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| DataLayerError::MappingError)?;
        Ok(Self {
            id: Set(wallet_unit.id),
            created_date: Set(wallet_unit.created_date),
            last_modified: Set(wallet_unit.last_modified),
            last_issuance: Set(wallet_unit.last_issuance),
            name: Set(wallet_unit.name),
            os: Set(wallet_unit.os.into()),
            status: Set(wallet_unit.status.into()),
            provider: Set(wallet_unit.provider),
            authentication_key_jwk: Set(authentication_key_jwk),
            nonce: Set(wallet_unit.nonce),
            user_nonce: Set(wallet_unit.user_nonce),
            user_sub: Set(wallet_unit.user_sub),
            organisation_id: Set(wallet_unit.organisation.id()),
            role: Set(wallet_unit.role.into()),
            verifier_csr: Set(wallet_unit.verifier_csr),
            verifier_signature_ids: Set(convert_inner(wallet_unit.verifier_signature_ids)),
        })
    }
}

impl IntoSortingColumn for SortableManagedInstanceColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match self {
            Self::CreatedDate => {
                ColumnSortingBehavior::default(managed_instance::Column::CreatedDate)
            }
            Self::LastModified => {
                ColumnSortingBehavior::default(managed_instance::Column::LastModified)
            }
            Self::Name => ColumnSortingBehavior::case_insensitive(managed_instance::Column::Name),
            Self::Status => ColumnSortingBehavior::default(managed_instance::Column::Status),
            Self::Os => ColumnSortingBehavior::default(managed_instance::Column::Os),
            Self::UserSub => {
                ColumnSortingBehavior::case_insensitive(managed_instance::Column::UserSub)
            }
        }
    }
}

impl IntoFilterCondition for ManagedInstanceFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> Condition {
        match self {
            Self::OrganisationId(organisation_id) => {
                get_equals_condition(managed_instance::Column::OrganisationId, organisation_id)
            }
            Self::Name(string_match) => {
                get_string_match_condition(managed_instance::Column::Name, string_match)
            }
            Self::Ids(ids) => managed_instance::Column::Id
                .is_in(ids.iter())
                .into_condition(),
            Self::Status(statuses) => managed_instance::Column::Status
                .is_in(
                    statuses
                        .into_iter()
                        .map(instance::InstanceStatus::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::ProviderName(names) => managed_instance::Column::Provider
                .is_in(names.iter())
                .into_condition(),
            Self::Role(roles) => managed_instance::Column::Role
                .is_in(
                    roles
                        .into_iter()
                        .map(instance::InstanceRole::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::Os(os_values) => managed_instance::Column::Os
                .is_in(
                    os_values
                        .into_iter()
                        .map(managed_instance::ManagedInstanceOs::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::AttestationHash(attestation_hash) => managed_instance::Column::Id
                .in_subquery(
                    Query::select()
                        .column(managed_instance_attestation::Column::ManagedInstanceId)
                        .from(managed_instance_attestation::Entity)
                        .cond_where(
                            managed_instance_attestation::Column::AttestationContentHash
                                .eq(attestation_hash),
                        )
                        .to_owned(),
                )
                .into_condition(),
            Self::CreatedDate(comparison) => {
                get_comparison_condition(managed_instance::Column::CreatedDate, comparison)
            }
            Self::LastModified(comparison) => {
                get_comparison_condition(managed_instance::Column::LastModified, comparison)
            }
            Self::UserSub(string_match) => {
                get_string_match_condition(managed_instance::Column::UserSub, string_match)
            }
        }
    }
}

impl IntoJoinRelations for ManagedInstanceFilterValue {
    fn get_join(&self) -> Vec<JoinRelation> {
        // No joins needed for wallet unit filters
        vec![]
    }
}
