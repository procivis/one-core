use std::sync::Arc;

use entity::instance;
use one_core::model::instance::{
    Instance, InstanceFilterValue, SortableInstanceColumn, WalletProviderType,
};
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::relation::{Related, RelatedVec};
use one_core::repository::instance_repository::InstanceWalletAttestationsLoader;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_core::repository::wallet_attestation_repository::WalletAttestationRepository;
use sea_orm::sea_query::{ColumnRef, IntoCondition};
use sea_orm::{ColumnTrait, Condition, Set};

use crate::entity;
use crate::entity::instance::{ActiveModel, Model};
use crate::list_query_generic::{
    ColumnSortingBehavior, IntoFilterCondition, IntoSortingColumn, get_equals_condition,
};

pub(crate) fn instance_from_model(
    value: Model,
    organisation_repository: &Arc<dyn OrganisationRepository>,
    key_repository: &Arc<dyn KeyRepository>,
    wallet_attestation_repository: &Arc<dyn WalletAttestationRepository>,
) -> Instance {
    Instance {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        provider_type: WalletProviderType::from(value.provider_type),
        provider_name: value.provider_name,
        provider_url: value.provider_url,
        provider_instance_id: value.provider_instance_id,
        status: value.status.into(),
        role: value.role.into(),
        nonce: value.nonce,
        user_nonce: value.user_nonce,
        organisation: Related::new(value.organisation_id, organisation_repository.clone()),
        authentication_key: value
            .authentication_key_id
            .map(|key_id| Related::new(key_id, key_repository.to_owned())),
        wallet_attestations: RelatedVec::new(InstanceWalletAttestationsLoader {
            id: value.id,
            wallet_attestation_repository: wallet_attestation_repository.to_owned(),
        }),
    }
}

impl From<Instance> for ActiveModel {
    fn from(value: Instance) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            status: Set(value.status.into()),
            role: Set(value.role.into()),
            provider_name: Set(value.provider_name),
            provider_type: Set(value.provider_type.into()),
            provider_url: Set(value.provider_url),
            provider_instance_id: Set(value.provider_instance_id),
            organisation_id: Set(value.organisation.id()),
            authentication_key_id: Set(value.authentication_key.map(|key| key.id())),
            nonce: Set(value.nonce),
            user_nonce: Set(value.user_nonce),
        }
    }
}

impl IntoSortingColumn for SortableInstanceColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match *self {}
    }
}

impl IntoFilterCondition for InstanceFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> Condition {
        match self {
            Self::OrganisationIds(organisation_ids) => instance::Column::OrganisationId
                .is_in(organisation_ids)
                .into_condition(),
            Self::Role(role) => {
                get_equals_condition(instance::Column::Role, instance::InstanceRole::from(role))
            }
            Self::Status(status) => get_equals_condition(
                instance::Column::Status,
                instance::InstanceStatus::from(status),
            ),
        }
    }
}
