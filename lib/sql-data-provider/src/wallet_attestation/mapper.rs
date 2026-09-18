use std::sync::Arc;

use one_core::model::list_filter::ListFilterCondition;
use one_core::model::relation::{OptionalRelatedExt, Related};
use one_core::model::wallet_attestation::{
    SortableWalletAttestationColumn, WalletAttestation, WalletAttestationFilterValue,
};
use one_core::repository::key_repository::KeyRepository;
use sea_orm::Set;
use sea_orm::sea_query::ColumnRef;

use crate::entity::wallet_attestation::{self, ActiveModel, Model};
use crate::list_query_generic::{
    ColumnSortingBehavior, IntoFilterCondition, IntoSortingColumn, get_comparison_condition,
    get_equals_condition,
};

impl From<WalletAttestation> for ActiveModel {
    fn from(wallet_attestation: WalletAttestation) -> Self {
        Self {
            id: Set(wallet_attestation.id),
            created_date: Set(wallet_attestation.created_date),
            last_modified: Set(wallet_attestation.last_modified),
            expiration_date: Set(wallet_attestation.expiration_date),
            attestation: Set(wallet_attestation.attestation.into_bytes()),
            instance_id: Set(wallet_attestation.instance_id),
            attested_key_id: Set(wallet_attestation.attested_key.id_opt()),
            r#type: Set(wallet_attestation.r#type.into()),
        }
    }
}

pub(super) fn wallet_instance_attestation_from_model(
    value: Model,
    key_repository: &Arc<dyn KeyRepository>,
) -> WalletAttestation {
    WalletAttestation {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        expiration_date: value.expiration_date,
        attestation: String::from_utf8_lossy(&value.attestation).to_string(),
        instance_id: value.instance_id,
        r#type: value.r#type.into(),
        attested_key: value
            .attested_key_id
            .map(|key_id| Related::new(key_id, key_repository.to_owned())),
    }
}

impl IntoSortingColumn for SortableWalletAttestationColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match self {
            Self::CreatedDate => {
                ColumnSortingBehavior::default(wallet_attestation::Column::CreatedDate)
            }
            Self::LastModified => {
                ColumnSortingBehavior::default(wallet_attestation::Column::LastModified)
            }
            Self::ExpirationDate => {
                ColumnSortingBehavior::default(wallet_attestation::Column::ExpirationDate)
            }
        }
    }
}

impl IntoFilterCondition for WalletAttestationFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::Instance(instance_id) => {
                get_equals_condition(wallet_attestation::Column::InstanceId, instance_id)
            }
            Self::ExpirationDate(value) => {
                get_comparison_condition(wallet_attestation::Column::ExpirationDate, value)
            }
        }
    }
}
