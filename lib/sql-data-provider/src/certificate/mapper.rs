use itertools::Itertools;
use one_core::model::certificate::{
    Certificate, CertificateFilterValue, SortableCertificateColumn,
};
use one_core::model::list_filter::ListFilterCondition;
use sea_orm::sea_query::{ColumnRef, IntoCondition};
use sea_orm::{ColumnTrait, Set};

use crate::entity::certificate::{self, ActiveModel};
use crate::list_query_generic::{
    ColumnSortingBehavior, IntoFilterCondition, IntoSortingColumn, get_comparison_condition,
    get_equals_condition, get_string_match_condition,
};

impl From<Certificate> for ActiveModel {
    fn from(certificate: Certificate) -> Self {
        let roles = if !certificate.roles.is_empty() {
            Some(certificate.roles.iter().join(","))
        } else {
            None
        };
        Self {
            id: Set(certificate.id),
            identifier_id: Set(certificate.identifier_id),
            created_date: Set(certificate.created_date),
            last_modified: Set(certificate.last_modified),
            expiry_date: Set(certificate.expiry_date),
            name: Set(certificate.name),
            chain: Set(certificate.chain),
            fingerprint: Set(certificate.fingerprint),
            state: Set(certificate.state.into()),
            key_id: Set(certificate.key.map(|key| key.id())),
            organisation_id: Set(certificate.organisation.id()),
            roles: Set(roles),
            deleted_at: Set(certificate.deleted_at),
        }
    }
}

impl IntoSortingColumn for SortableCertificateColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match self {
            Self::Name => ColumnSortingBehavior::case_insensitive(certificate::Column::Name),
            Self::CreatedDate => ColumnSortingBehavior::default(certificate::Column::CreatedDate),
            Self::State => ColumnSortingBehavior::default(certificate::Column::State),
            Self::ExpiryDate => ColumnSortingBehavior::default(certificate::Column::ExpiryDate),
        }
    }
}

impl IntoFilterCondition for CertificateFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::Ids(ids) => certificate::Column::Id.is_in(ids).into_condition(),
            Self::IdentifierId(identifier_id) => certificate::Column::IdentifierId
                .eq(identifier_id)
                .into_condition(),
            Self::Name(string_match) => {
                get_string_match_condition(certificate::Column::Name, string_match)
            }
            Self::State(state) => get_equals_condition(
                certificate::Column::State,
                certificate::CertificateState::from(state),
            ),
            Self::ExpiryDate(date_comparison) => {
                get_comparison_condition(certificate::Column::ExpiryDate, date_comparison)
            }
            Self::Fingerprint(fingerprint) => {
                get_equals_condition(certificate::Column::Fingerprint, fingerprint)
            }
            Self::OrganisationId(organisation_id) => {
                get_equals_condition(certificate::Column::OrganisationId, organisation_id)
            }
            Self::Deleted(false) => certificate::Column::DeletedAt.is_null().into_condition(),
            Self::Deleted(true) => certificate::Column::DeletedAt
                .is_not_null()
                .into_condition(),
        }
    }
}
