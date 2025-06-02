use one_core::model::certificate::{
    Certificate, CertificateFilterValue, GetCertificateList, SortableCertificateColumn,
};
use one_dto_mapper::convert_inner;
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::{ColumnTrait, IntoSimpleExpr, Set};

use crate::common::calculate_pages_count;
use crate::entity::certificate::{self, ActiveModel};
use crate::list_query_generic::{
    IntoFilterCondition, IntoJoinRelations, IntoSortingColumn, JoinRelation,
    get_comparison_condition, get_equals_condition, get_string_match_condition,
};

impl From<Certificate> for ActiveModel {
    fn from(certificate: Certificate) -> Self {
        let key_id = certificate.key.map(|key| key.id);

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
            key_id: Set(key_id),
            organisation_id: Set(certificate.organisation_id),
        }
    }
}

impl From<certificate::Model> for Certificate {
    fn from(value: certificate::Model) -> Self {
        Self {
            id: value.id,
            identifier_id: value.identifier_id,
            organisation_id: value.organisation_id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            expiry_date: value.expiry_date,
            name: value.name,
            chain: value.chain,
            fingerprint: value.fingerprint,
            state: value.state.into(),
            key: None,
        }
    }
}

impl IntoSortingColumn for SortableCertificateColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::Name => certificate::Column::Name,
            Self::CreatedDate => certificate::Column::CreatedDate,
            Self::State => certificate::Column::State,
            Self::ExpiryDate => certificate::Column::ExpiryDate,
        }
        .into_simple_expr()
    }
}

impl IntoFilterCondition for CertificateFilterValue {
    fn get_condition(self) -> sea_orm::Condition {
        match self {
            Self::Ids(ids) => certificate::Column::Id.is_in(ids).into_condition(),
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
        }
    }
}

impl IntoJoinRelations for CertificateFilterValue {
    fn get_join(&self) -> Vec<JoinRelation> {
        vec![]
    }
}

pub(super) fn create_list_response(
    certificates: Vec<certificate::Model>,
    limit: Option<u64>,
    items_count: u64,
) -> GetCertificateList {
    GetCertificateList {
        values: convert_inner(certificates),
        total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
        total_items: items_count,
    }
}
