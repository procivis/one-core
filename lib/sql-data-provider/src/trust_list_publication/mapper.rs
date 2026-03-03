use one_core::model::list_filter::ListFilterCondition;
use one_core::model::trust_list_publication::{
    SortableTrustListPublicationColumn, TrustListPublication, TrustListPublicationFilterValue,
};
use sea_orm::ActiveValue::Set;
use sea_orm::IntoSimpleExpr;
use sea_orm::sea_query::SimpleExpr;

use crate::entity::trust_list_publication;
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_comparison_condition, get_equals_condition,
    get_string_match_condition,
};

impl From<trust_list_publication::Model> for TrustListPublication {
    fn from(value: trust_list_publication::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            role: value.role.map(Into::into),
            r#type: value.r#type.into(),
            metadata: value.metadata,
            deactivated_at: value.deactivated_at,
            content: value.content,
            sequence_number: value.sequence_number,
            organisation_id: value.organisation_id,
            identifier_id: value.identifier_id,
            key_id: value.key_id,
            certificate_id: value.certificate_id,
            organisation: None,
            identifier: None,
            key: None,
            certificate: None,
        }
    }
}

impl From<TrustListPublication> for trust_list_publication::ActiveModel {
    fn from(value: TrustListPublication) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name),
            role: Set(value.role.map(Into::into)),
            r#type: Set(value.r#type.into()),
            metadata: Set(value.metadata),
            deactivated_at: Set(value.deactivated_at),
            content: Set(value.content),
            sequence_number: Set(value.sequence_number),
            organisation_id: Set(value.organisation_id),
            identifier_id: Set(value.identifier_id),
            key_id: Set(value.key_id),
            certificate_id: Set(value.certificate_id),
        }
    }
}

impl IntoSortingColumn for SortableTrustListPublicationColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::CreatedDate => trust_list_publication::Column::CreatedDate.into_simple_expr(),
        }
    }
}

impl IntoFilterCondition for TrustListPublicationFilterValue {
    fn get_condition(
        self,
        _entire_filter: &ListFilterCondition<TrustListPublicationFilterValue>,
    ) -> sea_orm::Condition {
        match self {
            Self::OrganisationId(id) => {
                get_equals_condition(trust_list_publication::Column::OrganisationId, id)
            }
            Self::Name(string_match) => {
                get_string_match_condition(trust_list_publication::Column::Name, string_match)
            }
            Self::Type(string_match) => {
                get_string_match_condition(trust_list_publication::Column::Type, string_match)
            }
            Self::Role(string_match) => {
                get_string_match_condition(trust_list_publication::Column::Role, string_match)
            }
            Self::CreatedDate(value) => {
                get_comparison_condition(trust_list_publication::Column::CreatedDate, value)
            }
            Self::LastModified(value) => {
                get_comparison_condition(trust_list_publication::Column::LastModified, value)
            }
        }
    }
}
