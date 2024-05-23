use one_core::service::trust_anchor::dto::{SortableTrustAnchorColumn, TrustAnchorFilterValue};
use sea_orm::IntoSimpleExpr;

use crate::entity::trust_anchor::{self, TrustAnchorRole};
use crate::list_query_generic::{
    get_equals_condition, get_string_match_condition, IntoFilterCondition, IntoSortingColumn,
};

impl IntoSortingColumn for SortableTrustAnchorColumn {
    fn get_column(&self) -> migration::SimpleExpr {
        match self {
            Self::Name => trust_anchor::Column::Name.into_simple_expr(),
            Self::CreatedDate => trust_anchor::Column::CreatedDate.into_simple_expr(),
            Self::Type => trust_anchor::Column::TypeField.into_simple_expr(),
            Self::Role => trust_anchor::Column::Role.into_simple_expr(),
            Self::Priority => trust_anchor::Column::Priority.into_simple_expr(),
        }
    }
}

impl IntoFilterCondition for TrustAnchorFilterValue {
    fn get_condition(self) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(trust_anchor::Column::Name, string_match)
            }
            Self::Role(role) => {
                get_equals_condition(trust_anchor::Column::Role, TrustAnchorRole::from(role))
            }
            Self::Type(string_match) => {
                get_string_match_condition(trust_anchor::Column::TypeField, string_match)
            }
            Self::OrganisationId(organisation_id) => {
                get_equals_condition(trust_anchor::Column::OrganisationId, organisation_id)
            }
        }
    }
}
