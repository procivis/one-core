use one_core::model::trust_anchor::TrustAnchor;
use one_core::service::trust_anchor::dto::{SortableTrustAnchorColumn, TrustAnchorFilterValue};
use sea_orm::sea_query::SimpleExpr;
use sea_orm::{IntoSimpleExpr, Set};

use crate::entity::trust_anchor::{self};
use crate::list_query_generic::{
    get_equals_condition, get_string_match_condition, IntoFilterCondition, IntoSortingColumn,
};

impl From<TrustAnchor> for trust_anchor::ActiveModel {
    fn from(value: TrustAnchor) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name),
            r#type: Set(value.r#type),
            is_publisher: Set(value.is_publisher),
            publisher_reference: Set(value.publisher_reference),
        }
    }
}

impl From<trust_anchor::Model> for TrustAnchor {
    fn from(value: trust_anchor::Model) -> Self {
        Self {
            id: value.id,
            name: value.name,
            created_date: value.created_date,
            last_modified: value.last_modified,
            r#type: value.r#type,
            is_publisher: value.is_publisher,
            publisher_reference: value.publisher_reference,
        }
    }
}

impl IntoSortingColumn for SortableTrustAnchorColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::Name => trust_anchor::Column::Name.into_simple_expr(),
            Self::CreatedDate => trust_anchor::Column::CreatedDate.into_simple_expr(),
            Self::Type => trust_anchor::Column::Type.into_simple_expr(),
        }
    }
}

impl IntoFilterCondition for TrustAnchorFilterValue {
    fn get_condition(self) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(trust_anchor::Column::Name, string_match)
            }
            Self::IsPublisher(is_publisher) => {
                get_equals_condition(trust_anchor::Column::IsPublisher, is_publisher)
            }
            Self::Type(string_match) => {
                get_string_match_condition(trust_anchor::Column::Type, string_match)
            }
        }
    }
}
