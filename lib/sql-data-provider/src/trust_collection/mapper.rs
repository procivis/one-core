use one_core::model::list_filter::ListFilterCondition;
use one_core::model::trust_collection::{
    SortableTrustCollectionColumn, TrustCollection, TrustCollectionFilterValue,
};
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::{ColumnTrait, IntoSimpleExpr};

use crate::entity::trust_collection;
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_comparison_condition, get_equals_condition,
    get_string_match_condition,
};

impl From<trust_collection::Model> for TrustCollection {
    fn from(value: trust_collection::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            deactivated_at: value.deactivated_at,
            organisation_id: value.organisation_id,
            organisation: None,
        }
    }
}

impl From<TrustCollection> for trust_collection::ActiveModel {
    fn from(value: TrustCollection) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name),
            deactivated_at: Set(value.deactivated_at),
            organisation_id: Set(value.organisation_id),
        }
    }
}

impl IntoSortingColumn for SortableTrustCollectionColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::Name => trust_collection::Column::Name,
            Self::CreatedDate => trust_collection::Column::CreatedDate,
            Self::LastModified => trust_collection::Column::LastModified,
        }
        .into_simple_expr()
    }
}

impl IntoFilterCondition for TrustCollectionFilterValue {
    fn get_condition(
        self,
        _entire_filter: &ListFilterCondition<TrustCollectionFilterValue>,
    ) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(trust_collection::Column::Name, string_match)
            }
            Self::OrganisationId(organisation_id) => {
                get_equals_condition(trust_collection::Column::OrganisationId, organisation_id)
            }
            Self::CreatedDate(value) => {
                get_comparison_condition(trust_collection::Column::CreatedDate, value)
            }
            Self::LastModified(value) => {
                get_comparison_condition(trust_collection::Column::LastModified, value)
            }
            Self::Ids(ids) => trust_collection::Column::Id.is_in(ids).into_condition(),
        }
    }
}
