use one_core::model::list_filter::ListFilterCondition;
use one_core::model::trust_list_subscription::{
    SortableTrustListSubscriptionColumn, TrustListSubscription, TrustListSubscriptionFilterValue,
};
use one_dto_mapper::convert_inner;
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::{ColumnTrait, IntoSimpleExpr};

use crate::entity::trust_list_publication::TrustRoleEnum;
use crate::entity::trust_list_subscription;
use crate::entity::trust_list_subscription::TrustListSubscriptionState;
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_comparison_condition, get_equals_condition,
    get_string_match_condition,
};

impl From<trust_list_subscription::Model> for TrustListSubscription {
    fn from(value: trust_list_subscription::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            deactivated_at: value.deactivated_at,
            r#type: value.r#type,
            reference: value.reference,
            role: value.role.into(),
            state: value.state.into(),
            trust_collection_id: value.trust_collection_id,
            trust_collection: None,
        }
    }
}

impl From<TrustListSubscription> for trust_list_subscription::ActiveModel {
    fn from(value: TrustListSubscription) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name),
            deactivated_at: Set(value.deactivated_at),
            r#type: Set(value.r#type),
            reference: Set(value.reference),
            role: Set(value.role.into()),
            state: Set(value.state.into()),
            trust_collection_id: Set(value.trust_collection_id),
        }
    }
}

impl IntoSortingColumn for SortableTrustListSubscriptionColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::Name => trust_list_subscription::Column::Name,
            Self::Type => trust_list_subscription::Column::Type,
            Self::Role => trust_list_subscription::Column::Role,
            Self::CreatedDate => trust_list_subscription::Column::CreatedDate,
            Self::LastModified => trust_list_subscription::Column::LastModified,
            Self::Reference => trust_list_subscription::Column::Reference,
        }
        .into_simple_expr()
    }
}

impl IntoFilterCondition for TrustListSubscriptionFilterValue {
    fn get_condition(
        self,
        _entire_filter: &ListFilterCondition<TrustListSubscriptionFilterValue>,
    ) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(trust_list_subscription::Column::Name, string_match)
            }
            Self::TrustCollectionId(trust_collection_id) => get_equals_condition(
                trust_list_subscription::Column::TrustCollectionId,
                trust_collection_id,
            ),
            Self::Role(roles) => trust_list_subscription::Column::Role
                .is_in(convert_inner::<_, TrustRoleEnum>(roles))
                .into_condition(),
            Self::State(states) => trust_list_subscription::Column::State
                .is_in(convert_inner::<_, TrustListSubscriptionState>(states))
                .into_condition(),
            Self::Type(types) => trust_list_subscription::Column::Type
                .is_in(types)
                .into_condition(),
            Self::CreatedDate(value) => {
                get_comparison_condition(trust_list_subscription::Column::CreatedDate, value)
            }
            Self::LastModified(value) => {
                get_comparison_condition(trust_list_subscription::Column::LastModified, value)
            }
            Self::Ids(ids) => trust_list_subscription::Column::Id
                .is_in(ids)
                .into_condition(),
            Self::Reference(string_match) => {
                get_string_match_condition(trust_list_subscription::Column::Reference, string_match)
            }
        }
    }
}
