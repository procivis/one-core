use one_core::model::list_filter::ListFilterCondition;
use one_core::model::organisation::{
    Organisation, OrganisationFilterValue, SortableOrganisationColumn, UpdateOrganisationRequest,
};
use sea_orm::sea_query::SimpleExpr;
use sea_orm::{IntoSimpleExpr, Set, Unchanged};
use time::OffsetDateTime;

use crate::entity::organisation;
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_comparison_condition, get_string_match_condition,
};

impl From<Organisation> for organisation::ActiveModel {
    fn from(value: Organisation) -> Self {
        Self {
            id: Set(value.id),
            name: Set(value.name),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            deactivated_at: Set(value.deactivated_at),
            wallet_provider: Set(value.wallet_provider),
            wallet_provider_issuer: Set(value.wallet_provider_issuer),
        }
    }
}

impl From<UpdateOrganisationRequest> for organisation::ActiveModel {
    fn from(value: UpdateOrganisationRequest) -> Self {
        Self {
            id: Set(value.id),
            name: match value.name {
                Some(name) => Set(name),
                None => Unchanged(Default::default()),
            },
            last_modified: Set(OffsetDateTime::now_utc()),
            deactivated_at: match value.deactivate {
                Some(true) => Set(Some(OffsetDateTime::now_utc())),
                Some(false) => Set(None),
                _ => Unchanged(Default::default()),
            },
            wallet_provider: match value.wallet_provider {
                None => Unchanged(Default::default()),
                Some(None) => Set(None),
                Some(Some(value)) => Set(Some(value)),
            },
            wallet_provider_issuer: match value.wallet_provider_issuer {
                None => Unchanged(Default::default()),
                Some(None) => Set(None),
                Some(Some(value)) => Set(Some(value)),
            },
            ..Default::default()
        }
    }
}

impl IntoSortingColumn for SortableOrganisationColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::Name => organisation::Column::Name,
            Self::CreatedDate => organisation::Column::CreatedDate,
        }
        .into_simple_expr()
    }
}

impl IntoFilterCondition for OrganisationFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(organisation::Column::Name, string_match)
            }
            Self::CreatedDate(value) => {
                get_comparison_condition(organisation::Column::CreatedDate, value)
            }
            Self::LastModified(value) => {
                get_comparison_condition(organisation::Column::LastModified, value)
            }
        }
    }
}
