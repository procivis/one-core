use one_core::model::list_filter::ListFilterCondition;
use one_core::model::wallet_unit::{SortableWalletUnitColumn, WalletUnitFilterValue};
use sea_orm::sea_query::SimpleExpr;
use sea_orm::sea_query::query::IntoCondition;
use sea_orm::{ColumnTrait, IntoSimpleExpr};

use crate::entity::wallet_unit;
use crate::list_query_generic::{
    IntoFilterCondition, IntoJoinRelations, IntoSortingColumn, JoinRelation,
    get_comparison_condition, get_string_match_condition,
};

impl IntoSortingColumn for SortableWalletUnitColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::CreatedDate => wallet_unit::Column::CreatedDate.into_simple_expr(),
            Self::LastModified => wallet_unit::Column::LastModified.into_simple_expr(),
            Self::Name => wallet_unit::Column::Name.into_simple_expr(),
            Self::Status => wallet_unit::Column::Status.into_simple_expr(),
            Self::Os => wallet_unit::Column::Os.into_simple_expr(),
        }
    }
}

impl IntoFilterCondition for WalletUnitFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(wallet_unit::Column::Name, string_match)
            }
            Self::Ids(ids) => wallet_unit::Column::Id.is_in(ids.iter()).into_condition(),
            Self::Status(statuses) => wallet_unit::Column::Status
                .is_in(
                    statuses
                        .into_iter()
                        .map(wallet_unit::WalletUnitStatus::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::WalletProviderType(types) => wallet_unit::Column::WalletProviderType
                .is_in(types.iter())
                .into_condition(),
            Self::Os(os_values) => wallet_unit::Column::Os
                .is_in(
                    os_values
                        .into_iter()
                        .map(wallet_unit::WalletUnitOs::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::CreatedDate(comparison) => {
                get_comparison_condition(wallet_unit::Column::CreatedDate, comparison)
            }
            Self::LastModified(comparison) => {
                get_comparison_condition(wallet_unit::Column::LastModified, comparison)
            }
        }
    }
}

impl IntoJoinRelations for WalletUnitFilterValue {
    fn get_join(&self) -> Vec<JoinRelation> {
        // No joins needed for wallet unit filters
        vec![]
    }
}
