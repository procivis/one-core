use one_core::model::list_filter::ListFilterCondition;
use one_core::model::trust_entry::{SortableTrustEntryColumn, TrustEntry, TrustEntryFilterValue};
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::{ColumnTrait, IntoSimpleExpr};

use crate::entity::trust_entry;
use crate::entity::trust_entry::TrustEntryStatus;
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_comparison_condition, get_equals_condition,
};

impl From<trust_entry::Model> for TrustEntry {
    fn from(value: trust_entry::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            status: value.status.into(),
            metadata: value.metadata,
            trust_list_publication_id: value.trust_list_publication_id,
            identifier_id: value.identifier_id,
            trust_list_publication: None,
            identifier: None,
        }
    }
}

impl From<TrustEntry> for trust_entry::ActiveModel {
    fn from(value: TrustEntry) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            status: Set(value.status.into()),
            metadata: Set(value.metadata),
            trust_list_publication_id: Set(value.trust_list_publication_id),
            identifier_id: Set(value.identifier_id),
        }
    }
}

impl IntoSortingColumn for SortableTrustEntryColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::CreatedDate => trust_entry::Column::CreatedDate.into_simple_expr(),
            Self::Status => trust_entry::Column::Status.into_simple_expr(),
            Self::LastModified => trust_entry::Column::LastModified.into_simple_expr(),
            Self::IdentifierId => trust_entry::Column::IdentifierId.into_simple_expr(),
        }
    }
}

impl IntoFilterCondition for TrustEntryFilterValue {
    fn get_condition(
        self,
        _entire_filter: &ListFilterCondition<TrustEntryFilterValue>,
    ) -> sea_orm::Condition {
        match self {
            Self::TrustListPublicationId(id) => {
                get_equals_condition(trust_entry::Column::TrustListPublicationId, id)
            }
            Self::Status(string_match) => {
                let statuses = string_match
                    .into_iter()
                    .map(TrustEntryStatus::from)
                    .collect::<Vec<_>>();
                trust_entry::Column::Status.is_in(statuses).into_condition()
            }
            Self::CreatedDate(value) => {
                get_comparison_condition(trust_entry::Column::CreatedDate, value)
            }
            Self::LastModified(value) => {
                get_comparison_condition(trust_entry::Column::LastModified, value)
            }
            Self::Ids(ids) => trust_entry::Column::Id.is_in(ids).into_condition(),
        }
    }
}
