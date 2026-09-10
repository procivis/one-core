use std::sync::Arc;

use one_core::model::list_filter::ListFilterCondition;
use one_core::model::relation::Related;
use one_core::model::trust_entry::{SortableTrustEntryColumn, TrustEntry, TrustEntryFilterValue};
use one_core::repository::identifier_repository::IdentifierRepository;
use one_core::repository::trust_list_publication_repository::TrustListPublicationRepository;
use sea_orm::ActiveValue::Set;
use sea_orm::ColumnTrait;
use sea_orm::sea_query::{Alias, ColumnRef, IntoColumnRef, IntoCondition};

use crate::entity::trust_entry;
use crate::entity::trust_entry::TrustEntryState;
use crate::list_query_generic::{
    ColumnSortingBehavior, IntoFilterCondition, IntoSortingColumn, get_comparison_condition,
    get_equals_condition,
};

pub(crate) fn trust_entry_from_model(
    value: trust_entry::Model,
    identifier_repository: &Arc<dyn IdentifierRepository>,
    trust_list_publication_repository: &Arc<dyn TrustListPublicationRepository>,
) -> TrustEntry {
    TrustEntry {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        state: value.state.into(),
        metadata: value.metadata,
        trust_list_publication: Related::new(
            value.trust_list_publication_id,
            trust_list_publication_repository.clone(),
        ),
        identifier: Related::new(value.identifier_id, identifier_repository.clone()),
    }
}

impl From<TrustEntry> for trust_entry::ActiveModel {
    fn from(value: TrustEntry) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            state: Set(value.state.into()),
            metadata: Set(value.metadata),
            trust_list_publication_id: Set(value.trust_list_publication.id()),
            identifier_id: Set(value.identifier.id()),
        }
    }
}

impl IntoSortingColumn for SortableTrustEntryColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match self {
            Self::CreatedDate => ColumnSortingBehavior::default(trust_entry::Column::CreatedDate),
            Self::State => ColumnSortingBehavior::default(trust_entry::Column::State),
            Self::LastModified => ColumnSortingBehavior::default(trust_entry::Column::LastModified),
            Self::Identifier => (
                Alias::new("identifier_name").into_column_ref(),
                ColumnSortingBehavior::CaseInsensitive,
            ),
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
            Self::State(string_match) => {
                let statuses = string_match
                    .into_iter()
                    .map(TrustEntryState::from)
                    .collect::<Vec<_>>();
                trust_entry::Column::State.is_in(statuses).into_condition()
            }
            Self::CreatedDate(value) => {
                get_comparison_condition(trust_entry::Column::CreatedDate, value)
            }
            Self::LastModified(value) => {
                get_comparison_condition(trust_entry::Column::LastModified, value)
            }
            Self::Ids(ids) => trust_entry::Column::Id.is_in(ids).into_condition(),
            Self::IdentifierIds(identifier_ids) => trust_entry::Column::IdentifierId
                .is_in(identifier_ids)
                .into_condition(),
        }
    }
}
