use one_core::model::list_filter::ListFilterCondition;
use one_core::model::revocation_list::{
    RevocationListEntityInfo, RevocationListEntry, RevocationListEntryFilterValue,
    SortableRevocationListEntryColumn,
};
use one_core::repository::error::DataLayerError;
use one_dto_mapper::try_convert_inner;
use sea_orm::sea_query::{ColumnRef, IntoCondition};
use sea_orm::{ColumnTrait, Condition};

use crate::entity::revocation_list_entry::{self, RevocationListEntryType};
use crate::list_query_generic::{
    ColumnSortingBehavior, IntoFilterCondition, IntoJoinRelations, IntoSortingColumn, JoinRelation,
    get_equals_condition,
};

pub(super) fn revocation_list_entry_from_model(
    entry: revocation_list_entry::Model,
) -> Result<RevocationListEntry, DataLayerError> {
    let entity_info = match entry.r#type {
        RevocationListEntryType::Credential => {
            RevocationListEntityInfo::Credential(entry.credential_id)
        }
        RevocationListEntryType::KeyAttestation => RevocationListEntityInfo::KeyAttestation,
        RevocationListEntryType::WalletInstanceAttestation => {
            RevocationListEntityInfo::WalletInstanceAttestation
        }
        RevocationListEntryType::Signature => match entry.signature_type {
            Some(signature_type) => RevocationListEntityInfo::Signature(
                signature_type.into(),
                try_convert_inner(entry.serial)?,
            ),
            None => {
                return Err(DataLayerError::MappingError(anyhow::anyhow!(
                    "Signature revocation list entry is missing signature_type"
                )));
            }
        },
    };
    Ok(RevocationListEntry {
        id: entry.id,
        created_date: entry.created_date,
        last_modified: entry.last_modified,
        entity_info,
        index: entry.index.map(|index| index as _),
        state: entry.state.into(),
    })
}

impl IntoSortingColumn for SortableRevocationListEntryColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match self {
            Self::Index => ColumnSortingBehavior::default(revocation_list_entry::Column::Index),
        }
    }
}

impl IntoFilterCondition for RevocationListEntryFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> Condition {
        match self {
            Self::List(list_id) => {
                get_equals_condition(revocation_list_entry::Column::RevocationListId, list_id)
            }
            Self::Ids(ids) => revocation_list_entry::Column::Id
                .is_in(ids.iter())
                .into_condition(),
            Self::States(states) => revocation_list_entry::Column::State
                .is_in(
                    states
                        .into_iter()
                        .map(revocation_list_entry::RevocationListEntryState::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::IndexRange { from, to } => {
                let mut condition = Condition::all();
                if let Some(from) = from {
                    condition =
                        condition.add(revocation_list_entry::Column::Index.gte(from as i32));
                }
                if let Some(to) = to {
                    condition = condition.add(revocation_list_entry::Column::Index.lt(to as i32));
                }
                condition
            }
        }
    }
}

impl IntoJoinRelations for RevocationListEntryFilterValue {
    fn get_join(&self) -> Vec<JoinRelation> {
        // No joins needed for current filters
        vec![]
    }
}
