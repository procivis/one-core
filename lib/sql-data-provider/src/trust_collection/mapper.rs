use std::sync::Arc;

use one_core::model::list_filter::ListFilterCondition;
use one_core::model::relation::Related;
use one_core::model::trust_collection::{
    SortableTrustCollectionColumn, TrustCollection, TrustCollectionFilterValue,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{Alias, ColumnRef, Expr, IntoCondition, JoinType, Query, SelectStatement};
use sea_orm::{ColumnTrait, ExprTrait};
use shared_types::OrganisationId;
use url::Url;

use crate::entity::{organisation, trust_collection, trust_list_subscription};
use crate::list_query_generic::{
    ColumnSortingBehavior, IntoFilterCondition, IntoSortingColumn, get_comparison_condition,
    get_equals_condition, get_string_match_condition,
};

pub(crate) fn trust_collection_from_model(
    value: trust_collection::Model,
    organisation_repository: &Arc<dyn OrganisationRepository>,
) -> Result<TrustCollection, DataLayerError> {
    Ok(TrustCollection {
        id: value.id,
        ecosystem: value.ecosystem,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
        deactivated_at: value.deactivated_at,
        remote_trust_collection_url: value
            .remote_trust_collection_url
            .map(|url| Url::parse(&url))
            .transpose()
            .map_err(|e| DataLayerError::MappingError(e.into()))?,
        organisation: Related::new(value.organisation_id, organisation_repository.clone()),
    })
}

impl From<TrustCollection> for trust_collection::ActiveModel {
    fn from(value: TrustCollection) -> Self {
        Self {
            id: Set(value.id),
            ecosystem: Set(value.ecosystem),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name),
            deactivated_at: Set(value.deactivated_at),
            organisation_id: Set(value.organisation.id()),
            remote_trust_collection_url: Set(value
                .remote_trust_collection_url
                .map(|url| url.to_string())),
        }
    }
}

impl IntoSortingColumn for SortableTrustCollectionColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match self {
            Self::Name => ColumnSortingBehavior::case_insensitive(trust_collection::Column::Name),
            Self::CreatedDate => {
                ColumnSortingBehavior::default(trust_collection::Column::CreatedDate)
            }
            Self::LastModified => {
                ColumnSortingBehavior::default(trust_collection::Column::LastModified)
            }
        }
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
            Self::OrganisationId {
                id,
                include_inherited_collections,
            } => {
                if include_inherited_collections {
                    // an organisation "inherits" collections owned by itself or its parent
                    trust_collection::Column::OrganisationId
                        .in_subquery(organisation_and_parent(id))
                        .into_condition()
                } else {
                    get_equals_condition(trust_collection::Column::OrganisationId, id)
                }
            }
            Self::CreatedDate(value) => {
                get_comparison_condition(trust_collection::Column::CreatedDate, value)
            }
            Self::LastModified(value) => {
                get_comparison_condition(trust_collection::Column::LastModified, value)
            }
            Self::Ids(ids) => trust_collection::Column::Id.is_in(ids).into_condition(),
            Self::Ecosystems(ecosystems) => trust_collection::Column::Ecosystem
                .is_in(ecosystems.iter())
                .into_condition(),
            Self::Remote(true) => trust_collection::Column::RemoteTrustCollectionUrl
                .is_not_null()
                .into_condition(),
            Self::Remote(false) => trust_collection::Column::RemoteTrustCollectionUrl
                .is_null()
                .into_condition(),
            Self::Empty(true) => Expr::exists(active_subscriptions_of_collection())
                .not()
                .into_condition(),
            Self::Empty(false) => {
                Expr::exists(active_subscriptions_of_collection()).into_condition()
            }
        }
    }
}

/// Selects the given organisation and its parent (if any).
/// Joining via the given organisation lets MariaDB resolve both ids by primary key and then look
/// up the collections via the `organisation_id` index, while
/// `organisation_id = ? OR organisation_id IN (SELECT parent ...)` scans the whole table.
fn organisation_and_parent(id: OrganisationId) -> SelectStatement {
    let child = Alias::new("child_organisation");
    Query::select()
        .column((organisation::Entity, organisation::Column::Id))
        .from(organisation::Entity)
        .join_as(
            JoinType::InnerJoin,
            organisation::Entity,
            child.clone(),
            Expr::col((organisation::Entity, organisation::Column::Id))
                .equals((child.clone(), organisation::Column::Id))
                .or(Expr::col((organisation::Entity, organisation::Column::Id))
                    .equals((child.clone(), organisation::Column::ParentOrganisation))),
        )
        .and_where(Expr::col((child, organisation::Column::Id)).eq(id))
        .to_owned()
}

/// Correlated subquery for the active subscriptions of the listed trust collection.
/// Subscriptions are only soft-deleted, so deactivated ones must not count.
fn active_subscriptions_of_collection() -> SelectStatement {
    Query::select()
        .expr(Expr::value(1))
        .from(trust_list_subscription::Entity)
        .and_where(
            Expr::col((
                trust_list_subscription::Entity,
                trust_list_subscription::Column::TrustCollectionId,
            ))
            .equals((trust_collection::Entity, trust_collection::Column::Id)),
        )
        .and_where(
            Expr::col((
                trust_list_subscription::Entity,
                trust_list_subscription::Column::DeactivatedAt,
            ))
            .is_null(),
        )
        .to_owned()
}
