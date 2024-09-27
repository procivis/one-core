use anyhow::anyhow;
use one_core::model::trust_anchor::TrustAnchor;
use one_core::repository::error::DataLayerError;
use one_core::service::trust_anchor::dto::{SortableTrustAnchorColumn, TrustAnchorFilterValue};
use sea_orm::sea_query::SimpleExpr;
use sea_orm::{IntoSimpleExpr, Set};

use crate::entity::trust_anchor::{self, TrustAnchorRole};
use crate::list_query_generic::{
    get_equals_condition, get_string_match_condition, IntoFilterCondition, IntoSortingColumn,
};

impl TryFrom<TrustAnchor> for trust_anchor::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: TrustAnchor) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name),
            type_field: Set(value.type_field),
            publisher_reference: Set(value.publisher_reference),
            role: Set(value.role.into()),
            priority: Set(value.priority),
            organisation_id: Set(value
                .organisation
                .as_ref()
                .ok_or(DataLayerError::Db(anyhow!(
                    "Missing organisation for proof schema {}",
                    value.id
                )))?
                .id),
        })
    }
}

impl From<trust_anchor::Model> for TrustAnchor {
    fn from(value: trust_anchor::Model) -> Self {
        Self {
            id: value.id,
            name: value.name,
            created_date: value.created_date,
            last_modified: value.last_modified,
            type_field: value.type_field,
            publisher_reference: value.publisher_reference,
            role: value.role.into(),
            priority: value.priority,
            organisation: None,
        }
    }
}

impl IntoSortingColumn for SortableTrustAnchorColumn {
    fn get_column(&self) -> SimpleExpr {
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
