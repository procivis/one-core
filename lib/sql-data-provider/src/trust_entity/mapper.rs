use one_core::model::trust_entity::TrustEntity;
use one_core::service::trust_entity::dto::{
    SortableTrustEntityColumnEnum, TrustEntitiesResponseItemDTO, TrustEntityFilterValue,
};
use sea_orm::sea_query::SimpleExpr;
use sea_orm::IntoSimpleExpr;

use crate::entity::trust_entity::{self, TrustEntityRole};
use crate::list_query_generic::{
    get_equals_condition, get_string_match_condition, IntoFilterCondition, IntoSortingColumn,
};
use crate::trust_entity::model::TrustEntityListItemEntityModel;

impl From<TrustEntityListItemEntityModel> for TrustEntitiesResponseItemDTO {
    fn from(val: TrustEntityListItemEntityModel) -> Self {
        TrustEntitiesResponseItemDTO {
            id: val.id,
            name: val.name,
            created_date: val.created_date,
            last_modified: val.last_modified,
            logo: val
                .logo
                .map(|logo| String::from_utf8_lossy(&logo).into_owned()),
            website: val.website,
            terms_url: val.terms_url,
            privacy_url: val.privacy_url,
            role: val.role.into(),
            state: val.state.into(),
            trust_anchor_id: val.trust_anchor_id,
            did_id: val.did_id,
        }
    }
}

impl From<trust_entity::Model> for TrustEntity {
    fn from(value: trust_entity::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            logo: value
                .logo
                .map(|logo| String::from_utf8_lossy(&logo).into_owned()),
            website: value.website,
            terms_url: value.terms_url,
            privacy_url: value.privacy_url,
            role: value.role.into(),
            state: value.state.into(),
            trust_anchor: None,
            did: None,
        }
    }
}

impl IntoSortingColumn for SortableTrustEntityColumnEnum {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::Name => trust_entity::Column::Name.into_simple_expr(),
            Self::Role => trust_entity::Column::Role.into_simple_expr(),
        }
    }
}

impl IntoFilterCondition for TrustEntityFilterValue {
    fn get_condition(self) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(trust_entity::Column::Name, string_match)
            }
            Self::Role(role) => {
                get_equals_condition(trust_entity::Column::Role, TrustEntityRole::from(role))
            }
            Self::TrustAnchor(id) => get_equals_condition(trust_entity::Column::TrustAnchorId, id),
            Self::DidId(id) => get_equals_condition(trust_entity::Column::DidId, id),
        }
    }
}
