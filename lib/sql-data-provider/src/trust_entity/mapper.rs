use one_core::model::list_filter::ListFilterCondition;
use one_core::model::trust_entity::TrustEntity;
use one_core::service::did::dto::DidListItemResponseDTO;
use one_core::service::trust_anchor::dto::GetTrustAnchorDetailResponseDTO;
use one_core::service::trust_entity::dto::{
    SortableTrustEntityColumnEnum, TrustEntitiesResponseItemDTO, TrustEntityFilterValue,
};
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::{ColumnTrait, Condition, IntoSimpleExpr};

use crate::entity::did;
use crate::entity::trust_entity::{self, TrustEntityRole, TrustEntityType};
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_equals_condition, get_string_match_condition,
};
use crate::trust_entity::model::TrustEntityListItemEntityModel;

impl From<TrustEntityListItemEntityModel> for TrustEntitiesResponseItemDTO {
    fn from(val: TrustEntityListItemEntityModel) -> Self {
        let did = if let (
            Some(did_id),
            Some(did_create_date),
            Some(did_last_modified),
            Some(did_name),
            Some(did_value),
            Some(did_type),
            Some(did_method),
            Some(did_deactivated),
        ) = (
            val.did_id,
            val.did_created_date,
            val.did_last_modified,
            val.did_name,
            val.did,
            val.did_type,
            val.did_method,
            val.did_deactivated,
        ) {
            Some(DidListItemResponseDTO {
                id: did_id,
                created_date: did_create_date,
                last_modified: did_last_modified,
                name: did_name,
                did: did_value,
                did_type: did_type.into(),
                did_method,
                deactivated: did_deactivated,
            })
        } else {
            None
        };

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
            r#type: val.r#type.into(),
            entity_key: val.entity_key,
            trust_anchor: GetTrustAnchorDetailResponseDTO {
                id: val.trust_anchor_id,
                created_date: val.trust_anchor_created_date,
                last_modified: val.trust_anchor_last_modified,
                name: val.trust_anchor_name,
                r#type: val.trust_anchor_type,
                is_publisher: val.trust_anchor_is_publisher,
                publisher_reference: val.trust_anchor_publisher_reference,
            },
            did,
            content: None,
            organisation_id: val.organisation_id,
        }
    }
}

impl From<trust_entity::Model> for TrustEntity {
    fn from(value: trust_entity::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            deactivated_at: value.deactivated_at,
            name: value.name,
            logo: value
                .logo
                .map(|logo| String::from_utf8_lossy(&logo).into_owned()),
            website: value.website,
            terms_url: value.terms_url,
            privacy_url: value.privacy_url,
            role: value.role.into(),
            state: value.state.into(),
            r#type: value.r#type.into(),
            entity_key: value.entity_key.into(),
            content: value
                .content
                .map(|b| String::from_utf8_lossy(&b).into_owned()),
            organisation: None,
            trust_anchor: None,
        }
    }
}

impl IntoSortingColumn for SortableTrustEntityColumnEnum {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::Name => trust_entity::Column::Name.into_simple_expr(),
            Self::Role => trust_entity::Column::Role.into_simple_expr(),
            Self::LastModified => trust_entity::Column::LastModified.into_simple_expr(),
            Self::State => trust_entity::Column::State.into_simple_expr(),
            Self::Type => trust_entity::Column::Type.into_simple_expr(),
            Self::EntityKey => trust_entity::Column::EntityKey.into_simple_expr(),
        }
    }
}

impl IntoFilterCondition for TrustEntityFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(trust_entity::Column::Name, string_match)
            }
            Self::Role(role) => {
                get_equals_condition(trust_entity::Column::Role, TrustEntityRole::from(role))
            }
            Self::TrustAnchor(id) => get_equals_condition(trust_entity::Column::TrustAnchorId, id),
            Self::OrganisationId(id) => Condition::any()
                .add(
                    Condition::all()
                        .add(trust_entity::Column::OrganisationId.eq(id))
                        .add(did::Column::OrganisationId.is_null()),
                )
                .add(did::Column::OrganisationId.eq(id)),
            Self::Type(r#type) => trust_entity::Column::Type
                .is_in(r#type.into_iter().map(TrustEntityType::from))
                .into_condition(),
            Self::EntityKey(entity_key) => {
                get_equals_condition(trust_entity::Column::EntityKey, entity_key)
            }
            Self::DidId(id) => get_equals_condition(did::Column::Id, id),
        }
    }
}
