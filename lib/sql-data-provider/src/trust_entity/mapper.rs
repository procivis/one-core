use one_core::model::trust_entity::TrustEntity;
use one_core::repository::error::DataLayerError;
use one_core::repository::error::DataLayerError::MappingError;
use one_core::service::did::dto::DidListItemResponseDTO;
use one_core::service::trust_anchor::dto::GetTrustAnchorDetailResponseDTO;
use one_core::service::trust_entity::dto::{
    SortableTrustEntityColumnEnum, TrustEntitiesResponseItemDTO, TrustEntityFilterValue,
};
use sea_orm::IntoSimpleExpr;
use sea_orm::sea_query::SimpleExpr;

use crate::entity::did;
use crate::entity::trust_entity::{self, TrustEntityRole};
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_equals_condition, get_string_match_condition,
};
use crate::trust_entity::model::TrustEntityListItemEntityModel;

impl TryFrom<TrustEntityListItemEntityModel> for TrustEntitiesResponseItemDTO {
    type Error = DataLayerError;

    fn try_from(val: TrustEntityListItemEntityModel) -> Result<Self, Self::Error> {
        let did = if let Some(did_id) = val.did_id {
            Some(DidListItemResponseDTO {
                id: did_id,
                created_date: val.did_created_date.ok_or(MappingError)?,
                last_modified: val.did_last_modified.ok_or(MappingError)?,
                name: val.did_name.ok_or(MappingError)?,
                did: val.did.ok_or(MappingError)?,
                did_type: val.did_type.ok_or(MappingError)?.into(),
                did_method: val.did_method.ok_or(MappingError)?,
                deactivated: val.did_deactivated.ok_or(MappingError)?,
            })
        } else {
            None
        };
        Ok(TrustEntitiesResponseItemDTO {
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
            entity_key: val.entity_key,
            r#type: val.r#type.into(),
            content: None,
            organisation_id: val.organisation_id,
        })
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
            entity_key: value.entity_key,
            content: value.content,
            trust_anchor: None,
            organisation: None,
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
            Self::DidId(id) => get_equals_condition(did::Column::Id, id),
            Self::OrganisationId(id) => {
                get_equals_condition(trust_entity::Column::OrganisationId, id)
            }
        }
    }
}
