use one_core::model::trust_entity::TrustEntity;
use one_core::repository::error::DataLayerError;
use one_core::service::did::dto::DidListItemResponseDTO;
use one_core::service::trust_anchor::dto::GetTrustAnchorDetailResponseDTO;
use one_core::service::trust_entity::dto::{
    SortableTrustEntityColumnEnum, TrustEntitiesResponseItemDTO, TrustEntityFilterValue,
};
use sea_orm::IntoSimpleExpr;
use sea_orm::sea_query::SimpleExpr;
use shared_types::OrganisationId;

use crate::entity::did;
use crate::entity::trust_entity::{self, TrustEntityRole};
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_equals_condition, get_string_match_condition,
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
            trust_anchor: GetTrustAnchorDetailResponseDTO {
                id: val.trust_anchor_id,
                created_date: val.trust_anchor_created_date,
                last_modified: val.trust_anchor_last_modified,
                name: val.trust_anchor_name,
                r#type: val.trust_anchor_type,
                is_publisher: val.trust_anchor_is_publisher,
                publisher_reference: val.trust_anchor_publisher_reference,
            },
            did: DidListItemResponseDTO {
                id: val.did_id,
                created_date: val.did_created_date,
                last_modified: val.did_last_modified,
                name: val.did_name,
                did: val.did,
                did_type: val.did_type.into(),
                did_method: val.did_method,
                deactivated: val.did_deactivated,
            },
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
            Self::DidId(id) => get_equals_condition(trust_entity::Column::DidId, id),
            Self::OrganisationId(id) => get_equals_condition(did::Column::OrganisationId, id),
        }
    }
}

pub fn trust_entity_to_organisation_id(
    trust_entity: TrustEntity,
) -> Result<OrganisationId, DataLayerError> {
    trust_entity
        .did
        .and_then(|did| did.organisation)
        .map(|organisation| organisation.id)
        .ok_or(DataLayerError::MappingError)
}
