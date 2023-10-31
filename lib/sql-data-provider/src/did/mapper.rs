use one_core::{
    model::did::{Did, DidFilterValue, DidType, GetDidList, KeyRole, SortableDidColumn},
    repository::error::DataLayerError,
};
use sea_orm::{sea_query::SimpleExpr, IntoSimpleExpr, Set};
use std::str::FromStr;
use uuid::Uuid;

use crate::{
    common::calculate_pages_count,
    entity::{self, did, key_did},
    list_query_generic::{
        get_equals_condition, get_string_match_condition, IntoFilterCondition, IntoSortingColumn,
    },
};

impl From<DidType> for entity::did::DidType {
    fn from(value: DidType) -> Self {
        match value {
            DidType::Remote => did::DidType::Remote,
            DidType::Local => did::DidType::Local,
        }
    }
}

impl From<entity::did::DidType> for DidType {
    fn from(value: entity::did::DidType) -> Self {
        match value {
            did::DidType::Remote => DidType::Remote,
            did::DidType::Local => DidType::Local,
        }
    }
}

impl TryFrom<entity::did::Model> for Did {
    type Error = DataLayerError;

    fn try_from(value: entity::did::Model) -> Result<Self, Self::Error> {
        let id = Uuid::from_str(&value.id).map_err(|_| DataLayerError::MappingError)?;

        Ok(Self {
            id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            did: value.did,
            did_type: value.type_field.into(),
            did_method: value.method,
            organisation: None,
            keys: None,
        })
    }
}

impl IntoSortingColumn for SortableDidColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            SortableDidColumn::Name => did::Column::Name,
            SortableDidColumn::CreatedDate => did::Column::CreatedDate,
            SortableDidColumn::Method => did::Column::Method,
            SortableDidColumn::Type => did::Column::TypeField,
            SortableDidColumn::Did => did::Column::Did,
        }
        .into_simple_expr()
    }
}

impl IntoFilterCondition for DidFilterValue {
    fn get_condition(self) -> sea_orm::Condition {
        match self {
            DidFilterValue::Name(string_match) => {
                get_string_match_condition(did::Column::Name, string_match)
            }
            DidFilterValue::Method(method) => get_equals_condition(did::Column::Method, method),
            DidFilterValue::Type(r#type) => {
                get_equals_condition(did::Column::TypeField, did::DidType::from(r#type))
            }
            DidFilterValue::Did(string_match) => {
                get_string_match_condition(did::Column::Did, string_match)
            }
            DidFilterValue::OrganisationId(organisation_id) => {
                get_equals_condition(did::Column::OrganisationId, organisation_id.to_string())
            }
        }
    }
}

pub(crate) fn create_list_response(
    dids: Vec<did::Model>,
    limit: Option<u64>,
    items_count: u64,
) -> Result<GetDidList, DataLayerError> {
    Ok(GetDidList {
        values: dids
            .into_iter()
            .map(|item| item.try_into())
            .collect::<Result<_, DataLayerError>>()?,
        total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
        total_items: items_count,
    })
}

impl TryFrom<Did> for did::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: Did) -> Result<Self, Self::Error> {
        let organisation = value.organisation.ok_or(DataLayerError::MappingError)?;

        Ok(Self {
            id: Set(value.id.to_string()),
            did: Set(value.did.to_owned()),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name),
            type_field: Set(value.did_type.into()),
            method: Set(value.did_method),
            organisation_id: Set(organisation.id.to_string()),
        })
    }
}

impl From<key_did::KeyRole> for KeyRole {
    fn from(value: key_did::KeyRole) -> Self {
        match value {
            key_did::KeyRole::Authentication => Self::Authentication,
            key_did::KeyRole::AssertionMethod => Self::AssertionMethod,
            key_did::KeyRole::KeyAgreement => Self::KeyAgreement,
            key_did::KeyRole::CapabilityInvocation => Self::CapabilityInvocation,
            key_did::KeyRole::CapabilityDelegation => Self::CapabilityDelegation,
        }
    }
}

impl From<KeyRole> for key_did::KeyRole {
    fn from(value: KeyRole) -> Self {
        match value {
            KeyRole::Authentication => Self::Authentication,
            KeyRole::AssertionMethod => Self::AssertionMethod,
            KeyRole::KeyAgreement => Self::KeyAgreement,
            KeyRole::CapabilityInvocation => Self::CapabilityInvocation,
            KeyRole::CapabilityDelegation => Self::CapabilityDelegation,
        }
    }
}
