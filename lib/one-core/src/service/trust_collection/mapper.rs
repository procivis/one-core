use std::sync::Arc;

use one_dto_mapper::convert_inner;
use uuid::Uuid;

use super::OrganisationRepository;
use super::dto::{
    CreateTrustCollectionRequestDTO, CreateTrustListSubscriptionRequestDTO,
    GetTrustCollectionResponseDTO, TrustCollectionFilterParamsDTO,
    TrustCollectionListItemResponseDTO, TrustCollectionPublicResponseDTO,
    TrustListSubscriptionExactColumn, TrustListSubscriptionFilterParamsDTO,
};
use super::error::TrustCollectionServiceError;
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use crate::model::relation::Related;
use crate::model::trust_collection::{
    ExactTrustCollectionFilterColumn, TrustCollection, TrustCollectionFilterValue,
};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{
    TrustListSubscription, TrustListSubscriptionFilterValue, TrustListSubscriptionState,
};

impl From<TrustCollection> for GetTrustCollectionResponseDTO {
    fn from(value: TrustCollection) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id: value.organisation.id(),
            remote_trust_collection_url: value.remote_trust_collection_url,
            ecosystem: value.ecosystem,
        }
    }
}

impl From<TrustCollection> for TrustCollectionListItemResponseDTO {
    fn from(value: TrustCollection) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id: value.organisation.id(),
            remote_trust_collection_url: value.remote_trust_collection_url,
            ecosystem: value.ecosystem,
        }
    }
}

pub(super) fn map_create_trust_collection_request(
    request: CreateTrustCollectionRequestDTO,
    organisation_repository: Arc<dyn OrganisationRepository>,
) -> TrustCollection {
    let now = crate::clock::now_utc();
    TrustCollection {
        id: Uuid::new_v4().into(),
        name: request.name,
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        remote_trust_collection_url: None,
        organisation: Related::new(request.organisation_id, organisation_repository),
        ecosystem: request.ecosystem,
    }
}

pub(super) fn map_create_trust_list_subscription_request(
    request: CreateTrustListSubscriptionRequestDTO,
    trust_collection: TrustCollection,
    role: Option<TrustListRoleEnum>,
) -> Result<TrustListSubscription, TrustCollectionServiceError> {
    let now = crate::clock::now_utc();
    Ok(TrustListSubscription {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        r#type: request.r#type,
        reference: request.reference.into(),
        role,
        state: TrustListSubscriptionState::Active,
        name: request.name,
        trust_collection: trust_collection.into(),
    })
}

pub(super) fn get_public_dto(
    collection: TrustCollection,
    trust_lists: Vec<TrustListSubscription>,
) -> TrustCollectionPublicResponseDTO {
    TrustCollectionPublicResponseDTO {
        name: collection.name,
        trust_lists: convert_inner(trust_lists),
    }
}

impl From<TrustCollectionFilterParamsDTO> for ListFilterCondition<TrustCollectionFilterValue> {
    fn from(value: TrustCollectionFilterParamsDTO) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id = TrustCollectionFilterValue::OrganisationId {
            id: value.organisation_id,
            include_inherited_collections: value.include_parent_organisation_collections,
        }
        .condition();

        let name = value.name.map(|name| {
            TrustCollectionFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactTrustCollectionFilterColumn::Name),
                value: name,
            })
        });

        let ids = value.ids.map(TrustCollectionFilterValue::Ids);

        let ecosystems = value.ecosystems.map(TrustCollectionFilterValue::Ecosystems);

        let created_date_after = value.created_date_after.map(|date| {
            TrustCollectionFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            TrustCollectionFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            TrustCollectionFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            TrustCollectionFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        organisation_id
            & name
            & ids
            & ecosystems
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
    }
}

impl From<TrustListSubscriptionFilterParamsDTO>
    for ListFilterCondition<TrustListSubscriptionFilterValue>
{
    fn from(value: TrustListSubscriptionFilterParamsDTO) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let name = value.name.map(|name| {
            TrustListSubscriptionFilterValue::Name(StringMatch {
                r#match: get_string_match_type(TrustListSubscriptionExactColumn::Name),
                value: name,
            })
        });

        let reference = value.reference.map(|reference| {
            TrustListSubscriptionFilterValue::Reference(StringMatch {
                r#match: get_string_match_type(TrustListSubscriptionExactColumn::Reference),
                value: reference,
            })
        });

        let ids = value.ids.map(TrustListSubscriptionFilterValue::Ids);

        let roles = value.roles.map(TrustListSubscriptionFilterValue::Role);
        let states = value.states.map(TrustListSubscriptionFilterValue::State);
        let types = value.types.map(TrustListSubscriptionFilterValue::Type);

        let created_date_after = value.created_date_after.map(|date| {
            TrustListSubscriptionFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            TrustListSubscriptionFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            TrustListSubscriptionFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            TrustListSubscriptionFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        ListFilterCondition::<TrustListSubscriptionFilterValue>::default()
            & name
            & reference
            & roles
            & states
            & types
            & ids
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
    }
}
