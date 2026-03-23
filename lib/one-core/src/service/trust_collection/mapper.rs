use one_dto_mapper::convert_inner;
use uuid::Uuid;

use super::dto::{
    CreateTrustCollectionRequestDTO, CreateTrustListSubscriptionRequestDTO,
    TrustCollectionPublicResponseDTO,
};
use crate::model::trust_collection::TrustCollection;
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{TrustListSubscription, TrustListSubscriptionState};
use crate::proto::clock::Clock;
use crate::service::trust_collection::error::TrustCollectionServiceError;

pub(super) fn map_create_trust_collection_request(
    clock: &dyn Clock,
    request: CreateTrustCollectionRequestDTO,
) -> TrustCollection {
    let now = clock.now_utc();
    TrustCollection {
        id: Uuid::new_v4().into(),
        name: request.name,
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        remote_trust_collection_url: None,
        organisation_id: request.organisation_id,
        organisation: None,
    }
}

pub(super) fn map_create_trust_list_subscription_request(
    clock: &dyn Clock,
    request: CreateTrustListSubscriptionRequestDTO,
    trust_collection: TrustCollection,
    role: TrustListRoleEnum,
) -> Result<TrustListSubscription, TrustCollectionServiceError> {
    let now = clock.now_utc();
    Ok(TrustListSubscription {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        r#type: request.r#type,
        reference: request.reference.into(),
        role,
        state: TrustListSubscriptionState::Active,
        trust_collection_id: trust_collection.id,
        name: request.name,
        trust_collection: Some(trust_collection),
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
