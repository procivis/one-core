use one_dto_mapper::convert_inner;
use uuid::Uuid;

use super::dto::{CreateTrustCollectionRequestDTO, TrustCollectionPublicResponseDTO};
use crate::model::trust_collection::TrustCollection;
use crate::model::trust_list_subscription::TrustListSubscription;
use crate::proto::clock::Clock;

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
        organisation_id: request.organisation_id,
        organisation: None,
    }
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
