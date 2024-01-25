use dto_mapper::convert_inner;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    model::{
        history::{History, HistoryAction, HistoryEntityType},
        key::{GetKeyList, Key, KeyId},
        organisation::Organisation,
    },
    provider::key_storage::GeneratedKey,
    service::{
        error::ServiceError,
        key::dto::{KeyRequestDTO, KeyResponseDTO},
    },
};

use super::dto::GetKeyListResponseDTO;

pub(super) fn from_create_request(
    key_id: KeyId,
    request: KeyRequestDTO,
    organisation: Organisation,
    generated_key: GeneratedKey,
) -> Key {
    let now = OffsetDateTime::now_utc();

    Key {
        id: key_id,
        created_date: now,
        last_modified: now,
        public_key: generated_key.public_key,
        name: request.name.to_owned(),
        key_reference: generated_key.key_reference,
        storage_type: request.storage_type.to_owned(),
        key_type: request.key_type,
        organisation: Some(organisation),
    }
}

impl TryFrom<Key> for KeyResponseDTO {
    type Error = ServiceError;

    fn try_from(value: Key) -> Result<Self, Self::Error> {
        let organisation_id = value
            .organisation
            .ok_or(ServiceError::MappingError(
                "organisation is None".to_string(),
            ))?
            .id;

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            organisation_id,
            name: value.name,
            public_key: value.public_key,
            key_type: value.key_type,
            storage_type: value.storage_type,
        })
    }
}

impl From<GetKeyList> for GetKeyListResponseDTO {
    fn from(value: GetKeyList) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

pub(super) fn key_create_history_event(key: Key) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Created,
        entity_id: key.id.into(),
        entity_type: HistoryEntityType::Key,
        organisation: key.organisation,
    }
}
