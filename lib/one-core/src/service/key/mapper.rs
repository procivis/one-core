use one_dto_mapper::convert_inner;
use shared_types::KeyId;
use time::OffsetDateTime;

use super::dto::{GetKeyListResponseDTO, KeyRequestDTO};
use crate::model::key::{GetKeyList, Key};
use crate::model::organisation::Organisation;
use crate::provider::key_storage::model::StorageGeneratedKey;
use crate::service::key::dto::KeyResponseDTO;
use crate::service::key::error::KeyServiceError;

pub(super) fn from_create_request(
    key_id: KeyId,
    request: KeyRequestDTO,
    organisation: Organisation,
    generated_key: StorageGeneratedKey,
) -> Key {
    let now = OffsetDateTime::now_utc();

    Key {
        id: key_id,
        created_date: now,
        last_modified: now,
        public_key: generated_key.public_key,
        name: request.name,
        key_reference: generated_key.key_reference,
        storage_type: request.storage_type,
        key_type: request.key_type,
        organisation: Some(organisation),
    }
}

impl TryFrom<Key> for KeyResponseDTO {
    type Error = KeyServiceError;

    fn try_from(value: Key) -> Result<Self, Self::Error> {
        let organisation_id = value
            .organisation
            .ok_or(KeyServiceError::MappingError(
                "organisation is None".to_string(),
            ))?
            .id;

        Ok(Self {
            id: value.id.into(),
            created_date: value.created_date,
            last_modified: value.last_modified,
            organisation_id,
            name: value.name,
            public_key: value.public_key,
            key_type: value.key_type,
            storage_type: value.storage_type,
            is_remote: value.key_reference.is_none(),
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
