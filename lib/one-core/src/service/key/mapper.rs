use time::OffsetDateTime;
use uuid::Uuid;

use crate::service::error::ServiceError;
use crate::service::key::dto::KeyResponseDTO;
use crate::{
    key_storage::GeneratedKey,
    model::{key::Key, organisation::Organisation},
    service::key::dto::KeyRequestDTO,
};

pub(super) fn from_create_request(
    request: KeyRequestDTO,
    organisation: Organisation,
    generated_key: GeneratedKey,
) -> Key {
    let now = OffsetDateTime::now_utc();

    Key {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        public_key: generated_key.public,
        name: request.name.to_owned(),
        private_key: generated_key.private,
        storage_type: request.storage_type.to_owned(),
        key_type: request.key_type,
        credential: None,
        dids: None,
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
