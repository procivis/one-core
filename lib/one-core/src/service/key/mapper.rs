use time::OffsetDateTime;
use uuid::Uuid;

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
