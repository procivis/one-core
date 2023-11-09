use crate::model::{
    credential::{CredentialId, CredentialState, CredentialStateEnum, UpdateCredentialRequest},
    interaction::Interaction,
    key::Key,
};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

pub(super) fn get_issued_credential_update(
    credential_id: &CredentialId,
    token: &str,
    key: &Key,
) -> UpdateCredentialRequest {
    UpdateCredentialRequest {
        id: credential_id.to_owned(),
        credential: Some(token.bytes().collect()),
        state: Some(CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Accepted,
        }),
        key: Some(key.id),
        ..Default::default()
    }
}

pub fn interaction_from_handle_invitation(
    host: Url,
    data: Option<Vec<u8>>,
    now: OffsetDateTime,
) -> Interaction {
    Interaction {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        host: Some(host),
        data,
    }
}
