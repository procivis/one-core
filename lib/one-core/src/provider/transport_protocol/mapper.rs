use crate::model::credential::{
    CredentialId, CredentialState, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::interaction::Interaction;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

pub(super) fn from_credential_id_and_token(
    credential_id: &CredentialId,
    token: &str,
) -> UpdateCredentialRequest {
    UpdateCredentialRequest {
        id: credential_id.to_owned(),
        credential: Some(token.bytes().collect()),
        holder_did_id: None,
        issuer_did_id: None,
        state: Some(CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Accepted,
        }),
        interaction: None,
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
