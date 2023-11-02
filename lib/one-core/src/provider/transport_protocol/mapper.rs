use crate::model::credential::{
    CredentialId, CredentialState, CredentialStateEnum, UpdateCredentialRequest,
};
use time::OffsetDateTime;

pub(super) fn from_credential_id_and_token(
    credential_id: &CredentialId,
    token: &str,
) -> UpdateCredentialRequest {
    UpdateCredentialRequest {
        id: credential_id.to_owned(),
        credential: Some(token.bytes().collect()),
        holder_did_id: None,
        state: Some(CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Accepted,
        }),
        interaction: None,
    }
}
