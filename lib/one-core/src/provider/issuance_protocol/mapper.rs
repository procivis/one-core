use shared_types::{BlobId, IdentifierId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::credential::{Clearable, CredentialStateEnum, UpdateCredentialRequest};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::organisation::Organisation;

pub(super) fn get_issued_credential_update(
    credential_blob_id: BlobId,
    holder_identifier_id: IdentifierId,
) -> UpdateCredentialRequest {
    UpdateCredentialRequest {
        state: Some(CredentialStateEnum::Accepted),
        suspend_end_date: Clearable::DontTouch,
        holder_identifier_id: Some(holder_identifier_id),
        credential_blob_id: Some(credential_blob_id),
        ..Default::default()
    }
}

pub(crate) fn interaction_from_handle_invitation(
    data: Option<Vec<u8>>,
    now: OffsetDateTime,
    organisation: Option<Organisation>,
) -> Interaction {
    Interaction {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        data,
        organisation,
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
    }
}
