use one_dto_mapper::Into;
use serde::{Deserialize, Serialize};
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(PartialEq, Debug, strum::Display)]
pub(crate) enum LvvcStatus {
    #[strum(serialize = "ACCEPTED")]
    Accepted,
    #[strum(serialize = "REVOKED")]
    Revoked,
    #[strum(serialize = "SUSPENDED")]
    Suspended {
        suspend_end_date: Option<OffsetDateTime>,
    },
}

#[derive(Clone, Debug, Deserialize)]
pub struct IssuerResponseDTO {
    pub credential: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Into)]
#[into(crate::model::validity_credential::Lvvc)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Lvvc {
    pub id: Uuid,
    pub created_date: OffsetDateTime,
    pub credential: Vec<u8>,
    pub linked_credential_id: CredentialId,
}
