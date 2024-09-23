use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(PartialEq, Debug, strum::Display)]
pub enum LvvcStatus {
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
pub(super) struct IssuerResponseDTO {
    pub credential: String,
    pub format: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Lvvc {
    pub id: Uuid,
    pub created_date: OffsetDateTime,
    pub credential: Vec<u8>,
    pub linked_credential_id: Uuid,
}
