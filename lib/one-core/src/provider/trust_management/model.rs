use serde::Deserialize;
use shared_types::{DidValue, TrustEntityId};
use time::OffsetDateTime;

use crate::model::trust_entity::{TrustEntityRole, TrustEntityState};

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TrustEntityByDid {
    pub id: TrustEntityId,
    pub name: String,
    pub did: DidValue,

    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub created_date: OffsetDateTime,
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub last_modified: OffsetDateTime,

    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub state: TrustEntityState,
}
