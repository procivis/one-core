use serde::Deserialize;
use shared_types::{DidValue, IdentifierId, OrganisationId, TrustEntityId, TrustEntityKey};
use time::OffsetDateTime;

use crate::model::trust_entity::{TrustEntityRole, TrustEntityState, TrustEntityType};

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TrustEntityByEntityKey {
    pub id: TrustEntityId,
    pub name: String,
    pub did: Option<DidValue>,
    pub identifier_id: Option<IdentifierId>,
    pub entity_key: TrustEntityKey,
    pub r#type: TrustEntityType,
    pub content: Option<String>,

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
    pub organisation_id: Option<OrganisationId>,
}
