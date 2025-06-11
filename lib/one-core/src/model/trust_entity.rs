use serde::{Deserialize, Serialize};
use shared_types::TrustEntityId;
use time::OffsetDateTime;

use super::trust_anchor::{TrustAnchor, TrustAnchorRelations};
use crate::model::organisation::{Organisation, OrganisationRelations};

#[derive(Clone, Debug)]
pub struct TrustEntity {
    pub id: TrustEntityId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
    pub name: String,
    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub state: TrustEntityState,
    pub r#type: TrustEntityType,
    pub entity_key: String,
    pub content: Option<Vec<u8>>,

    // Relations
    pub trust_anchor: Option<TrustAnchor>,
    pub organisation: Option<Organisation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustEntityType {
    Did,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustEntityRole {
    Issuer,
    Verifier,
    Both,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustEntityState {
    Active,
    Removed,
    Withdrawn,
    RemovedAndWithdrawn,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct TrustEntityRelations {
    pub trust_anchor: Option<TrustAnchorRelations>,
    pub organisation: Option<OrganisationRelations>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateTrustEntityRequest {
    pub state: Option<TrustEntityState>,
    pub logo: Option<Option<String>>,
    pub privacy_url: Option<Option<String>>,
    pub website: Option<Option<String>>,
    pub name: Option<String>,
    pub terms_url: Option<Option<String>>,
    pub role: Option<TrustEntityRole>,
}
