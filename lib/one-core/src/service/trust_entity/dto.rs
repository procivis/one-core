use shared_types::TrustAnchorId;

use crate::model::trust_entity::TrustEntityRole;

#[derive(Clone, Debug)]
pub struct CreateTrustEntityRequestDTO {
    pub entity_id: String,
    pub name: String,
    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub trust_anchor_id: TrustAnchorId,
}
