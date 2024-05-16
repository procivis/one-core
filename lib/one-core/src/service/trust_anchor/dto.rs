use shared_types::OrganisationId;

use crate::model::trust_anchor::TrustAnchorRole;

#[derive(Clone, Debug)]
pub struct CreateTrustAnchorRequestDTO {
    pub name: String,
    pub type_: String,
    pub publisher_reference: String,
    pub role: TrustAnchorRole,
    pub priority: u32,
    pub organisation_id: OrganisationId,
}
