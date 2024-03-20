use shared_types::OrganisationId;

use super::dto::CreateOrganisationResponseRestDTO;

impl From<OrganisationId> for CreateOrganisationResponseRestDTO {
    fn from(value: OrganisationId) -> Self {
        Self { id: value }
    }
}
