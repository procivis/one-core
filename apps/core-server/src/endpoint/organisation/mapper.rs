use uuid::Uuid;

use super::dto::CreateOrganisationResponseRestDTO;

impl From<Uuid> for CreateOrganisationResponseRestDTO {
    fn from(value: Uuid) -> Self {
        Self { id: value }
    }
}
