use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::organisation::Organisation;
use crate::service::organisation::dto::{
    CreateOrganisationRequestDTO, UpsertOrganisationRequestDTO,
};

impl From<CreateOrganisationRequestDTO> for Organisation {
    fn from(request: CreateOrganisationRequestDTO) -> Self {
        let now = OffsetDateTime::now_utc();
        let id = request.id.unwrap_or(Uuid::new_v4().into());
        Organisation {
            name: request.name.unwrap_or(id.to_string()),
            id,
            created_date: now,
            last_modified: now,
        }
    }
}

impl From<UpsertOrganisationRequestDTO> for CreateOrganisationRequestDTO {
    fn from(request: UpsertOrganisationRequestDTO) -> Self {
        CreateOrganisationRequestDTO {
            id: Some(request.id),
            name: Some(request.name),
        }
    }
}
