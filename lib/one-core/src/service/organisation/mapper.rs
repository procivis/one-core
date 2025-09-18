use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::identifier::Identifier;
use crate::model::organisation::Organisation;
use crate::service::organisation::dto::{
    CreateOrganisationRequestDTO, GetOrganisationDetailsResponseDTO, UpsertOrganisationRequestDTO,
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
            deactivated_at: None,
            wallet_provider: None,
            wallet_provider_issuer: None,
        }
    }
}

impl From<UpsertOrganisationRequestDTO> for CreateOrganisationRequestDTO {
    fn from(request: UpsertOrganisationRequestDTO) -> Self {
        CreateOrganisationRequestDTO {
            id: Some(request.id),
            name: request.name,
        }
    }
}

pub(super) fn detail_from_model(
    organisation: Organisation,
    wallet_provider_issuer: Option<Identifier>,
) -> GetOrganisationDetailsResponseDTO {
    GetOrganisationDetailsResponseDTO {
        id: organisation.id,
        name: organisation.name,
        created_date: organisation.created_date,
        last_modified: organisation.last_modified,
        deactivated_at: organisation.deactivated_at,
        wallet_provider: organisation.wallet_provider,
        wallet_provider_issuer: wallet_provider_issuer.map(Into::into),
    }
}
