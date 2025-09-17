use one_core::service::organisation::dto::UpsertOrganisationRequestDTO;
use shared_types::OrganisationId;

use super::dto::{CreateOrganisationResponseRestDTO, UpsertOrganisationRequestRestDTO};

impl From<OrganisationId> for CreateOrganisationResponseRestDTO {
    fn from(value: OrganisationId) -> Self {
        Self { id: value }
    }
}

pub(crate) fn upsert_request_from_request(
    id: OrganisationId,
    request: UpsertOrganisationRequestRestDTO,
) -> UpsertOrganisationRequestDTO {
    UpsertOrganisationRequestDTO {
        id,
        name: request.name,
        deactivate: request.deactivate,
        wallet_provider: request.wallet_provider,
        wallet_provider_issuer: request.wallet_provider_issuer,
    }
}
