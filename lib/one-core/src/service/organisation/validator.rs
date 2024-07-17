use shared_types::OrganisationId;

use crate::model::organisation::OrganisationRelations;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::service::error::ServiceError;

pub(crate) async fn organisation_already_exists(
    repository: &dyn OrganisationRepository,
    id: &OrganisationId,
) -> Result<bool, ServiceError> {
    let organisation = repository
        .get_organisation(id, &OrganisationRelations::default())
        .await?;

    Ok(organisation.is_some())
}
