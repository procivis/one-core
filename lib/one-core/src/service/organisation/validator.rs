use std::sync::Arc;

use uuid::Uuid;

use crate::{
    model::organisation::OrganisationRelations,
    repository::organisation_repository::OrganisationRepository, service::error::ServiceError,
};

pub(crate) async fn organisation_already_exists(
    repository: &Arc<dyn OrganisationRepository>,
    id: &Uuid,
) -> Result<bool, ServiceError> {
    let organisation = repository
        .get_organisation(id, &OrganisationRelations::default())
        .await?;

    Ok(organisation.is_some())
}
