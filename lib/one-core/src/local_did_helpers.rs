use uuid::Uuid;

use crate::{
    error::OneCoreError,
    model::did::Did,
    repository::{
        did_repository::DidRepository, error::DataLayerError,
        organisation_repository::OrganisationRepository,
    },
};

pub async fn get_first_organisation_id(
    organisation_repository: &std::sync::Arc<dyn OrganisationRepository + Send + Sync>,
) -> Result<Uuid, OneCoreError> {
    let organisations = organisation_repository
        .get_organisation_list()
        .await
        .map_err(OneCoreError::DataLayerError)?;
    Ok(organisations
        .first()
        .ok_or(OneCoreError::DataLayerError(DataLayerError::RecordNotFound))?
        .id)
}

pub async fn get_first_local_did(
    did_repository: &std::sync::Arc<dyn DidRepository + Send + Sync>,
    organisation_id: &Uuid,
) -> Result<Did, OneCoreError> {
    let dids = did_repository
        .get_local_dids(organisation_id)
        .await
        .map_err(OneCoreError::DataLayerError)?;
    Ok(dids
        .first()
        .ok_or(OneCoreError::DataLayerError(DataLayerError::RecordNotFound))?
        .to_owned())
}
