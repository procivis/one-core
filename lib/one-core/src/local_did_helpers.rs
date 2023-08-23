use uuid::Uuid;

use crate::error::OneCoreError;
use crate::repository::data_provider::DataProvider;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::{data_provider::GetDidDetailsResponse, error::DataLayerError};

pub async fn get_first_organisation_id(
    data_layer: &std::sync::Arc<dyn OrganisationRepository + Send + Sync>,
) -> Result<Uuid, OneCoreError> {
    let organisations = data_layer
        .get_organisation_list()
        .await
        .map_err(OneCoreError::DataLayerError)?;
    Ok(organisations
        .first()
        .ok_or(OneCoreError::DataLayerError(DataLayerError::RecordNotFound))?
        .id)
}

pub async fn get_first_local_did(
    data_layer: &std::sync::Arc<dyn DataProvider + Send + Sync>,
    organisation_id: &Uuid,
) -> Result<GetDidDetailsResponse, OneCoreError> {
    let dids = data_layer
        .get_local_dids(&organisation_id.to_string())
        .await
        .map_err(OneCoreError::DataLayerError)?;
    Ok(dids
        .first()
        .ok_or(OneCoreError::DataLayerError(DataLayerError::RecordNotFound))?
        .to_owned())
}
