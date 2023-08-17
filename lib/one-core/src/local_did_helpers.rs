use crate::data_layer::{data_model::GetDidDetailsResponse, DataLayer, DataLayerError};
use crate::error::OneCoreError;

pub async fn get_first_organisation_id(data_layer: &DataLayer) -> Result<String, OneCoreError> {
    let organisations = data_layer
        .get_organisations()
        .await
        .map_err(OneCoreError::DataLayerError)?;
    Ok(organisations
        .first()
        .ok_or(OneCoreError::DataLayerError(DataLayerError::RecordNotFound))?
        .id
        .to_owned())
}

pub async fn get_first_local_did(
    data_layer: &DataLayer,
    organisation_id: &str,
) -> Result<GetDidDetailsResponse, OneCoreError> {
    let dids = data_layer
        .get_local_dids(organisation_id)
        .await
        .map_err(OneCoreError::DataLayerError)?;
    Ok(dids
        .first()
        .ok_or(OneCoreError::DataLayerError(DataLayerError::RecordNotFound))?
        .to_owned())
}
