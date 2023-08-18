use crate::data_layer::data_model::GetDidDetailsResponse;
use crate::data_layer::get_dids::GetDidQuery;
use crate::data_layer::{DataLayer, DataLayerError};
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

pub async fn get_first_did(
    data_layer: &DataLayer,
    organisation_id: &str,
) -> Result<GetDidDetailsResponse, OneCoreError> {
    let dids = data_layer
        .get_dids(GetDidQuery {
            page: 0,
            page_size: 1,
            sort: None,
            sort_direction: None,
            name: None,
            organisation_id: organisation_id.to_string(),
        })
        .await
        .map_err(OneCoreError::DataLayerError)?;
    Ok(dids
        .values
        .first()
        .ok_or(OneCoreError::DataLayerError(DataLayerError::RecordNotFound))?
        .to_owned())
}
