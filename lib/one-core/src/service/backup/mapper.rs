use one_dto_mapper::convert_inner;

use crate::config::core_config::CoreConfig;
use crate::model::backup::UnexportableEntities;
use crate::service::backup::dto::UnexportableEntitiesResponseDTO;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::error::ServiceError;

pub(super) fn unexportable_entities_to_response_dto(
    entities: UnexportableEntities,
    config: &CoreConfig,
) -> Result<UnexportableEntitiesResponseDTO, ServiceError> {
    Ok(UnexportableEntitiesResponseDTO {
        credentials: entities
            .credentials
            .into_iter()
            .map(|credential| credential_detail_response_from_model(credential, config, None, None))
            .collect::<Result<Vec<_>, _>>()?,
        keys: convert_inner(entities.keys),
        dids: convert_inner(entities.dids),
        identifiers: convert_inner(entities.identifiers),
        total_credentials: entities.total_credentials,
        total_keys: entities.total_keys,
        total_dids: entities.total_dids,
        total_identifiers: entities.total_identifiers,
    })
}
