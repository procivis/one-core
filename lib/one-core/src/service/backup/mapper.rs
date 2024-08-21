use crate::config::core_config::CoreConfig;
use crate::model::backup::UnexportableEntities;
use crate::service::backup::dto::UnexportableEntitiesResponseDTO;
use crate::service::credential::dto::CredentialDetailResponseDTO;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::error::ServiceError;
use dto_mapper::convert_inner;

pub(super) async fn unexportable_entities_to_response_dto(
    entities: UnexportableEntities,
    config: &CoreConfig,
) -> Result<UnexportableEntitiesResponseDTO, ServiceError> {
    let mut credentials: Vec<CredentialDetailResponseDTO> = vec![];
    for credential in entities.credentials {
        credentials.push(credential_detail_response_from_model(credential, config).await?);
    }

    Ok(UnexportableEntitiesResponseDTO {
        credentials,
        keys: convert_inner(entities.keys),
        dids: convert_inner(entities.dids),
        total_credentials: entities.total_credentials,
        total_keys: entities.total_keys,
        total_dids: entities.total_dids,
    })
}
