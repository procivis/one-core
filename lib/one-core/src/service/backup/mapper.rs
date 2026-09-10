use one_dto_mapper::convert_inner;

use super::error::BackupServiceError;
use crate::config::core_config::CoreConfig;
use crate::error::ContextWithErrorCode;
use crate::model::backup::UnexportableEntities;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::service::backup::dto::UnexportableEntitiesResponseDTO;
use crate::service::credential::dto::CredentialAttestationBlobs;
use crate::service::credential::mapper::credential_detail_response_from_model;

pub(super) async fn unexportable_entities_to_response_dto(
    entities: UnexportableEntities,
    config: &CoreConfig,
    credential_repository: &dyn CredentialRepository,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<UnexportableEntitiesResponseDTO, BackupServiceError> {
    let mut credentials = vec![];

    for credential in entities.credentials {
        credentials.push(
            credential_detail_response_from_model(
                credential,
                config,
                CredentialAttestationBlobs::default(),
                None,
                None,
                credential_repository,
                formatter_provider,
                None,
            )
            .await
            .error_while("converting credential")?,
        );
    }

    Ok(UnexportableEntitiesResponseDTO {
        credentials,
        keys: convert_inner(entities.keys),
        dids: convert_inner(entities.dids),
        identifiers: convert_inner(entities.identifiers),
        history: convert_inner(entities.histories),
        total_credentials: entities.total_credentials,
        total_keys: entities.total_keys,
        total_dids: entities.total_dids,
        total_identifiers: entities.total_identifiers,
        total_histories: entities.total_histories,
    })
}
