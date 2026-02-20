use shared_types::RevocationListId;

use super::dto::RevocationListResponseDTO;
use crate::config::core_config::RevocationType;
use crate::error::ContextWithErrorCode;
use crate::model::revocation_list::RevocationListRelations;
use crate::service::error::{EntityNotFoundError, MissingProviderError, ServiceError};
use crate::service::revocation_list::RevocationListService;

impl RevocationListService {
    pub async fn get_revocation_list_by_id(
        &self,
        id: &RevocationListId,
    ) -> Result<RevocationListResponseDTO, ServiceError> {
        let result = self
            .revocation_list_repository
            .get_revocation_list(id, &RevocationListRelations::default())
            .await
            .error_while("getting revocation list")?;

        let Some(list) = result else {
            return Err(EntityNotFoundError::RevocationList(*id).into());
        };

        let r#type = self
            .config
            .revocation
            .get_type(&list.r#type)
            .error_while("getting revocation type")?;

        Ok(RevocationListResponseDTO {
            revocation_list: list
                .get_status_credential()
                .error_while("parsing status list")?,
            format: list.format,
            r#type,
        })
    }

    pub async fn get_crl_by_id(&self, id: &RevocationListId) -> Result<Vec<u8>, ServiceError> {
        let result = self
            .revocation_list_repository
            .get_revocation_list(id, &RevocationListRelations::default())
            .await
            .error_while("getting revocation list")?;

        let Some(list) = result else {
            return Err(EntityNotFoundError::RevocationList(*id).into());
        };

        let r#type = self
            .config
            .revocation
            .get_type(&list.r#type)
            .error_while("getting revocation type")?;
        if r#type != RevocationType::CRL {
            tracing::warn!("Invalid CRL request, list_id: {id}");
            return Err(EntityNotFoundError::RevocationList(*id).into());
        }

        let revocation_method = self
            .revocation_method_provider
            .get_revocation_method(&list.r#type)
            .ok_or(MissingProviderError::RevocationMethod(list.r#type))?;

        let updated_list = revocation_method
            .get_updated_list(list.id)
            .await
            .error_while("getting updated CRL")?;
        Ok(updated_list)
    }
}
