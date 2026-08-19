use shared_types::RevocationListId;

use super::RevocationListService;
use super::dto::RevocationListResponseDTO;
use super::error::RevocationServiceError;
use crate::config::core_config::RevocationType;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::repository::error::{DataLayerError, EntityKind};

impl RevocationListService {
    pub async fn get_revocation_list_by_id(
        &self,
        id: &RevocationListId,
    ) -> Result<RevocationListResponseDTO, RevocationServiceError> {
        let list = self
            .revocation_list_repository
            .get_revocation_list(id)
            .await
            .error_while("getting revocation list")?;

        let r#type = self
            .config
            .revocation
            .get_type(&list.r#type)
            .error_while("getting revocation type")?;

        Ok(RevocationListResponseDTO {
            revocation_list: list.formatted_list,
            format: list.format,
            r#type,
        })
    }

    pub async fn get_crl_by_id(
        &self,
        id: &RevocationListId,
    ) -> Result<Vec<u8>, RevocationServiceError> {
        let list = self
            .revocation_list_repository
            .get_revocation_list(id)
            .await
            .error_while("getting revocation list")?;

        let r#type = self
            .config
            .revocation
            .get_type(&list.r#type)
            .error_while("getting revocation type")?;
        if r#type != RevocationType::CRL {
            tracing::warn!("Invalid CRL request, list_id: {id}");
            return Err(DataLayerError::EntityNotFound {
                kind: EntityKind::RevocationList,
                id: (*id).into(),
            }
            .error_while("getting revocation type")
            .into());
        }

        let revocation_method = self
            .revocation_method_provider
            .get_revocation_method(&list.r#type)?;

        let updated_list = revocation_method
            .get_updated_list(list.id)
            .await
            .error_while("getting updated CRL")?;
        Ok(updated_list)
    }
}
