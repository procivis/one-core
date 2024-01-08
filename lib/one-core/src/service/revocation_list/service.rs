use crate::model::revocation_list::RevocationListRelations;
use crate::service::error::{EntityNotFoundError, ServiceError};
use crate::service::revocation_list::dto::RevocationListId;
use crate::service::revocation_list::RevocationListService;

impl RevocationListService {
    pub async fn get_revocation_list_by_id(
        &self,
        id: &RevocationListId,
    ) -> Result<String, ServiceError> {
        let result = self
            .revocation_list_repository
            .get_revocation_list(id, &RevocationListRelations::default())
            .await?;

        let Some(result) = result else {
            return Err(EntityNotFoundError::RevocationList(*id).into());
        };

        result.try_into()
    }
}
