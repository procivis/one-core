use crate::{dto::PresentationDefinitionBindingDTO, utils::run_sync, OneCoreBinding};
use one_core::service::error::ServiceError;
use uuid::Uuid;

impl OneCoreBinding {
    pub fn get_presentation_defintion(
        &self,
        proof_id: String,
    ) -> Result<PresentationDefinitionBindingDTO, ServiceError> {
        let proof_id =
            Uuid::parse_str(&proof_id).map_err(|e| ServiceError::MappingError(e.to_string()))?;

        run_sync(async {
            Ok(self
                .inner
                .proof_service
                .get_proof_presentation_definition(&proof_id)
                .await?
                .into())
        })
    }
}
