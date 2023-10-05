use crate::{
    dto::PresentationDefinitionBindingDTO,
    utils::{into_uuid, run_sync},
    OneCoreBinding,
};
use one_core::service::error::ServiceError;

impl OneCoreBinding {
    pub fn get_presentation_defintion(
        &self,
        proof_id: String,
    ) -> Result<PresentationDefinitionBindingDTO, ServiceError> {
        run_sync(async {
            Ok(self
                .inner
                .proof_service
                .get_proof_presentation_definition(&into_uuid(&proof_id)?)
                .await?
                .into())
        })
    }
}
