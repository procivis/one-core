use crate::{
    dto::PresentationDefinitionBindingDTO, error::BindingError, utils::into_uuid, OneCoreBinding,
};

impl OneCoreBinding {
    pub fn get_presentation_defintion(
        &self,
        proof_id: String,
    ) -> Result<PresentationDefinitionBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .proof_service
                .get_proof_presentation_definition(&into_uuid(&proof_id)?)
                .await?
                .into())
        })
    }
}
