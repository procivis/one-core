use crate::dto::PresentationDefinitionBindingDTO;
use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn get_presentation_definition(
        &self,
        proof_id: String,
    ) -> Result<PresentationDefinitionBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .proof_service
                .get_proof_presentation_definition(&into_id(&proof_id)?)
                .await?
                .into())
        })
    }
}
