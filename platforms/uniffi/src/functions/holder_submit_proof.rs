use std::collections::HashMap;

use one_core::service::ssi_holder::dto::PresentationSubmitRequestDTO;
use one_dto_mapper::try_convert_inner;

use crate::dto::PresentationSubmitCredentialRequestBindingDTO;
use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn holder_submit_proof(
        &self,
        interaction_id: String,
        submit_credentials: HashMap<String, PresentationSubmitCredentialRequestBindingDTO>,
        did_id: String,
        key_id: Option<String>,
    ) -> Result<(), BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            core.ssi_holder_service
                .submit_proof(PresentationSubmitRequestDTO {
                    interaction_id: into_id(&interaction_id)?,
                    submit_credentials: try_convert_inner(submit_credentials)?,
                    did_id: into_id(&did_id)?,
                    key_id: key_id.map(|key_id| into_id(&key_id)).transpose()?,
                })
                .await?;

            Ok(())
        })
    }
}
