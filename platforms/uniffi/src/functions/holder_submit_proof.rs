use crate::{
    dto::PresentationSubmitCredentialRequestBindingDTO, error::BindingError, utils::into_uuid,
    OneCoreBinding,
};
use one_core::service::ssi_holder::dto::PresentationSubmitRequestDTO;
use std::collections::HashMap;

impl OneCoreBinding {
    pub fn holder_submit_proof(
        &self,
        interaction_id: String,
        submit_credentials: HashMap<String, PresentationSubmitCredentialRequestBindingDTO>,
    ) -> Result<(), BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            core.ssi_holder_service
                .submit_proof(PresentationSubmitRequestDTO {
                    interaction_id: into_uuid(&interaction_id)?,
                    submit_credentials: submit_credentials
                        .into_iter()
                        .map(|(key, value)| Ok((key, value.try_into()?)))
                        .collect::<Result<_, BindingError>>()?,
                })
                .await?;

            Ok(())
        })
    }
}
