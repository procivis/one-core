use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

impl OneCoreBinding {
    pub fn holder_accept_credential(
        &self,
        interaction_id: String,
        did_id: String,
        key_id: Option<String>,
    ) -> Result<(), BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .ssi_holder_service
                .accept_credential(
                    &into_id(&interaction_id)?,
                    into_id(&did_id)?,
                    key_id.map(|key_id| into_id(&key_id)).transpose()?,
                )
                .await?)
        })
    }
}
