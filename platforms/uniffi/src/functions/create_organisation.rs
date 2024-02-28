use crate::{error::BindingError, utils::into_id, OneCoreBinding};

impl OneCoreBinding {
    pub fn create_organisation(&self, uuid: Option<String>) -> Result<String, BindingError> {
        let id = match uuid {
            None => None,
            Some(uuid_str) => Some(into_id(&uuid_str)?),
        };

        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .organisation_service
                .create_organisation(id)
                .await?
                .to_string())
        })
    }
}
