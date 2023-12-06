use crate::{error::BindingError, utils::into_uuid, OneCoreBinding};

impl OneCoreBinding {
    pub fn create_organisation(&self, uuid: Option<String>) -> Result<String, BindingError> {
        let id = match uuid {
            None => None,
            Some(uuid_str) => Some(into_uuid(&uuid_str)?),
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
