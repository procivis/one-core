use crate::{
    utils::{into_uuid, run_sync},
    OneCoreBinding,
};
use one_core::{
    model::did::DidType,
    service::{
        did::dto::{CreateDidRequestDTO, CreateDidRequestKeysDTO},
        error::ServiceError,
    },
};

impl OneCoreBinding {
    pub fn create_local_key_did(
        &self,
        did: String,
        organisation_id: String,
        key_id: String,
    ) -> Result<String, ServiceError> {
        let key_id = into_uuid(&key_id)?;
        run_sync(async {
            self.inner
                .did_service
                .create_did(CreateDidRequestDTO {
                    name: "local".to_string(),
                    organisation_id: into_uuid(&organisation_id)?,
                    did,
                    did_type: DidType::Local,
                    did_method: "KEY".to_string(),
                    keys: CreateDidRequestKeysDTO {
                        authentication: vec![key_id],
                        assertion: vec![key_id],
                        key_agreement: vec![key_id],
                        capability_invocation: vec![key_id],
                        capability_delegation: vec![key_id],
                    },
                })
                .await
                .map(|id| id.to_string())
        })
    }
}
