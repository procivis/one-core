use crate::config::data_structure::KeyStorageHsmAzureParams;
use crate::key_storage::{GeneratedKey, KeyStorage};
use crate::service::error::ServiceError;

#[derive(Default)]
pub struct HsmAzureKeyProvider {
    pub params: KeyStorageHsmAzureParams,
}

impl KeyStorage for HsmAzureKeyProvider {
    fn generate(&self, _algorithm: &str) -> Result<GeneratedKey, ServiceError> {
        unimplemented!()
    }
}
