use std::collections::HashMap;

use one_core::service::key::dto::KeyCheckCertificateRequestDTO;
use one_dto_mapper::Into;

use super::OneCoreBinding;
use crate::error::BindingError;
use crate::utils::into_id;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn generate_key(
        &self,
        request: KeyRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .key_service
            .create_key(request.try_into()?)
            .await?
            .to_string())
    }

    #[uniffi::method]
    pub async fn check_certificate(
        &self,
        key_id: String,
        certificate: KeyCheckCertificateRequestBindingDTO,
    ) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .key_service
            .check_certificate(&into_id(&key_id)?, certificate.into())
            .await?)
    }
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(KeyCheckCertificateRequestDTO)]
pub struct KeyCheckCertificateRequestBindingDTO {
    pub certificate: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct KeyRequestBindingDTO {
    pub organisation_id: String,
    pub key_type: String,
    pub key_params: HashMap<String, String>,
    pub name: String,
    pub storage_type: String,
    pub storage_params: HashMap<String, String>,
}
