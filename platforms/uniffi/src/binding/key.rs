use std::collections::HashMap;

use one_core::service::key::dto::{
    KeyGenerateCSRRequestDTO, KeyGenerateCSRRequestProfile, KeyGenerateCSRRequestSubjectDTO,
};
use one_dto_mapper::Into;

use super::OneCoreBinding;
use crate::error::BindingError;

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

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(KeyGenerateCSRRequestDTO)]
pub struct KeyGenerateCSRRequestBindingDTO {
    pub profile: KeyGenerateCSRRequestProfileBinding,
    pub subject: KeyGenerateCSRRequestSubjectBindingDTO,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(KeyGenerateCSRRequestProfile)]
pub enum KeyGenerateCSRRequestProfileBinding {
    Generic,
    Mdl,
    Ca,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(KeyGenerateCSRRequestSubjectDTO)]
pub struct KeyGenerateCSRRequestSubjectBindingDTO {
    /// Two-letter country code.
    pub country_name: Option<String>,
    /// Common name to include in the CSR, typically the domain name of the organization.
    pub common_name: Option<String>,

    pub state_or_province_name: Option<String>,
    pub organisation_name: Option<String>,
    pub locality_name: Option<String>,
    pub serial_number: Option<String>,
}
