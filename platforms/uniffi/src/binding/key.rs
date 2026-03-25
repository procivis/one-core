use std::collections::HashMap;

use one_core::service::key::dto::{KeyGenerateCSRRequestSubjectDTO, KeyListItemResponseDTO};
use one_dto_mapper::{From, Into};

use super::OneCore;
use crate::error::BindingError;
use crate::utils::TimestampFormat;

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
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
#[uniffi(name = "GenerateKeyRequest")]
pub struct KeyRequestBindingDTO {
    /// Specifies the organizational context of this operation.
    pub organisation_id: String,
    /// Choose which key algorithm to use to create the key pair. Check
    /// `keyAlgorithm` of your configuration for supported options and
    /// reference the configured instance.
    pub key_type: String,
    pub key_params: HashMap<String, String>,
    /// Internal label for created key pair.
    pub name: String,
    /// Choose how to store the key. Check `keyStorage` of your configuration
    /// for supported options and reference the configured instance.
    pub storage_type: String,
    pub storage_params: HashMap<String, String>,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(KeyGenerateCSRRequestSubjectDTO)]
#[uniffi(name = "CSRSubject")]
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

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(KeyListItemResponseDTO)]
#[uniffi(name = "KeyListItem")]
pub struct KeyListItemBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub key_type: String,
    pub storage_type: String,
}
