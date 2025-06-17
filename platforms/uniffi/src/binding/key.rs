use std::collections::HashMap;

use one_core::service::key::dto::{
    PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO, PublicKeyJwkMlweDataDTO, PublicKeyJwkOctDataDTO,
    PublicKeyJwkRsaDataDTO,
};
use one_dto_mapper::From;

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

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(PublicKeyJwkDTO)]
pub enum PublicKeyJwkBindingDTO {
    Ec(PublicKeyJwkEllipticDataBindingDTO),
    Rsa(PublicKeyJwkRsaDataBindingDTO),
    Okp(PublicKeyJwkEllipticDataBindingDTO),
    Oct(PublicKeyJwkOctDataBindingDTO),
    Mlwe(PublicKeyJwkMlweDataBindingDTO),
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(PublicKeyJwkMlweDataDTO)]
pub struct PublicKeyJwkMlweDataBindingDTO {
    pub r#use: Option<String>,
    pub alg: String,
    pub x: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(PublicKeyJwkOctDataDTO)]
pub struct PublicKeyJwkOctDataBindingDTO {
    pub r#use: Option<String>,
    pub k: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(PublicKeyJwkRsaDataDTO)]
pub struct PublicKeyJwkRsaDataBindingDTO {
    pub r#use: Option<String>,
    pub e: String,
    pub n: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(PublicKeyJwkEllipticDataDTO)]
pub struct PublicKeyJwkEllipticDataBindingDTO {
    pub r#use: Option<String>,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
}
