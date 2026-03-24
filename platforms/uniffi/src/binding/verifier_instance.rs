use one_core::service::verifier_instance::dto::{
    RegisterVerifierInstanceRequestDTO, RegisterVerifierInstanceResponseDTO,
};
use one_dto_mapper::{From, TryInto};

use super::OneCore;
use crate::error::{BindingError, ErrorResponseBindingDTO};
use crate::utils::into_id;

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    #[uniffi::method]
    pub async fn register_verifier_instance(
        &self,
        request: RegisterVerifierInstanceRequestBindingDTO,
    ) -> Result<RegisterVerifierInstanceResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let response = core
            .verifier_instance_service
            .register_verifier_instance(request.try_into()?)
            .await?;
        Ok(response.into())
    }
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = RegisterVerifierInstanceRequestDTO, Error = ErrorResponseBindingDTO)]
#[uniffi(name = "RegisterVerifierInstanceRequest")]
pub struct RegisterVerifierInstanceRequestBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    pub verifier_provider_url: String,
    pub r#type: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(RegisterVerifierInstanceResponseDTO)]
#[uniffi(name = "RegisterVerifierInstanceResponse")]
pub struct RegisterVerifierInstanceResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
}
