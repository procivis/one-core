use one_core::model::instance::{InstanceRole, InstanceStatus, WalletProviderType};
use one_core::service::instance::dto::{
    HolderActivateInstanceRequestDTO, HolderActivateInstanceResponseDTO, HolderInstanceResponseDTO,
    HolderRegisterInstanceRequestDTO, HolderRegisterInstanceResponseDTO, InstanceProviderDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner};

use super::OneCore;
use super::key::KeyListItemBindingDTO;
use crate::ServiceError;
use crate::error::BindingError;
use crate::utils::{TimestampFormat, from_id_opt, into_id};

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Registers the instance with a Wallet or Verifier Provider.
    #[uniffi::method]
    pub async fn holder_register_instance(
        &self,
        request: HolderRegisterInstanceRequestBindingDTO,
    ) -> Result<HolderRegisterInstanceResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let response = core
            .instance_service
            .register_instance(request.try_into()?)
            .await?;
        Ok(response.into())
    }

    /// Check status of the instance with the provider. Will return an error
    /// if the instance has been revoked.
    #[uniffi::method]
    pub async fn holder_instance_status(&self, id: String) -> Result<(), BindingError> {
        let core = self.use_core().await?;

        Ok(core
            .instance_service
            .holder_instance_status(into_id(&id)?)
            .await?)
    }

    /// Returns instance registration details from the provider.
    #[uniffi::method]
    pub async fn holder_get_instance(
        &self,
        id: String,
    ) -> Result<HolderInstanceResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;

        Ok(core
            .instance_service
            .holder_get_instance_details(into_id(&id)?)
            .await?
            .into())
    }

    /// Activates the instance with the provider after user authentication.
    #[uniffi::method]
    pub async fn holder_activate_instance(
        &self,
        id: String,
        request: HolderActivateInstanceRequestBindingDTO,
    ) -> Result<HolderActivateInstanceResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .instance_service
            .holder_activate(into_id(&id)?, request.into())
            .await?
            .into())
    }
}

#[derive(Clone, Debug, uniffi::Enum, Into, From)]
#[into(WalletProviderType)]
#[from(WalletProviderType)]
#[uniffi(name = "InstanceProviderType")]
pub enum InstanceProviderTypeBindingEnum {
    ProcivisOne,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T=HolderRegisterInstanceRequestDTO, Error=ServiceError)]
#[uniffi(name = "HolderRegisterInstanceRequest")]
pub struct HolderRegisterInstanceRequestBindingDTO {
    /// The instance's organization.
    #[try_into(with_fn = into_id)]
    organisation_id: String,
    /// Role of the instance being registered.
    #[try_into(infallible)]
    role: InstanceRoleBindingEnum,
    /// Provider details.
    #[try_into(infallible)]
    provider: InstanceProviderBindingDTO,
    /// Choose a key type and the system will generate a key to use for
    /// registration.
    #[try_into(infallible)]
    key_type: String,
}

#[derive(Clone, Debug, uniffi::Enum, Into, From)]
#[into(InstanceRole)]
#[from(InstanceRole)]
#[uniffi(name = "InstanceRole")]
pub enum InstanceRoleBindingEnum {
    Wallet,
    Verifier,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(HolderRegisterInstanceResponseDTO)]
#[uniffi(name = "HolderRegisterInstanceResponse")]
pub struct HolderRegisterInstanceResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    pub status: InstanceStatusBindingEnum,
    pub user_nonce: Option<String>,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(InstanceProviderDTO)]
#[uniffi(name = "InstanceProvider")]
struct InstanceProviderBindingDTO {
    /// Full URL for the GET provider metadata endpoint, for example:
    /// <domain>/ssi/wallet-provider/v1/<provider> or
    /// <domain>/ssi/verifier-provider/v1/<provider>
    url: String,
    /// Choose the provider implementation.
    r#type: InstanceProviderTypeBindingEnum,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(HolderInstanceResponseDTO)]
#[uniffi(name = "HolderInstance")]
pub struct HolderInstanceResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub role: InstanceRoleBindingEnum,
    #[from(with_fn_ref = "ToString::to_string")]
    pub provider_instance_id: String,
    pub provider_url: String,
    pub provider_type: InstanceProviderTypeBindingEnum,
    pub provider_name: String,
    pub status: InstanceStatusBindingEnum,
    #[from(with_fn = convert_inner)]
    pub authentication_key: Option<KeyListItemBindingDTO>,
    pub user_nonce: Option<String>,
}

#[derive(Clone, Debug, uniffi::Enum, From)]
#[from(InstanceStatus)]
#[uniffi(name = "InstanceStatus")]
pub enum InstanceStatusBindingEnum {
    Pending,
    Active,
    Revoked,
    Unattested,
    Error,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(HolderActivateInstanceRequestDTO)]
#[uniffi(name = "HolderActivateInstanceRequest")]
pub struct HolderActivateInstanceRequestBindingDTO {
    /// Key type for the authentication key generated during activation.
    pub key_type: String,
    /// Identity token obtained from the identity provider after user authentication.
    pub user_id_token: Option<String>,
    /// Access token obtained from the identity provider after user authentication.
    pub user_access_token: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(HolderActivateInstanceResponseDTO)]
#[uniffi(name = "HolderActivateInstanceResponse")]
pub struct HolderActivateInstanceResponseBindingDTO {
    /// IdentifierId with provisioned access certificate (if any)
    #[from(with_fn = from_id_opt)]
    pub access_certificate_identifier_id: Option<String>,
}
