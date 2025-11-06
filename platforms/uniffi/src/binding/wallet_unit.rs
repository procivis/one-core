use one_core::model::wallet_unit::{WalletProviderType, WalletUnitStatus};
use one_core::service::wallet_unit::dto::{
    HolderRefreshWalletUnitRequestDTO, HolderRegisterWalletUnitRequestDTO,
    HolderWalletUnitResponseDTO, WalletProviderDTO,
};
use one_dto_mapper::{From, Into, TryInto};

use crate::ServiceError;
use crate::binding::OneCoreBinding;
use crate::binding::identifier::KeyListItemResponseBindingDTO;
use crate::error::BindingError;
use crate::utils::{TimestampFormat, into_id};

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn holder_register_wallet_unit(
        &self,
        request: HolderRegisterWalletUnitRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let core = self.use_core().await?;
        let response = core
            .wallet_unit_service
            .holder_register(request.try_into()?)
            .await?;
        Ok(response.to_string())
    }

    #[uniffi::method]
    pub async fn holder_wallet_unit_status(&self, id: String) -> Result<(), BindingError> {
        let core = self.use_core().await?;

        Ok(core
            .wallet_unit_service
            .holder_wallet_unit_status(into_id(&id)?)
            .await?)
    }

    #[uniffi::method]
    pub async fn holder_get_wallet_unit(
        &self,
        id: String,
    ) -> Result<HolderWalletUnitResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;

        Ok(core
            .wallet_unit_service
            .get_wallet_unit_details(into_id(&id)?)
            .await?
            .into())
    }
}

#[derive(Clone, Debug, uniffi::Enum, Into, From)]
#[into(WalletProviderType)]
#[from(WalletProviderType)]
pub enum WalletProviderTypeBindingEnum {
    ProcivisOne,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T=HolderRegisterWalletUnitRequestDTO, Error=ServiceError)]
pub struct HolderRegisterWalletUnitRequestBindingDTO {
    #[try_into(with_fn = into_id)]
    organisation_id: String,
    #[try_into(infallible)]
    wallet_provider: WalletProviderBindingDTO,
    #[try_into(infallible)]
    key_type: String,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T=HolderRefreshWalletUnitRequestDTO, Error=ServiceError)]
pub struct HolderRefreshWalletUnitRequestBindingDTO {
    #[try_into(with_fn = into_id)]
    organisation_id: String,
    #[try_into(infallible)]
    pub app_integrity_check_required: bool,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(WalletProviderDTO)]
struct WalletProviderBindingDTO {
    url: String,
    r#type: WalletProviderTypeBindingEnum,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(HolderWalletUnitResponseDTO)]
pub struct HolderWalletUnitResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub provider_wallet_unit_id: String,
    pub wallet_provider_url: String,
    pub wallet_provider_type: WalletProviderTypeBindingEnum,
    pub wallet_provider_name: String,
    pub status: WalletUnitStatusBindingEnum,
    pub authentication_key: KeyListItemResponseBindingDTO,
}

#[derive(Clone, Debug, uniffi::Enum, From)]
#[from(WalletUnitStatus)]
pub enum WalletUnitStatusBindingEnum {
    Pending,
    Active,
    Revoked,
    Error,
}
