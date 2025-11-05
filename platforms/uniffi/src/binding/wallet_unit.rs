use one_core::model::wallet_unit::WalletProviderType;
use one_core::service::wallet_unit::dto::{
    HolderRefreshWalletUnitRequestDTO, HolderRegisterWalletUnitRequestDTO, WalletProviderDTO,
};
use one_dto_mapper::{From, Into, TryInto};

use crate::ServiceError;
use crate::binding::OneCoreBinding;
use crate::error::BindingError;
use crate::utils::into_id;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn holder_register_wallet_unit(
        &self,
        request: HolderRegisterWalletUnitRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let core = self.use_core().await?;
        let result = request.try_into();
        let response = core.wallet_unit_service.holder_register(result?).await?;
        Ok(response.to_string())
    }

    #[uniffi::method]
    pub async fn holder_wallet_unit_status(&self, id: String) -> Result<(), BindingError> {
        let core = self.use_core().await?;

        let id = into_id(&id)?;

        Ok(core
            .wallet_unit_service
            .holder_wallet_unit_status(id)
            .await?)
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
