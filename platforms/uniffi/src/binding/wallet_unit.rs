use one_core::model::wallet_unit::{WalletProviderType, WalletUnitStatus};
use one_core::service::wallet_unit::dto::{
    HolderRefreshWalletUnitRequestDTO, HolderRegisterWalletUnitRequestDTO,
    HolderWalletUnitAttestationResponseDTO, WalletProviderDTO,
};
use one_dto_mapper::{From, Into, TryInto};

use crate::ServiceError;
use crate::binding::OneCoreBinding;
use crate::error::BindingError;
use crate::utils::{TimestampFormat, into_id};

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn holder_register_wallet_unit(
        &self,
        request: HolderRegisterWalletUnitRequestBindingDTO,
    ) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        let result = request.try_into();
        core.wallet_unit_service.holder_register(result?).await?;
        Ok(())
    }

    #[uniffi::method]
    pub async fn holder_refresh_wallet_unit(
        &self,
        request: HolderRefreshWalletUnitRequestBindingDTO,
    ) -> Result<(), BindingError> {
        let request = request.try_into()?;

        let core = self.use_core().await?;
        core.wallet_unit_service.holder_refresh(request).await?;
        Ok(())
    }

    #[uniffi::method]
    pub async fn holder_get_wallet_unit_attestation(
        &self,
        organisation_id: String,
    ) -> Result<HolderAttestationWalletUnitResponseBindingDTO, BindingError> {
        let organisation_id = into_id(&organisation_id)?;

        let core = self.use_core().await?;
        let response = core
            .wallet_unit_service
            .holder_attestation(organisation_id)
            .await?;
        Ok(response.into())
    }
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T=HolderRegisterWalletUnitRequestDTO, Error=ServiceError)]
pub struct HolderRegisterWalletUnitRequestBindingDTO {
    #[try_into(with_fn = into_id)]
    organisation_id: String,
    #[try_into(infallible)]
    wallet_provider: WalletProviderBindingDTO,
    #[try_into(with_fn = into_id)]
    key: String,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T=HolderRefreshWalletUnitRequestDTO, Error=ServiceError)]
pub struct HolderRefreshWalletUnitRequestBindingDTO {
    #[try_into(with_fn = into_id)]
    organisation_id: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(HolderWalletUnitAttestationResponseDTO)]
pub struct HolderAttestationWalletUnitResponseBindingDTO {
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub expiration_date: String,
    pub status: WalletUnitStatusBindingEnum,
    pub attestation: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub wallet_unit_id: String,
    pub wallet_provider_url: String,
    pub wallet_provider_type: WalletProviderTypeBindingEnum,
    pub wallet_provider_name: String,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(WalletProviderDTO)]
struct WalletProviderBindingDTO {
    url: String,
    r#type: WalletProviderTypeBindingEnum,
    name: String,
}

#[derive(Clone, Debug, From, Into, uniffi::Enum)]
#[into(WalletProviderType)]
#[from(WalletProviderType)]
pub(crate) enum WalletProviderTypeBindingEnum {
    ProcivisOne,
}

#[derive(Clone, Debug, From, Into, uniffi::Enum)]
#[into(WalletUnitStatus)]
#[from(WalletUnitStatus)]
pub(crate) enum WalletUnitStatusBindingEnum {
    Active,
    Revoked,
}
