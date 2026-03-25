use one_core::model::wallet_unit::{WalletProviderType, WalletUnitStatus};
use one_core::service::wallet_provider::dto::DisplayNameDTO;
use one_core::service::wallet_unit::dto::{
    HolderRegisterWalletUnitRequestDTO, HolderWalletUnitRegisterResponseDTO,
    HolderWalletUnitResponseDTO, TrustCollectionsDetailResponseDTO, WalletProviderDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner};

use super::OneCore;
use super::key::KeyListItemBindingDTO;
use crate::ServiceError;
use crate::error::BindingError;
use crate::utils::{TimestampFormat, into_id};

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Registers with a Wallet Provider.
    #[uniffi::method]
    pub async fn holder_register_wallet_unit(
        &self,
        request: HolderRegisterWalletUnitRequestBindingDTO,
    ) -> Result<HolderRegisterWalletUnitResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let response = core
            .wallet_unit_service
            .holder_register(request.try_into()?)
            .await?;
        Ok(response.into())
    }

    /// Check status of wallet unit with the Wallet Provider. Will return an error
    /// if the unit has been revoked.
    #[uniffi::method]
    pub async fn holder_wallet_unit_status(&self, id: String) -> Result<(), BindingError> {
        let core = self.use_core().await?;

        Ok(core
            .wallet_unit_service
            .holder_wallet_unit_status(into_id(&id)?)
            .await?)
    }

    /// Returns wallet registration details from the Wallet Provider.
    #[uniffi::method]
    pub async fn holder_get_wallet_unit(
        &self,
        id: String,
    ) -> Result<HolderWalletUnitResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;

        Ok(core
            .wallet_unit_service
            .holder_get_wallet_unit_details(into_id(&id)?)
            .await?
            .into())
    }

    /// Edit holder wallet unit
    #[uniffi::method]
    pub async fn holder_wallet_unit_update(
        &self,
        id: String,
        request: EditHolderWalletUnitRequestBindingDTO,
    ) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        core.wallet_unit_service
            .edit_holder_wallet_unit(into_id(&id)?, request.try_into()?)
            .await?;
        Ok(())
    }

    #[uniffi::method]
    pub async fn holder_get_wallet_unit_trust_collections(
        &self,
        id: String,
    ) -> Result<TrustCollectionsBindingDTO, BindingError> {
        let core = self.use_core().await?;

        Ok(core
            .wallet_unit_service
            .holder_get_wallet_unit_trust_collections(into_id(&id)?)
            .await?
            .into())
    }
}

#[derive(Clone, Debug, uniffi::Enum, Into, From)]
#[into(WalletProviderType)]
#[from(WalletProviderType)]
#[uniffi(name = "WalletProviderType")]
pub enum WalletProviderTypeBindingEnum {
    ProcivisOne,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T=HolderRegisterWalletUnitRequestDTO, Error=ServiceError)]
#[uniffi(name = "HolderRegisterWalletUnitRequest")]
pub struct HolderRegisterWalletUnitRequestBindingDTO {
    /// Specifies the organizational context for this operation.
    #[try_into(with_fn = into_id)]
    organisation_id: String,
    /// Reference the `walletProvider` configuration.
    #[try_into(infallible)]
    wallet_provider: WalletProviderBindingDTO,
    #[try_into(infallible)]
    key_type: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(HolderWalletUnitRegisterResponseDTO)]
#[uniffi(name = "HolderRegisterWalletUnitResponse")]
pub struct HolderRegisterWalletUnitResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    pub status: WalletUnitStatusBindingEnum,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(WalletProviderDTO)]
#[uniffi(name = "WalletProvider")]
struct WalletProviderBindingDTO {
    url: String,
    r#type: WalletProviderTypeBindingEnum,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(HolderWalletUnitResponseDTO)]
#[uniffi(name = "HolderWalletUnit")]
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
    #[from(with_fn = convert_inner)]
    pub authentication_key: Option<KeyListItemBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Enum, From)]
#[from(WalletUnitStatus)]
#[uniffi(name = "WalletUnitStatus")]
pub enum WalletUnitStatusBindingEnum {
    Pending,
    Active,
    Revoked,
    Unattested,
    Error,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "HolderWalletUnitUpdateRequest")]
pub struct EditHolderWalletUnitRequestBindingDTO {
    pub trust_collections: Vec<String>,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[from(TrustCollectionsDetailResponseDTO)]
#[uniffi(name = "TrustCollections")]
pub struct TrustCollectionsBindingDTO {
    #[from(with_fn = convert_inner)]
    pub trust_collections: Vec<TrustCollectionInfoBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "TrustCollectionInfo")]
pub struct TrustCollectionInfoBindingDTO {
    pub selected: bool,
    pub id: String,
    pub name: String,
    pub logo: String,
    pub display_name: Vec<DisplayNameBindingDTO>,
    pub description: Vec<DisplayNameBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[from(DisplayNameDTO)]
#[uniffi(name = "DisplayName")]
pub struct DisplayNameBindingDTO {
    pub lang: String,
    pub value: String,
}
