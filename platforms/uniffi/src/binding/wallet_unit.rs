use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, StringMatch, StringMatchType, ValueComparison,
};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::model::wallet_unit::{
    SortableWalletUnitColumn, WalletProviderType, WalletUnitFilterValue, WalletUnitListQuery,
    WalletUnitStatus,
};
use one_core::service::wallet_unit::dto::{
    GetWalletUnitListResponseDTO, GetWalletUnitResponseDTO, HolderRefreshWalletUnitRequestDTO,
    HolderRegisterWalletUnitRequestDTO, HolderWalletUnitAttestationResponseDTO, WalletProviderDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner};

use crate::ServiceError;
use crate::binding::OneCoreBinding;
use crate::binding::common::SortDirection;
use crate::binding::mapper::deserialize_timestamp;
use crate::error::BindingError;
use crate::utils::{TimestampFormat, into_id};

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn get_wallet_unit(&self, id: String) -> Result<WalletUnitBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .wallet_unit_service
            .get_wallet_unit(&into_id(id)?)
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn list_wallet_units(
        &self,
        query: WalletUnitListQueryBindingDTO,
    ) -> Result<WalletUnitListBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let condition = {
            let exact = query.exact.unwrap_or_default();

            let name = query.name.map(|name| {
                WalletUnitFilterValue::Name(StringMatch {
                    value: name,
                    r#match: if exact.contains(&ExactWalletUnitFilterColumnBindingEnum::Name) {
                        StringMatchType::Equals
                    } else {
                        StringMatchType::StartsWith
                    },
                })
            });

            let ids = match query.ids {
                Some(ids) => {
                    let ids = ids.iter().map(into_id).collect::<Result<Vec<_>, _>>()?;
                    Some(WalletUnitFilterValue::Ids(ids))
                }
                None => None,
            };

            let status = query.status.map(|status| {
                WalletUnitFilterValue::Status(status.iter().map(|st| st.clone().into()).collect())
            });

            let wallet_provider_type = query.wallet_provider_type.map(|wp_type| {
                WalletUnitFilterValue::WalletProviderType(
                    wp_type
                        .iter()
                        .map(|wpt| {
                            let core_type: WalletProviderType = wpt.clone().into();
                            core_type.to_string()
                        })
                        .collect(),
                )
            });

            let os = query.os.map(WalletUnitFilterValue::Os);

            let created_date_after = query
                .created_date_after
                .map(|date| {
                    Ok::<_, BindingError>(WalletUnitFilterValue::CreatedDate(ValueComparison {
                        comparison: ComparisonType::GreaterThanOrEqual,
                        value: deserialize_timestamp(&date)?,
                    }))
                })
                .transpose()?;
            let created_date_before = query
                .created_date_before
                .map(|date| {
                    Ok::<_, BindingError>(WalletUnitFilterValue::CreatedDate(ValueComparison {
                        comparison: ComparisonType::LessThanOrEqual,
                        value: deserialize_timestamp(&date)?,
                    }))
                })
                .transpose()?;

            let last_modified_after = query
                .last_modified_after
                .map(|date| {
                    Ok::<_, BindingError>(WalletUnitFilterValue::LastModified(ValueComparison {
                        comparison: ComparisonType::GreaterThanOrEqual,
                        value: deserialize_timestamp(&date)?,
                    }))
                })
                .transpose()?;

            let last_modified_before = query
                .last_modified_before
                .map(|date| {
                    Ok::<_, BindingError>(WalletUnitFilterValue::LastModified(ValueComparison {
                        comparison: ComparisonType::LessThanOrEqual,
                        value: deserialize_timestamp(&date)?,
                    }))
                })
                .transpose()?;

            ListFilterCondition::<WalletUnitFilterValue>::default()
                & name
                & ids
                & status
                & wallet_provider_type
                & os
                & created_date_after
                & created_date_before
                & last_modified_after
                & last_modified_before
        };

        let sorting = query.sort.map(|sort| ListSorting {
            column: sort.into(),
            direction: query.sort_direction.map(Into::into),
        });

        let query = WalletUnitListQuery {
            pagination: Some(ListPagination {
                page: query.page,
                page_size: query.page_size,
            }),
            sorting,
            filtering: Some(condition),
            include: None,
        };
        Ok(core
            .wallet_unit_service
            .get_wallet_unit_list(query)
            .await?
            .into())
    }

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

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetWalletUnitListResponseDTO)]
pub struct WalletUnitListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<WalletUnitBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetWalletUnitResponseDTO)]
pub struct WalletUnitBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_issuance: String,
    pub name: String,
    pub os: String,
    pub status: WalletUnitStatusBindingEnum,
    pub wallet_provider_type: WalletProviderTypeBindingEnum,
    pub wallet_provider_name: String,
    pub public_key: String,
}

#[derive(Clone, Debug, uniffi::Enum, Into, From)]
#[into(WalletUnitStatus)]
#[from(WalletUnitStatus)]
pub enum WalletUnitStatusBindingEnum {
    Active,
    Revoked,
}

#[derive(Clone, Debug, uniffi::Enum, Into, From)]
#[into(WalletProviderType)]
#[from(WalletProviderType)]
pub enum WalletProviderTypeBindingEnum {
    ProcivisOne,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct WalletUnitListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortableWalletUnitColumnBindingEnum>,
    pub sort_direction: Option<SortDirection>,

    pub name: Option<String>,
    pub exact: Option<Vec<ExactWalletUnitFilterColumnBindingEnum>>,
    pub ids: Option<Vec<String>>,
    pub status: Option<Vec<WalletUnitStatusBindingEnum>>,
    pub wallet_provider_type: Option<Vec<WalletProviderTypeBindingEnum>>,
    pub os: Option<Vec<String>>,
    pub created_date_after: Option<String>,
    pub created_date_before: Option<String>,
    pub last_modified_after: Option<String>,
    pub last_modified_before: Option<String>,
}

#[derive(Clone, Debug, PartialEq, uniffi::Enum)]
pub enum ExactWalletUnitFilterColumnBindingEnum {
    Name,
}

#[derive(Clone, Debug, uniffi::Enum, Into, From)]
#[into(SortableWalletUnitColumn)]
#[from(SortableWalletUnitColumn)]
pub enum SortableWalletUnitColumnBindingEnum {
    Name,
    CreatedDate,
    LastModified,
    Os,
    Status,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T=HolderRegisterWalletUnitRequestDTO, Error=ServiceError)]
pub struct HolderRegisterWalletUnitRequestBindingDTO {
    #[try_into(with_fn = into_id)]
    organisation_id: String,
    #[try_into(infallible)]
    wallet_provider: WalletProviderBindingDTO,
    #[try_into(with_fn = into_id)]
    key_id: String,
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
