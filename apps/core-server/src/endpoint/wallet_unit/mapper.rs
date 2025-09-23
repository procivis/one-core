use one_core::model::list_filter::{
    ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::model::wallet_unit::{WalletUnitFilterValue, WalletUnitListQuery};
use one_core::service::error::ServiceError;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use one_dto_mapper::convert_inner;

use super::dto::{ListWalletUnitsQuery, WalletUnitFilterQueryParamsRestDTO};

impl TryFrom<WalletUnitFilterQueryParamsRestDTO> for ListFilterCondition<WalletUnitFilterValue> {
    type Error = ServiceError;
    fn try_from(value: WalletUnitFilterQueryParamsRestDTO) -> Result<Self, Self::Error> {
        let organisation_id =
            WalletUnitFilterValue::OrganisationId(value.organisation_id).condition();
        let name = value.name.map(|name| {
            WalletUnitFilterValue::Name(StringMatch {
                r#match: StringMatchType::StartsWith,
                value: name,
            })
        });

        let ids = value.ids.map(WalletUnitFilterValue::Ids);

        let status = value
            .status
            .map(|status| WalletUnitFilterValue::Status(convert_inner(status)));

        let os = value
            .os
            .map(|os_values| WalletUnitFilterValue::Os(convert_inner(os_values)));

        let attestation = if let Some(attestation) = value.attestation {
            let attestation_hash = SHA256.hash_base64(attestation.as_bytes()).map_err(|e| {
                ServiceError::MappingError(format!("Could not hash wallet unit attestation: {e}"))
            })?;
            Some(WalletUnitFilterValue::AttestationHash(attestation_hash))
        } else {
            None
        };

        let wallet_provider_type = value
            .wallet_provider_type
            .map(WalletUnitFilterValue::WalletProviderType);

        Ok(organisation_id & name & ids & status & os & wallet_provider_type & attestation)
    }
}

impl TryFrom<ListWalletUnitsQuery> for WalletUnitListQuery {
    type Error = ServiceError;

    fn try_from(value: ListWalletUnitsQuery) -> Result<Self, Self::Error> {
        Ok(Self {
            pagination: Some(ListPagination {
                page: value.page,
                page_size: value.page_size.inner(),
            }),
            sorting: value.sort.map(|column| ListSorting {
                column: column.into(),
                direction: convert_inner(value.sort_direction),
            }),
            filtering: Some(value.filter.try_into()?),
            include: value.include.map(convert_inner),
        })
    }
}
