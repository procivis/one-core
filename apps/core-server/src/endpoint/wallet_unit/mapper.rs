use one_core::model::list_filter::{ListFilterCondition, StringMatch, StringMatchType};
use one_core::model::wallet_unit::WalletUnitFilterValue;
use one_dto_mapper::convert_inner;

use super::dto::WalletUnitFilterQueryParamsRestDTO;

impl From<WalletUnitFilterQueryParamsRestDTO> for ListFilterCondition<WalletUnitFilterValue> {
    fn from(value: WalletUnitFilterQueryParamsRestDTO) -> Self {
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

        let wallet_provider_type = value
            .wallet_provider_type
            .map(WalletUnitFilterValue::WalletProviderType);

        ListFilterCondition::<WalletUnitFilterValue>::from(name)
            & ids
            & status
            & os
            & wallet_provider_type
    }
}
