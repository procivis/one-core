use one_core::model::key::KeyFilterValue;
use one_core::model::list_filter::{
    ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
};

use super::dto::KeyFilterQueryParamsRest;
use crate::dto::common::ExactColumn;

impl From<KeyFilterQueryParamsRest> for ListFilterCondition<KeyFilterValue> {
    fn from(value: KeyFilterQueryParamsRest) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id = KeyFilterValue::OrganisationId(value.organisation_id).condition();

        let name = value.name.map(|name| {
            KeyFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactColumn::Name),
                value: name,
            })
        });

        let key_algorithms = value.key_types.map(KeyFilterValue::KeyTypes);
        let key_storages = value.key_storages.map(KeyFilterValue::KeyStorages);
        let ids = value.ids.map(KeyFilterValue::Ids);
        let remote = value.is_remote.map(KeyFilterValue::remote);

        organisation_id & name & key_algorithms & key_storages & ids & remote
    }
}
