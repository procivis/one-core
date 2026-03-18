use std::collections::HashMap;

use super::dto::DisplayNameDTO;

pub(super) fn params_into_display_names(params: HashMap<String, String>) -> Vec<DisplayNameDTO> {
    params
        .into_iter()
        .map(|(lang, value)| DisplayNameDTO { lang, value })
        .collect()
}
