use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Localized strings serialized and iterated in ascending language order.
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct I18nString(pub BTreeMap<String, String>);

impl IntoIterator for I18nString {
    type Item = (String, String);
    type IntoIter = std::collections::btree_map::IntoIter<String, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
