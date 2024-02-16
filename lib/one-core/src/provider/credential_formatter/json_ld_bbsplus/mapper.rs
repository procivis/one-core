use crate::provider::credential_formatter::json_ld_bbsplus::model::GroupEntry;

use super::model::TransformedEntry;

pub fn to_grouped_entry(entries: Vec<(usize, String)>) -> TransformedEntry {
    TransformedEntry {
        data_type: "Map".to_owned(),
        value: entries
            .into_iter()
            .map(|(index, triple)| GroupEntry {
                index,
                entry: triple,
            })
            .collect(),
    }
}
