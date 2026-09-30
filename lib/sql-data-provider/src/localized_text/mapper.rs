use std::collections::HashSet;

use one_core::clock::now_utc;
use one_core::model::localized_text::LocalizedText;
use sea_orm::Set;

use crate::entity::localized_text::{ActiveModel, Model};

pub(super) fn deduplicate_localized_texts(texts: Vec<LocalizedText>) -> Vec<LocalizedText> {
    let mut seen = HashSet::new();
    texts
        .into_iter()
        .rev()
        .filter(|text| seen.insert((text.entity_id, text.lang.clone(), text.field.clone())))
        .collect()
}

impl From<LocalizedText> for ActiveModel {
    fn from(value: LocalizedText) -> Self {
        let now = now_utc();
        Self {
            entity_id: Set(value.entity_id),
            lang: Set(value.lang),
            field: Set(value.field.into()),
            created_date: Set(now),
            last_modified: Set(now),
            value: Set(value.value),
            entity_type: Set(value.entity_type.into()),
        }
    }
}

impl From<Model> for LocalizedText {
    fn from(value: Model) -> Self {
        Self {
            entity_id: value.entity_id,
            lang: value.lang,
            field: value.field.into(),
            created_date: value.created_date,
            last_modified: value.last_modified,
            value: value.value,
            entity_type: value.entity_type.into(),
        }
    }
}
