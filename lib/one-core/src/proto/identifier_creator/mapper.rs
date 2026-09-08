use shared_types::IdentifierId;

use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::proto::identifier_creator::IdentifierTranslations;

pub(super) fn identifier_translations_from_dto(
    id: IdentifierId,
    translations: IdentifierTranslations,
    now: time::OffsetDateTime,
) -> Vec<LocalizedText> {
    let mut result = Vec::new();
    for (lang, value) in translations.name {
        result.push(LocalizedText {
            entity_id: id.into(),
            field: LocalizedTextField::Name,
            created_date: now,
            last_modified: now,
            lang,
            value,
            entity_type: LocalizedTextEntityType::Identifier,
        });
    }
    if let Some(logo_alt_text) = translations.logo_alt_text {
        for (lang, value) in logo_alt_text {
            result.push(LocalizedText {
                entity_id: id.into(),
                field: LocalizedTextField::LogoAltText,
                created_date: now,
                last_modified: now,
                lang,
                value,
                entity_type: LocalizedTextEntityType::Identifier,
            });
        }
    }
    result
}
