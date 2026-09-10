use std::collections::HashMap;

use shared_types::IdentifierId;
use shared_types::i18n::I18nString;
use standardized_types::openid4vci::IssuerDisplay;
use time::OffsetDateTime;

use super::creator::default_name_translation;
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

pub(crate) fn build_identifier_translations(
    identifier_id: IdentifierId,
    identifier_name: &str,
    maybe_translations: Option<IdentifierTranslations>,
    now: OffsetDateTime,
    default_language: &str,
) -> Vec<LocalizedText> {
    let mut translations = match maybe_translations {
        Some(translations) => identifier_translations_from_dto(identifier_id, translations, now),
        None => vec![],
    };

    if !translations
        .iter()
        .any(|text| text.field == LocalizedTextField::Name && text.lang == *default_language)
    {
        translations.extend(default_name_translation(
            identifier_id,
            identifier_name.to_owned(),
            now,
            default_language,
        ));
    }

    translations
}

pub(crate) fn issuer_display_to_identifier_translations(
    display: &[IssuerDisplay],
    default_language: &str,
) -> Option<IdentifierTranslations> {
    if display.is_empty() {
        return None;
    }

    let mut names = HashMap::new();
    let mut logo_alt_texts = HashMap::new();
    for entry in display {
        let lang = entry
            .locale
            .as_deref()
            .unwrap_or(default_language)
            .to_owned();
        names.insert(lang.clone(), entry.name.clone());
        if let Some(alt_text) = entry.logo.as_ref().and_then(|logo| logo.alt_text.clone()) {
            logo_alt_texts.insert(lang, alt_text);
        }
    }

    Some(IdentifierTranslations {
        name: I18nString(names),
        logo_alt_text: (!logo_alt_texts.is_empty()).then_some(I18nString(logo_alt_texts)),
    })
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;
    use standardized_types::openid4vci::{Image, IssuerDisplay};
    use uuid::Uuid;

    use super::{build_identifier_translations, issuer_display_to_identifier_translations};
    use crate::clock::now_utc;
    use crate::model::localized_text::LocalizedTextField;
    use crate::proto::identifier_creator::IdentifierTranslations;

    fn display(name: &str, locale: Option<&str>, alt_text: Option<&str>) -> IssuerDisplay {
        IssuerDisplay {
            name: name.to_owned(),
            locale: locale.map(ToOwned::to_owned),
            logo: alt_text.map(|alt| Image {
                uri: "https://logo".to_owned(),
                alt_text: Some(alt.to_owned()),
            }),
        }
    }

    #[test]
    fn issuer_display_to_translations_none_for_empty_display() {
        assert!(issuer_display_to_identifier_translations(&[], "en").is_none());
    }

    #[test]
    fn issuer_display_to_translations_uses_default_language_for_missing_locale() {
        let result =
            issuer_display_to_identifier_translations(&[display("Issuer", None, None)], "en")
                .unwrap();

        assert_eq!(result.name.0.get("en").map(String::as_str), Some("Issuer"));
        assert!(result.logo_alt_text.is_none());
    }

    #[test]
    fn issuer_display_to_translations_collects_names_and_alt_texts_per_language() {
        let result = issuer_display_to_identifier_translations(
            &[
                display("Issuer", Some("en"), None),
                display("Aussteller", Some("de"), Some("Logo Beschreibung")),
            ],
            "en",
        )
        .unwrap();

        assert_eq!(result.name.0.get("en").map(String::as_str), Some("Issuer"));
        assert_eq!(
            result.name.0.get("de").map(String::as_str),
            Some("Aussteller")
        );
        let alt = result.logo_alt_text.unwrap();
        assert_eq!(
            alt.0.get("de").map(String::as_str),
            Some("Logo Beschreibung")
        );
        assert!(!alt.0.contains_key("en"));
    }

    #[test]
    fn build_identifier_translations_backfills_default_language_name() {
        let id = Uuid::new_v4().into();
        let supplied = IdentifierTranslations {
            name: shared_types::i18n::I18nString(std::collections::HashMap::from([(
                "pl".to_owned(),
                "Nazwisko".to_owned(),
            )])),
            logo_alt_text: None,
        };
        let rows = build_identifier_translations(id, "Plain name", Some(supplied), now_utc(), "en");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].field, LocalizedTextField::Name);
        assert_eq!(rows[0].lang, "pl");
        assert_eq!(rows[0].value, "Nazwisko");
        assert_eq!(rows[1].field, LocalizedTextField::Name);
        assert_eq!(rows[1].lang, "en");
        assert_eq!(rows[1].value, "Plain name");
    }

    #[test]
    fn build_identifier_translations_keeps_supplied_default_language_name() {
        let id = Uuid::new_v4().into();
        let supplied = IdentifierTranslations {
            name: shared_types::i18n::I18nString(std::collections::HashMap::from([(
                "en".to_owned(),
                "Given name".to_owned(),
            )])),
            logo_alt_text: None,
        };
        let rows = build_identifier_translations(id, "Plain name", Some(supplied), now_utc(), "en");

        let en_names: Vec<_> = rows
            .iter()
            .filter(|r| r.field == LocalizedTextField::Name && r.lang == "en")
            .collect();
        assert_eq!(en_names.len(), 1);
        assert_eq!(en_names[0].value, "Given name");
    }
}
