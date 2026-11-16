//! Localized strings.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Localized strings serialized and iterated in ascending language order.
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct I18nString(BTreeMap<String, String>);

impl I18nString {
    /// Returns the translation for the given language.
    pub fn get(&self, lang: &str) -> Option<&str> {
        self.0.get(lang).map(String::as_str)
    }

    /// Iterates over `(language, translation)` pairs in ascending language order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(lang, text)| (lang.as_str(), text.as_str()))
    }

    /// Returns the number of translations.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if there are no translations.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the underlying map from language to translation.
    pub fn into_inner(self) -> BTreeMap<String, String> {
        self.0
    }
}

impl From<BTreeMap<String, String>> for I18nString {
    fn from(value: BTreeMap<String, String>) -> Self {
        Self(value)
    }
}

impl<K: Into<String>, V: Into<String>, const N: usize> From<[(K, V); N]> for I18nString {
    fn from(value: [(K, V); N]) -> Self {
        value.into_iter().collect()
    }
}

impl From<I18nString> for BTreeMap<String, String> {
    fn from(value: I18nString) -> Self {
        value.0
    }
}

impl<K: Into<String>, V: Into<String>> FromIterator<(K, V)> for I18nString {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|(lang, text)| (lang.into(), text.into()))
                .collect(),
        )
    }
}

impl IntoIterator for I18nString {
    type Item = (String, String);
    type IntoIter = std::collections::btree_map::IntoIter<String, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_construction_and_access() {
        let value = I18nString::from([("en", "Hello"), ("de", "Hallo")]);
        assert_eq!(value.get("en"), Some("Hello"));
        assert_eq!(value.get("fr"), None);
        assert_eq!(value.len(), 2);
        assert!(!value.is_empty());
        assert!(I18nString::default().is_empty());

        // iterated in ascending language order
        assert_eq!(
            value.iter().collect::<Vec<_>>(),
            vec![("de", "Hallo"), ("en", "Hello")]
        );
        assert_eq!(
            value.clone().into_inner(),
            BTreeMap::from([
                ("de".to_string(), "Hallo".to_string()),
                ("en".to_string(), "Hello".to_string()),
            ])
        );
        assert_eq!(I18nString::from(value.clone().into_inner()), value);
    }

    #[test]
    fn test_serde_transparent() {
        let value = I18nString::from([("en", "Hello"), ("de", "Hallo")]);
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, r#"{"de":"Hallo","en":"Hello"}"#);
        assert_eq!(serde_json::from_str::<I18nString>(&json).unwrap(), value);
    }
}
