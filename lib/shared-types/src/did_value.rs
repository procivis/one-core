use std::fmt::Display;
use std::str::FromStr;
use std::sync::LazyLock;

use anyhow::Context;
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

static DID_ALLOWLIST_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9:._%-]+$").expect("Failed to compile regex"));

const QUERY_PARAM_DID_METHODS_EXCEPTIONS: &[&str] = &["sd_jwt_vc_issuer_metadata"];

#[derive(Debug, Error)]
pub enum DidValueError {
    #[error("Incorrect did schema")]
    IncorrectSchema,
    #[error("Incorrect did method")]
    IncorrectDiDMethod,
    #[error("Incorrect did value")]
    IncorrectDiDValue,
    #[error("Did method not found")]
    DidMethodNotFound,
}

/// https://www.w3.org/TR/did-core/#did-syntax
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DidValue {
    url: Url,
    method: String,
}

impl DidValue {
    pub fn into_url(self) -> Url {
        self.url
    }

    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    pub fn method(&self) -> &str {
        self.method.as_str()
    }

    /// https://www.w3.org/TR/did-core/#did-url-syntax
    pub fn from_did_url(url: impl AsRef<str>) -> Result<Self, anyhow::Error> {
        let url = url.as_ref();
        let mut url =
            Url::parse(url).with_context(|| format!("Failed to convert did: {url} to URL"))?;

        url.set_fragment(None);
        url.set_query(None);
        if let Some((method_with_id, _segments)) = url.path().split_once("/") {
            url.set_path(method_with_id.to_owned().as_mut_str());
        }

        url.as_str().parse()
    }
}

#[cfg(feature = "utoipa")]
mod utoipa_schema {
    use utoipa::openapi::{KnownFormat, ObjectBuilder, RefOr, Schema, SchemaFormat, Type};
    use utoipa::{PartialSchema, ToSchema};

    use super::*;

    impl PartialSchema for DidValue {
        fn schema() -> RefOr<Schema> {
            RefOr::T(Schema::Object(
                ObjectBuilder::new()
                    .schema_type(Type::String)
                    .format(Some(SchemaFormat::KnownFormat(KnownFormat::Uri)))
                    .examples(["did:key:z6MkqfAeg81kn2x4fns8j2rGq1bhdJhT6f3Wh88hLLEq24v2"])
                    .build(),
            ))
        }
    }

    impl ToSchema for DidValue {}
}

impl FromStr for DidValue {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(s).with_context(|| format!("Failed to convert did: {s} to URL"))?;

        if url.scheme() != "did" {
            return Err(DidValueError::IncorrectSchema).context("did parsing error");
        }

        let (method, rest) = url
            .path()
            .split_once(":")
            .ok_or(DidValueError::DidMethodNotFound)?;

        if url.query().is_some() && !QUERY_PARAM_DID_METHODS_EXCEPTIONS.contains(&method) {
            return Err(DidValueError::IncorrectDiDValue).context("did value with query");
        }

        if url.fragment().is_some() {
            return Err(DidValueError::IncorrectDiDValue).context("did value with fragment");
        }

        if !method
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(DidValueError::IncorrectDiDMethod).context("did parsing error");
        }

        if !DID_ALLOWLIST_REGEX.is_match(rest) {
            return Err(DidValueError::IncorrectDiDValue).context("did parsing error");
        }

        let method = method.to_owned();
        Ok(DidValue { url, method })
    }
}

impl From<DidValue> for String {
    fn from(did: DidValue) -> Self {
        did.url.to_string()
    }
}

impl TryFrom<String> for DidValue {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        DidValue::from_str(&value)
    }
}

impl Display for DidValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.url, f)
    }
}

// needed for sea-orm `find_by_id` to work
impl From<&DidValue> for DidValue {
    fn from(source: &DidValue) -> Self {
        source.clone()
    }
}

// needed if we want to put the type inside and Option
#[cfg(feature = "sea-orm")]
mod seaorm {
    use super::*;
    impl sea_orm::sea_query::value::Nullable for DidValue {
        fn null() -> sea_orm::Value {
            sea_orm::Value::String(None)
        }
    }

    impl From<DidValue> for sea_orm::Value {
        fn from(source: DidValue) -> Self {
            source.to_string().into()
        }
    }

    impl sea_orm::sea_query::ValueType for DidValue {
        fn try_from(v: sea_orm::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
            let s = <String as sea_orm::sea_query::ValueType>::try_from(v)?;
            let s = s.parse().map_err(|_| sea_orm::sea_query::ValueTypeErr)?;
            Ok(s)
        }

        fn type_name() -> String {
            "DidValue".to_owned()
        }

        fn array_type() -> sea_orm::sea_query::ArrayType {
            sea_orm::sea_query::ArrayType::String
        }

        fn column_type() -> sea_orm::sea_query::ColumnType {
            sea_orm::sea_query::ColumnType::string(None)
        }
    }

    impl sea_orm::TryGetable for DidValue {
        fn try_get_by<I: sea_orm::ColIdx>(
            res: &sea_orm::QueryResult,
            idx: I,
        ) -> Result<Self, sea_orm::TryGetError> {
            let s: String = <String as sea_orm::TryGetable>::try_get_by(res, idx)?;

            let newtype_str = stringify!($newtype);
            let s = s.parse().map_err(|error| {
                sea_orm::TryGetError::DbErr(sea_orm::error::DbErr::Type(format!(
                    "Failed to parse {newtype_str}: {error}"
                )))
            })?;

            Ok(s)
        }
    }

    impl From<&DidValue> for sea_orm::Value {
        fn from(source: &DidValue) -> Self {
            source.to_string().into()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_parsing_did_value() {
        assert!(&DidValue::from_str("did:example:12345").is_ok());
        assert!(
            &DidValue::from_str("did:key:zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6")
                .is_ok()
        );
        assert!(&DidValue::from_str("did:example:3fa85f64-5717-4562-b3fc-2c963f66afa6").is_ok());

        assert!(&DidValue::from_str("did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImJVUWhlQkxPa2lfN3RudWJpZHZEaHJjX2VkMXlIMFBGeElzRjF0anBnYWsiLCJ5IjoiYWc3N0pUX3pZdXphSWtLbDdDU2w1b2I4UUJSWjhncFBmR3pvblRkWDJqQSJ9").is_ok());
        assert!(
            &DidValue::from_str("did:key:zDnaedcfZgHvBTh719abnBU4bNQw3gVnf3Wpn7rj3r8gYEMWc")
                .is_ok()
        );
        assert!(&DidValue::from_str(
            "did:web:core.dev.procivis-one.com:ssi:did-web:v1:00099573-c026-491d-84c4-6d0b578a7348"
        )
        .is_ok());

        assert!(&DidValue::from_str("did:key:zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6#zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6").is_err());
        assert!(
            &DidValue::from_str(
                "did:key:zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6?version=1"
            )
            .is_err()
        );

        assert!(&DidValue::from_str("did:example.12345").is_err());
        assert!(&DidValue::from_str("did:example:path/123/345345").is_err());
        assert!(&DidValue::from_str("did:example:path/123/345345/../").is_err());
        assert!(&DidValue::from_str("../etc/passwd").is_err());
        assert!(&DidValue::from_str("did:example:../schema").is_err());
        assert!(&DidValue::from_str("did:example:12345!").is_err());
        assert!(&DidValue::from_str("%2e%2e%2fetc/passwd").is_err());
        assert!(&DidValue::from_str("%252e%252e%252fetc/passwd").is_err());
        assert!(&DidValue::from_str("..\\..\\windows\\system32\\cmd.exe").is_err());
        assert!(&DidValue::from_str("..\\/..\\/etc/passwd").is_err());
        assert!(&DidValue::from_str("folder/../../etc/passwd").is_err());
    }

    #[test]
    fn test_conversion_did_value_from_did_url() {
        let did = DidValue::from_did_url("did:example:12345").unwrap();
        assert_eq!(did.as_str(), "did:example:12345");
        assert_eq!(did.method(), "example");

        assert_eq!(
            DidValue::from_did_url("did:key:zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6#zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6")
                .unwrap()
                .as_str(),
            "did:key:zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6"
        );

        assert_eq!(
            DidValue::from_did_url(
                "did:key:zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6?version=1"
            )
            .unwrap()
            .as_str(),
            "did:key:zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6"
        );

        assert_eq!(
            DidValue::from_did_url("did:example:path/123/345345")
                .unwrap()
                .as_str(),
            "did:example:path"
        );
    }
}
