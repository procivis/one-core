use std::str::FromStr;
use std::sync::LazyLock;

use anyhow::Context;
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::macros::impl_display;

static DID_ALLOWLIST_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9:._%-]+$").expect("Failed to compile regex"));

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
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct DidValue(Url);

impl DidValue {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl TryInto<Url> for &DidValue {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Url, Self::Error> {
        self.as_str()
            .parse()
            .with_context(|| format!("Failed to convert did: {} to URL", self))
    }
}

impl DidValue {
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

impl FromStr for DidValue {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(s).with_context(|| format!("Failed to convert did: {s} to URL"))?;

        if url.scheme() != "did" {
            return Err(DidValueError::IncorrectSchema).context("did parsing error");
        }

        if url.query().is_some() {
            return Err(DidValueError::IncorrectDiDValue).context("did value with query");
        }

        if url.fragment().is_some() {
            return Err(DidValueError::IncorrectDiDValue).context("did value with fragment");
        }

        let (method, rest) = url
            .path()
            .split_once(":")
            .ok_or(DidValueError::DidMethodNotFound)?;

        if !method
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(DidValueError::IncorrectDiDMethod).context("did parsing error");
        }

        if !DID_ALLOWLIST_REGEX.is_match(rest) {
            return Err(DidValueError::IncorrectDiDValue).context("did parsing error");
        }

        Ok(DidValue(url))
    }
}

impl_display!(DidValue);

#[cfg(feature = "sea-orm")]
use crate::macros::impls_for_seaorm_newtype;

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(DidValue);

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
        assert!(&DidValue::from_str(
            "did:key:zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6?version=1"
        )
        .is_err());

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
        assert_eq!(
            DidValue::from_did_url("did:example:12345")
                .unwrap()
                .as_str(),
            "did:example:12345"
        );

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
