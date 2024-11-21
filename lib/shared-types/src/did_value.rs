use std::convert::Infallible;
use std::str::FromStr;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::macros::impl_display;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct DidValue(String);

impl DidValue {
    pub fn as_str(&self) -> &str {
        &self.0
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

impl FromStr for DidValue {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(DidValue::from(s))
    }
}

impl<T> From<T> for DidValue
where
    T: AsRef<str>,
{
    fn from(value: T) -> Self {
        Self(
            value
                .as_ref()
                // Drop everything starting from the first # to allow parsing a did from a
                // verification method reference as well.
                .split('#')
                .next()
                .unwrap_or_default()
                .to_string(),
        )
    }
}

impl_display!(DidValue);

#[cfg(feature = "sea-orm")]
use crate::macros::impls_for_seaorm_newtype;

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(DidValue);
